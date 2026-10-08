"""Desktop access to the existing real OpenSSL laboratory and its evidence."""
import json
import os
import socket
from pathlib import Path
import sys
from datetime import datetime
from pqc_lab.lab import find_openssl, openssl_candidates, service_is_active
from pqc_lab.profiles import (LabProfile, PROTOCOLS, TLS_GROUPS, TLS_SIGNATURES,
                              SIGNATURE_VARIANTS, CLASSICAL_SIGNATURE_VARIANTS,
                              success_matches_profile)

from PySide6.QtCore import QProcess, QTimer, Qt, QUrl, Signal, QSignalBlocker
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QFrame, QGroupBox, QLineEdit, QSpinBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QPlainTextEdit, QTabWidget, QFileDialog,
    QComboBox, QCheckBox,
)

ROOT = Path(__file__).resolve().parents[1]


def _default_openssl():
    explicit = os.environ.get("PQC_OPENSSL")
    if explicit:
        return explicit
    for candidate in openssl_candidates():
        if Path(candidate).is_file():
            return candidate
    return ""


def _port(value):
    return type(value) is int and 1 <= value <= 65535


def _port_is_available(port):
    try:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False


class PqcLabTab(QWidget):
    """Own only processes launched here; closing the application stops those services."""
    idle = Signal()
    shutdown_failed = Signal(str)

    def __init__(self, parent=None, *, base=None, openssl=None):
        super().__init__(parent)
        self.base = Path(base or ROOT / "pqc_lab").resolve()
        self._service = QProcess(self)
        self._command = QProcess(self)
        self._action = None
        self._starting = False
        self._stopping = False
        self._closing = False
        self._open_pending = False
        self._report_stamp = None
        self._before_start_stamp = None
        self._record = None
        self._report = None
        self._report_state = "unverified"
        self._restore_saved_profile = True
        for process in (self._service, self._command):
            process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
            process.setWorkingDirectory(str(ROOT))
        self._service.readyReadStandardOutput.connect(self._read_service_output)
        self._service.finished.connect(self._service_finished)
        self._service.errorOccurred.connect(self._service_error)
        self._command.readyReadStandardOutput.connect(self._read_command_output)
        self._command.finished.connect(self._command_finished)
        self._command.errorOccurred.connect(self._command_error)
        self._build_ui(openssl if openssl is not None else _default_openssl())
        self._report_stamp = None  # The first refresh must read any saved report.
        self._timer = QTimer(self)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()
        self.idle.connect(self._finish_close)
        self._refresh()
        self._restore_saved_profile = False

    def _build_ui(self, openssl):
        root = QVBoxLayout(self)
        root.setSpacing(12)
        hero = QFrame()
        hero.setStyleSheet("QFrame { background:#102b46; border-radius:12px; }"
                          "QLabel { color:#e8f2ff; background:transparent; }"
                          "QPushButton:disabled { background:#344f69; color:#a7b9cc; border-color:#344f69; }")
        layout = QVBoxLayout(hero)
        layout.setContentsMargins(22, 16, 22, 16)
        title = QLabel("本地后量子实验站")
        title.setStyleSheet("font-size:25px; font-weight:700;")
        layout.addWidget(title)
        intro = QLabel("选择 HTTPS / TLS 握手或 TCP / UDP 签名消息，实测不同密钥交换与数字签名算法。")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        row = QHBoxLayout()
        self.btn_start = QPushButton("启动实验并展示网页")
        self.btn_start.setObjectName("primary")
        self.btn_start.clicked.connect(self._start)
        self.btn_open = QPushButton("打开展示网页")
        self.btn_open.clicked.connect(self._open_page)
        self.btn_verify = QPushButton("重新实测")
        self.btn_verify.clicked.connect(lambda: self._run_command("verify"))
        self.btn_stop = QPushButton("停止实验")
        self.btn_stop.clicked.connect(self._stop)
        for button in (self.btn_start, self.btn_open, self.btn_verify, self.btn_stop):
            row.addWidget(button)
        row.addStretch()
        layout.addLayout(row)
        self.service_status = QLabel("服务未启动")
        self.service_status.setWordWrap(True)
        layout.addWidget(self.service_status)
        root.addWidget(hero)

        settings = QGroupBox("本机实验入口")
        grid = QGridLayout(settings)
        self.tls_port, self.http_port = QSpinBox(), QSpinBox()
        for field, value in ((self.tls_port, 8443), (self.http_port, 8080)):
            field.setRange(1, 65535)
            field.setValue(value)
            field.valueChanged.connect(self._configuration_changed)
        grid.addWidget(QLabel("被测协议端口"), 0, 0)
        grid.addWidget(self.tls_port, 0, 1)
        grid.addWidget(QLabel("展示页端口"), 0, 2)
        grid.addWidget(self.http_port, 0, 3)
        self.http_address = QLabel()
        self.tls_address = QLabel()
        for label in (self.http_address, self.tls_address):
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        grid.addWidget(QLabel("报告展示页（HTTP）"), 1, 0)
        grid.addWidget(self.http_address, 1, 1, 1, 3)
        grid.addWidget(QLabel("真实被测端点"), 2, 0)
        grid.addWidget(self.tls_address, 2, 1, 1, 3)
        self.openssl_edit = QLineEdit(openssl)
        self.openssl_edit.setPlaceholderText("支持 X25519MLKEM768 和 ML-DSA-65 的 OpenSSL")
        self.btn_openssl = QPushButton("选择 OpenSSL…")
        self.btn_openssl.clicked.connect(self._choose_openssl)
        grid.addWidget(QLabel("OpenSSL 程序"), 3, 0)
        grid.addWidget(self.openssl_edit, 3, 1, 1, 2)
        grid.addWidget(self.btn_openssl, 3, 3)
        self.protocol_combo, self.group_combo = QComboBox(), QComboBox()
        for value, label in PROTOCOLS.items():
            self.protocol_combo.addItem(label, value)
        self.group_combo.addItems(tuple(TLS_GROUPS))
        grid.addWidget(QLabel("实验协议"), 4, 0)
        grid.addWidget(self.protocol_combo, 4, 1)
        grid.addWidget(QLabel("TLS 密钥交换"), 4, 2)
        grid.addWidget(self.group_combo, 4, 3)
        self.signature_combo, self.classical_combo = QComboBox(), QComboBox()
        self.signature_combo.addItems(tuple(TLS_SIGNATURES))
        self.signature_combo.setCurrentText("ML-DSA-65")
        self.classical_combo.addItems(CLASSICAL_SIGNATURE_VARIANTS)
        self.hybrid_check = QCheckBox("消息混合签名")
        grid.addWidget(QLabel("后量子签名"), 5, 0)
        grid.addWidget(self.signature_combo, 5, 1)
        grid.addWidget(self.hybrid_check, 5, 2)
        grid.addWidget(self.classical_combo, 5, 3)
        for field in (self.protocol_combo, self.group_combo, self.signature_combo, self.classical_combo):
            field.setMinimumContentsLength(18)
            field.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.message_edit = QLineEdit("本地后量子签名消息实验")
        self.message_edit.setMaxLength(4096)
        grid.addWidget(QLabel("TCP/UDP 消息"), 6, 0)
        grid.addWidget(self.message_edit, 6, 1, 1, 3)
        self.scope_hint = QLabel()
        self.scope_hint.setWordWrap(True)
        self.scope_hint.setStyleSheet("color:#64748b; font-size:11px;")
        grid.addWidget(self.scope_hint, 7, 0, 1, 4)
        root.addWidget(settings)

        cards = QHBoxLayout()
        self.group_value = self._card(cards, "协议层 · 交换与传输", "等待实测")
        self.cert_value = self._card(cards, "身份层 · 后量子签名", "等待实测")
        self.handshake_value = self._card(cards, "真实通信验证", "等待实测")
        root.addLayout(cards)
        summary = QHBoxLayout()
        self.report_status = QLabel("尚无实测报告")
        self.report_status.setStyleSheet("font-size:16px; font-weight:700; color:#475569;")
        summary.addWidget(self.report_status)
        summary.addStretch()
        refresh = QPushButton("刷新报告")
        refresh.clicked.connect(self.reload_evidence)
        self.btn_evidence = QPushButton("查看证据文件")
        self.btn_evidence.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.base / "public"))))
        help_button = QPushButton("实验说明")
        help_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(ROOT / "pqc_lab/README.md"))))
        for button in (refresh, self.btn_evidence, help_button):
            summary.addWidget(button)
        root.addLayout(summary)
        meta = QHBoxLayout()
        self.report_time = QLabel("报告时间：未提供")
        self.report_target = QLabel("被测端点：未提供")
        self.openssl_version = QLabel("OpenSSL：等待实测")
        for label in (self.report_time, self.report_target, self.openssl_version):
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            meta.addWidget(label)
        root.addLayout(meta)
        self.checks_table = QTableWidget(0, 3)
        self.checks_table.setHorizontalHeaderLabels(["实测检查项目", "结果", "证据摘要"])
        self.checks_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.checks_table.verticalHeader().setVisible(False)
        for column in (0, 1):
            self.checks_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.checks_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(1500)
        self.log.setPlaceholderText("启动、实测和停止的运行输出会显示在这里。")
        details = QTabWidget()
        details.addTab(self.checks_table, "逐项实测结果")
        details.addTab(self.log, "运行日志")
        root.addWidget(details, 1)
        footer = QLabel("报告是上一次实测的时间快照。TLS 使用指定实验 CA；签名消息使用本地固定公钥且明文传输。关闭应用会停止由本页启动的服务。")
        footer.setWordWrap(True)
        footer.setStyleSheet("color:#64748b; font-size:11px;")
        root.addWidget(footer)
        self.protocol_combo.currentIndexChanged.connect(self._mode_changed)
        for field in (self.group_combo, self.signature_combo, self.classical_combo):
            field.currentIndexChanged.connect(self._configuration_changed)
        self.hybrid_check.toggled.connect(self._configuration_changed)
        self.message_edit.textChanged.connect(self._configuration_changed)
        self._mode_changed()

    def _selected_profile(self):
        return LabProfile(protocol=self.protocol_combo.currentData(), group=self.group_combo.currentText(),
                          signature=self.signature_combo.currentText(),
                          classical_signature=self.classical_combo.currentText() if self.hybrid_check.isChecked() else "")

    def _mode_changed(self):
        signature = self.signature_combo.currentText()
        is_tls = self.protocol_combo.currentData() in ("https", "tls")
        blocker = QSignalBlocker(self.signature_combo)
        self.signature_combo.clear()
        self.signature_combo.addItems(tuple(TLS_SIGNATURES) if is_tls else SIGNATURE_VARIANTS)
        self.signature_combo.setCurrentText(signature if self.signature_combo.findText(signature) >= 0 else "ML-DSA-65")
        del blocker
        if is_tls:
            self.hybrid_check.setChecked(False)
        self._configuration_changed()

    def _configuration_changed(self):
        if hasattr(self, "group_value") and not self._record:
            self._report_stamp = self._stamp()
            self._render_unavailable("实验配置已更改，请启动并实测")
        self._update_addresses()
        self._update_buttons()

    def _load_running_profile(self):
        if not self._record:
            return
        profile = LabProfile.from_dict(self._record.get("profile", {}))
        self._set_controls_profile(profile, self._record.get("message", "本地后量子签名消息实验"))
        self.tls_port.setValue(self._record["port"])
        self.http_port.setValue(self._record["http_port"])
        if isinstance(self._record.get("openssl"), str) and self._record["openssl"]:
            self.openssl_edit.setText(self._record["openssl"])

    def _set_controls_profile(self, profile, message=None):
        widgets = (self.protocol_combo, self.group_combo, self.signature_combo,
                   self.classical_combo, self.hybrid_check, self.message_edit)
        blockers = [QSignalBlocker(widget) for widget in widgets]
        self.protocol_combo.setCurrentIndex(self.protocol_combo.findData(profile.protocol))
        self.group_combo.setCurrentText(profile.group)
        self.signature_combo.clear()
        self.signature_combo.addItems(tuple(TLS_SIGNATURES) if profile.is_tls else SIGNATURE_VARIANTS)
        self.signature_combo.setCurrentText(profile.signature)
        self.hybrid_check.setChecked(bool(profile.classical_signature))
        if profile.classical_signature:
            self.classical_combo.setCurrentText(profile.classical_signature)
        if isinstance(message, str):
            self.message_edit.setText(message)
        del blockers

    @staticmethod
    def _card(row, title, value):
        box = QGroupBox(title)
        layout = QVBoxLayout(box)
        label = QLabel(value)
        label.setWordWrap(True)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setStyleSheet("font-size:17px; font-weight:700; color:#1d4ed8; padding:5px;")
        layout.addWidget(label)
        row.addWidget(box, 1)
        return label

    def _choose_openssl(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择支持 PQC 的 OpenSSL 程序")
        if path:
            self.openssl_edit.setText(path)

    def _runtime(self):
        try:
            data = json.loads((self.base / ".runtime/service.json").read_text(encoding="utf-8"))
            if (isinstance(data, dict) and _port(data.get("port")) and _port(data.get("http_port"))
                    and type(data.get("pid")) is int and data["pid"] > 0 and service_is_active(self.base)):
                LabProfile.from_dict(data.get("profile", {}))
                if not isinstance(data.get("message", ""), str):
                    return None
                # While our new manager is starting, an older record can still exist.
                if self._starting and self._service.state() != QProcess.ProcessState.NotRunning and data["pid"] != self._service.processId():
                    return None
                return data
        except (OSError, ValueError, TypeError):
            pass
        return None

    def _update_addresses(self):
        record = self._record or {}
        tls = record.get("port", self.tls_port.value())
        http = record.get("http_port", self.http_port.value())
        self.http_address.setText("http://127.0.0.1:%d/index.html" % http)
        protocol = (record.get("profile") or {}).get("protocol", self.protocol_combo.currentData())
        self.tls_address.setText(("https://localhost:%d/index.html" % tls) if protocol == "https"
                                 else ("tls://localhost:%d" % tls) if protocol == "tls"
                                 else ("%s://127.0.0.1:%d" % (protocol, tls)))
        self.scope_hint.setText(
            "TLS 握手与证书链使用显式指定的实验 CA；HTTPS 模式另执行真实 GET。仅监听本机。"
            if protocol in ("https", "tls") else
            "应用签名协议 · TCP/UDP 明文传输，不提供内容加密；使用本地固定公钥验签，混合签名要求两份签名均有效。")

    def _args(self, action):
        record = self._record or {}
        args = ["-u", str(ROOT / "pqc_lab/lab.py"), action, "--base", str(self.base),
                "--port", str(record.get("port", self.tls_port.value())),
                "--http-port", str(record.get("http_port", self.http_port.value()))]
        openssl = record.get("openssl") or self.openssl_edit.text().strip()
        if openssl and action != "stop":
            args.extend(["--openssl", openssl])
        profile = LabProfile.from_dict(record["profile"]) if record.get("profile") else self._selected_profile()
        args.extend(["--protocol", profile.protocol, "--group", profile.group, "--signature", profile.signature])
        if profile.classical_signature:
            args.extend(["--classical-signature", profile.classical_signature])
        args.extend(["--message", record.get("message", self.message_edit.text())])
        return args

    def is_busy(self):
        return any(process.state() != QProcess.ProcessState.NotRunning for process in (self._service, self._command))

    def _start(self):
        if self.is_busy() or self._runtime():
            return
        if self.http_port.value() == self.tls_port.value():
            self.service_status.setText("启动前请设置不同的 TLS/消息端口和展示页端口。")
            return
        if len(self.message_edit.text().encode("utf-8")) > 4096:
            self.service_status.setText("消息不能超过 4096 UTF-8 字节。")
            return
        busy = [str(spin.value()) for spin in (self.tls_port, self.http_port)
                if not _port_is_available(spin.value())]
        if busy:
            self.service_status.setText("端口 %s 已被占用；请更换端口后重试。" % "、".join(busy))
            return
        profile = self._selected_profile()
        if profile.is_tls:
            try:
                find_openssl(self.openssl_edit.text().strip() or None, profile)
            except RuntimeError as exc:
                self.service_status.setText(str(exc))
                return
        self._before_start_stamp = self._stamp()
        self._starting, self._open_pending = True, True
        self.service_status.setText("正在启动本机服务并进行真实验证…")
        self.log.appendPlainText("启动本地后量子实验站…")
        self._service.start(sys.executable, self._args("serve"))
        self._update_buttons()

    def _run_command(self, action):
        if self._command.state() != QProcess.ProcessState.NotRunning:
            return
        if action == "verify" and (not self._runtime() or self._starting or self._stopping):
            return
        self._action = action
        if action == "verify":
            self.report_status.setText("正在重新实测…")
        self._command.start(sys.executable, self._args(action))
        self._update_buttons()

    def _stop(self):
        if self._stopping:
            return
        self._record = self._runtime()
        if self._record and self._command.state() == QProcess.ProcessState.NotRunning:
            self._stopping = True
            self.service_status.setText("正在停止实验并清理连接…")
            self._run_command("stop")

    def _open_page(self):
        if self._runtime():
            if not QDesktopServices.openUrl(QUrl(self.http_address.text())):
                self.service_status.setText("浏览器未能打开；可复制上方 HTTP 展示页地址访问。")

    def _read_service_output(self):
        text = bytes(self._service.readAllStandardOutput()).decode("utf-8", "replace")
        self.log.appendPlainText(text.rstrip())
        self._refresh()

    def _read_command_output(self):
        text = bytes(self._command.readAllStandardOutput()).decode("utf-8", "replace")
        self.log.appendPlainText(text.rstrip())

    def _service_error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            self._starting = self._open_pending = False
            self.service_status.setText("实验未能启动：" + self._service.errorString())
            self._update_buttons()
            if not self.is_busy():
                self.idle.emit()

    def _service_finished(self, code, _status):
        self._read_service_output()
        self._starting = self._stopping = self._open_pending = False
        self._record = self._runtime()
        self.service_status.setText("实验服务已停止" if code == 0 else "实验服务已退出；请查看运行日志（退出码 %d）" % code)
        self._update_addresses()
        self._update_buttons()
        if not self.is_busy():
            self.idle.emit()

    def _command_error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            self._command_finished(-1, None)

    def _command_finished(self, code, _status):
        self._read_command_output()
        action, self._action = self._action, None
        if action == "stop":
            self._stopping = False
            if code:
                message = "停止实验失败，请查看日志后重试。"
                self.service_status.setText(message)
                if self._closing:
                    self._closing = False
                    self.shutdown_failed.emit(message)
            elif self._service.state() == QProcess.ProcessState.NotRunning:
                self.service_status.setText("实验服务已停止")
        elif code:
            self.log.appendPlainText("本次实测未通过，请检查逐项结果与日志。")
        self.reload_evidence()
        if self._closing:
            self._stop_owned_service()
        if not self.is_busy():
            self.idle.emit()

    def _stamp(self):
        try:
            return (self.base / "public/evidence.json").stat().st_mtime_ns
        except OSError:
            return None

    def reload_evidence(self):
        self._refresh(force_report=True)

    def _refresh(self, force_report=False):
        self._record = self._runtime()
        self._load_running_profile()
        self._update_addresses()
        stamp = self._stamp()
        if (force_report or stamp != self._report_stamp) and not (self._starting and stamp == self._before_start_stamp):
            self._report_stamp = stamp
            try:
                data = json.loads((self.base / "public/evidence.json").read_text(encoding="utf-8"))
                self._render_report(data)
            except (OSError, ValueError, TypeError, AttributeError):
                self._render_unavailable("报告不可用或格式无效，尚未验证")
        if self._open_pending and stamp != self._before_start_stamp and self._report_state in ("passed", "failed") and self._record:
            self._starting = self._open_pending = False
            self.service_status.setText("实验服务运行中 · 展示页已就绪")
            self._open_page()
        self._update_buttons()
        if self._record and self._service.state() == QProcess.ProcessState.NotRunning and not self._stopping:
            self.service_status.setText("发现正在运行的本机实验服务 · 可打开展示网页")
        if self._closing:
            self._stop_owned_service()

    def _update_buttons(self):
        command_busy = self._command.state() != QProcess.ProcessState.NotRunning
        service_busy = self._service.state() != QProcess.ProcessState.NotRunning
        active = bool(self._record)
        self.btn_start.setEnabled(not (service_busy or active or command_busy or self._closing))
        self.btn_open.setEnabled(active and not self._closing and not self._stopping)
        self.btn_verify.setEnabled(active and not (command_busy or self._starting or self._stopping or self._closing))
        self.btn_stop.setEnabled(active and not (command_busy or self._stopping or self._closing))
        self.btn_evidence.setEnabled((self.base / "public").is_dir())
        editable = not (active or service_busy or command_busy or self._closing)
        is_tls = self.protocol_combo.currentData() in ("https", "tls")
        for widget in (self.tls_port, self.http_port, self.protocol_combo, self.signature_combo):
            widget.setEnabled(editable)
        for widget in (self.group_combo, self.openssl_edit, self.btn_openssl):
            widget.setEnabled(editable and is_tls)
        for widget in (self.hybrid_check, self.message_edit):
            widget.setEnabled(editable and not is_tls)
        self.classical_combo.setEnabled(editable and not is_tls and self.hybrid_check.isChecked())

    def _render_unavailable(self, message):
        self._report, self._report_state = None, "unverified"
        self.report_status.setText(message)
        self.report_status.setStyleSheet("font-size:16px; font-weight:700; color:#475569;")
        for label in (self.group_value, self.cert_value, self.handshake_value):
            label.setText("等待实测")
        self.report_time.setText("报告时间：未提供")
        self.report_target.setText("被测端点：未提供")
        self.openssl_version.setText("OpenSSL：等待实测")
        self.checks_table.setRowCount(0)

    def _render_report(self, data):
        if not isinstance(data, dict) or data.get("status") not in ("running", "passed", "failed"):
            raise ValueError("Invalid report status")
        checks, summary = data.get("checks"), data.get("summary", {})
        if not isinstance(checks, list) or not isinstance(summary, dict):
            raise ValueError("Invalid report structure")
        if any(not isinstance(item, dict) or not isinstance(item.get("label"), str)
               or not isinstance(item.get("detail"), str) or type(item.get("passed")) is not bool for item in checks):
            raise ValueError("Invalid check structure")
        try:
            timestamp = datetime.fromisoformat(data.get("generated_at", "").replace("Z", "+00:00"))
            valid_time = timestamp.tzinfo is not None
        except (ValueError, TypeError, AttributeError):
            timestamp, valid_time = None, False
        target = data.get("target")
        prefix, separator, number = target.rpartition(":") if isinstance(target, str) else ("", "", "")
        valid_target = prefix == "127.0.0.1" and separator and number.isascii() and number.isdigit() and _port(int(number))
        state = data["status"]
        if state == "passed" and not (
            valid_time and valid_target and checks and all(item["passed"] for item in checks)
            and success_matches_profile(data)
        ):
            state = "failed"
        profile = LabProfile.from_dict(data["profile"]) if "profile" in data else LabProfile()
        if self._restore_saved_profile and not self._record:
            self._set_controls_profile(profile, summary.get("message"))
            if valid_target:
                self.tls_port.setValue(int(number))
        if state == "passed" and (profile != self._selected_profile()
                                  or valid_target and int(number) != self.tls_port.value()):
            state = "failed"
        self._report, self._report_state = data, state
        title, color = {"running": ("实测进行中…", "#b45309"),
                        "passed": ("上次实测通过 · " + ("双层后量子验证" if profile.is_tls else "消息签名验证"), "#15803d"),
                        "failed": ("实测未通过或报告存在不一致", "#b91c1c")}[state]
        self.report_status.setText(title + (" · %d/%d 项通过" % (len(checks), len(checks)) if state == "passed" else ""))
        self.report_status.setStyleSheet("font-size:16px; font-weight:700; color:%s;" % color)
        def value(key):
            item = summary.get(key)
            return item if isinstance(item, str) and item else "尚无证据"
        self.group_value.setText(value("group_name") if profile.is_tls else profile.protocol.upper() + " · 明文签名消息")
        signature = value("certificate_algorithm") if profile.is_tls else value("signature_algorithm")
        self.cert_value.setText(signature + (" + " + profile.classical_signature if profile.classical_signature else ""))
        handshake = summary.get("finished_verified") is True and summary.get("certificate_verify_verified") is True
        https = any(item.get("id") == "https_get" and item["passed"] for item in checks)
        self.handshake_value.setText(("握手已验证 · HTTPS 成功" if https else "TLS 握手已验证")
                                    if state == "passed" and profile.is_tls and handshake else
                                    "消息验签通过 · 不提供内容加密" if state == "passed" and not profile.is_tls and summary.get("message_signature_verified") is True
                                    else "结果以逐项检查为准")
        self.report_time.setText("报告时间：" + (timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S") if valid_time else "无效时间"))
        self.report_target.setText("被测端点：" + (target if isinstance(target, str) else "未提供") + " · " + PROTOCOLS[profile.protocol])
        version = data.get("openssl_version")
        self.openssl_version.setText(version if isinstance(version, str) else "OpenSSL：未提供")
        self.checks_table.setRowCount(len(checks))
        for row, check in enumerate(checks):
            detail = check["detail"].replace("\n", " ")
            for col, text in enumerate((check["label"], "通过" if check["passed"] else "未通过", detail[:180])):
                item = QTableWidgetItem(text)
                item.setToolTip(check["detail"] if col == 2 else text)
                self.checks_table.setItem(row, col, item)
        self.checks_table.resizeRowsToContents()

    def request_shutdown(self):
        self._closing = True
        self._open_pending = False
        self._stop_owned_service()
        self._update_buttons()

    def _stop_owned_service(self):
        if self._service.state() != QProcess.ProcessState.NotRunning:
            if not self._stopping and self._command.state() == QProcess.ProcessState.NotRunning:
                record = self._runtime()
                if record and record["pid"] == self._service.processId():
                    self._stop()

    def _finish_close(self):
        if self._closing and not self.is_busy():
            self.close()

    def closeEvent(self, event):
        if self.is_busy():
            self.request_shutdown()
            event.ignore()
        else:
            self._timer.stop()
            super().closeEvent(event)
