"""Desktop review of recorded connection inputs, computation, and outputs."""
import copy
import json
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QLabel,
                               QPlainTextEdit, QPushButton, QSplitter, QTabWidget,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
                               QHeaderView)

from modules import pqc_recheck
from modules.mlkem_trace_ui import CalculationTraceView


FIELD_NAMES = {
    "group_id": "协商组", "cipher_code": "协商密码套件", "server_key_share": "服务器实际交换材料",
    "kem_private_key": "同次连接的 ML-KEM 解封装私钥", "ecdh_private_key": "同次连接的 ECDHE 临时私钥",
    "expected_shared_secret": "原连接记录的共享秘密（用于比较）",
    "certificate_chain": "原握手证书", "signature_scheme": "握手签名算法",
    "signature": "原 CertificateVerify 签名", "transcript_before_cv": "签名前的完整握手转录",
    "encrypted_records": "原连接完整密文记录",
    "server_finished": "服务器 Finished 握手记录", "client_finished": "客户端 Finished 握手记录",
}
OPERATIONS = {"exchange": "密钥封装 / ECDHE", "signature": "握手签名", "records": "加密记录"}


class _RecheckWorker(QThread):
    done = Signal(dict)
    failed = Signal(str)

    def __init__(self, session, parameters, keylog, parent):
        super().__init__(parent)
        self.session, self.parameters, self.keylog = session, parameters, keylog

    def run(self):
        try:
            self.done.emit(pqc_recheck.recheck(self.session, self.parameters, keylog=self.keylog))
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.session, self.parameters, self.keylog = None, None, ""


class PqcRecheckTab(QWidget):
    def __init__(self, parent=None, *, session_provider=None):
        super().__init__(parent)
        self._session_provider = session_provider
        self._sessions, self._imported = [], []
        self._worker = None
        self._result = None
        root = QVBoxLayout(self)
        intro = QLabel("选择前面检测或抓包的实际连接，补充同次连接的秘密参数，再执行计算复核。"
                       "抓包通常没有临时私钥或流量秘密；缺少数据时会明确列出。秘密参数仅保留在内存中。")
        intro.setWordWrap(True)
        root.addWidget(intro)
        source = QGroupBox("1. 选择真实连接 / 导入实际材料")
        row = QHBoxLayout(source)
        self.session_combo = QComboBox()
        self.session_combo.setMinimumWidth(220)
        row.addWidget(self.session_combo, 1)
        self.btn_refresh = QPushButton("刷新检测 / 抓包会话")
        self.btn_refresh.clicked.connect(self.refresh_sessions)
        row.addWidget(self.btn_refresh)
        self.btn_import = QPushButton("导入会话报告…")
        self.btn_import.clicked.connect(self._pick_report)
        row.addWidget(self.btn_import)
        root.addWidget(source)
        self.source_status = QLabel("尚未选择连接")
        self.source_status.setWordWrap(True)
        root.addWidget(self.source_status)

        splitter = QSplitter(Qt.Orientation.Vertical)
        root.addWidget(splitter, 1)
        secrets = QGroupBox("2. 补充同次连接的秘密参数")
        secret_layout = QVBoxLayout(secrets)
        hint = QLabel("私钥和共享秘密使用十六进制；X25519 私钥为 32 字节，P-256/P-384 的 ECDHE 私钥为大端标量，"
                      "ML-KEM 私钥为原始解封装私钥。可导入客户端记录的参数 JSON 或 NSS / OpenSSL Key Log。"
                      "Key Log 按 ClientRandom 匹配，只能提供流量秘密，不能代替 ML-KEM 私钥。")
        hint.setWordWrap(True)
        secret_layout.addWidget(hint)
        buttons = QHBoxLayout()
        self.btn_secret_import = QPushButton("导入秘密参数 JSON…")
        self.btn_secret_import.clicked.connect(self._pick_secrets)
        self.btn_keylog_import = QPushButton("导入 Key Log…")
        self.btn_keylog_import.clicked.connect(self._pick_keylog)
        buttons.addWidget(self.btn_secret_import)
        buttons.addWidget(self.btn_keylog_import)
        buttons.addStretch()
        secret_layout.addLayout(buttons)
        edits = QTabWidget()
        self.secret_edit = QPlainTextEdit()
        self.secret_edit.setPlaceholderText("先选择会话；保留 session_id，再填写实际秘密参数（十六进制）。")
        self.keylog_edit = QPlainTextEdit()
        self.keylog_edit.setPlaceholderText("SERVER_HANDSHAKE_TRAFFIC_SECRET <ClientRandom> <Secret>\nSERVER_TRAFFIC_SECRET_0 <ClientRandom> <Secret>")
        self.secret_edit.textChanged.connect(self._invalidate)
        self.keylog_edit.textChanged.connect(self._invalidate)
        edits.addTab(self.secret_edit, "临时私钥 / 秘密参数")
        edits.addTab(self.keylog_edit, "Key Log 流量秘密")
        secret_layout.addWidget(edits)
        splitter.addWidget(secrets)

        result_box = QGroupBox("3. 计算复核 · 4. 实际输入、过程、输出与一致性")
        result_layout = QVBoxLayout(result_box)
        run_row = QHBoxLayout()
        self.btn_run = QPushButton("执行本次连接计算复核")
        self.btn_run.setObjectName("primary")
        self.btn_run.clicked.connect(self._run)
        self.btn_clear = QPushButton("清空复核材料")
        self.btn_clear.clicked.connect(self._clear)
        run_row.addWidget(self.btn_run)
        run_row.addWidget(self.btn_clear)
        run_row.addStretch()
        result_layout.addLayout(run_row)
        self.result_status = QLabel("待复核")
        result_layout.addWidget(self.result_status)
        self.summary = QTableWidget(3, 3)
        self.summary.setHorizontalHeaderLabels(["复核类型", "结论", "过程说明 / 缺少的参数"])
        self.summary.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.summary.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.summary.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.summary.setMaximumHeight(140)
        self.summary.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        result_layout.addWidget(self.summary)
        self.pages = QTabWidget()
        self.input_view = QPlainTextEdit()
        self.input_view.setReadOnly(True)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.pages.addTab(self.output, "输出与结论")
        self.pages.addTab(self.input_view, "实际输入材料")
        self.trace_views = {}
        for key, label in OPERATIONS.items():
            view = CalculationTraceView()
            view.layout().itemAt(0).widget().setText("选择步骤查看原连接的实际输入、运算规则、输出及比较结果。")
            self.trace_views[key] = view
            self.pages.addTab(view, label + "过程")
        result_layout.addWidget(self.pages, 1)
        splitter.addWidget(result_box)
        splitter.setSizes([220, 460])
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        self.session_combo.currentIndexChanged.connect(self._select_session)
        self._invalidate()
        self.refresh_sessions()

    def showEvent(self, event):
        super().showEvent(event)
        if self._worker is None:
            self.refresh_sessions()

    def refresh_sessions(self):
        if self._worker is not None:
            return
        old = self.session_combo.currentData()
        previous = self._selected()
        try:
            provided = self._session_provider() if self._session_provider else []
            self._sessions = copy.deepcopy(list(provided or []) + self._imported)
        except Exception as exc:
            self.source_status.setText("读取会话失败：" + str(exc))
            return
        self.session_combo.blockSignals(True)
        self.session_combo.clear()
        for session in self._sessions:
            self.session_combo.addItem(session.get("label", "TLS 会话"), session["session_id"] + ":" + session.get("label", ""))
        selected = self.session_combo.findData(old) if old else 0
        self.session_combo.setCurrentIndex(max(selected, 0) if self._sessions else -1)
        self.session_combo.blockSignals(False)
        if self._selected() != previous or previous is None:
            self._select_session(self.session_combo.currentIndex())

    def _selected(self):
        index = self.session_combo.currentIndex()
        return self._sessions[index] if 0 <= index < len(self._sessions) else None

    def _select_session(self, index):
        self._invalidate()
        self.keylog_edit.clear()
        session = self._selected()
        if session is None:
            self.secret_edit.clear()
            self.input_view.clear()
            self.source_status.setText("暂无会话：先在第一页执行检测或第三页加载抓包，也可导入导出的会话报告。")
            self.btn_run.setEnabled(False)
            return
        parameters = session.get("_secrets") or {"session_id": session["session_id"], "kem_private_key": "",
            "ecdh_private_key": "", "expected_shared_secret": "", "server_handshake_traffic_secret": "",
            "server_application_traffic_secret": "", "client_handshake_traffic_secret": "",
            "client_application_traffic_secret": ""}
        self.secret_edit.setPlainText(json.dumps(parameters, ensure_ascii=False, indent=2))
        self.input_view.setPlainText(json.dumps(pqc_recheck.public_session(session), ensure_ascii=False, indent=2))
        self.source_status.setText("%s · %s · %s · 加密记录 %d 条 · %s" % (
            session.get("label", ""), session.get("group_name", "未取得组"), session.get("cipher_suite", "未取得套件"),
            len(session.get("server_records", [])) + len(session.get("client_records", [])),
            "已保留本次客户端临时秘密" if session.get("_secrets") else "待补充本次连接秘密参数"))
        self.btn_run.setEnabled(True)

    def _invalidate(self):
        self._result = None
        self.result_status.setText("待复核：输入改变后需要重新计算")
        self.output.clear()
        for row, (key, label) in enumerate(OPERATIONS.items()):
            for col, value in enumerate((label, "待复核", "")):
                self.summary.setItem(row, col, QTableWidgetItem(value))
            self.trace_views[key].clear()
            self.trace_views[key].detail.setPlainText("尚未复核；缺少材料时会逐项提示。")

    def _set_busy(self, busy):
        for widget in (self.session_combo, self.btn_refresh, self.btn_import, self.btn_secret_import,
                       self.btn_keylog_import, self.secret_edit, self.keylog_edit, self.btn_clear):
            widget.setEnabled(not busy)
        self.btn_run.setEnabled(not busy and self._selected() is not None)

    def _run(self):
        session = self._selected()
        if self._worker is not None or session is None:
            return
        self._invalidate()
        try:
            parameters = json.loads(self.secret_edit.toPlainText() or "{}")
            if not isinstance(parameters, dict):
                raise ValueError("秘密参数必须为 JSON 对象")
            worker = _RecheckWorker(copy.deepcopy(session), parameters, self.keylog_edit.toPlainText(), self)
        except (ValueError, TypeError) as exc:
            self._failed(str(exc))
            return
        self._worker = worker
        self._set_busy(True)
        self.result_status.setText("正在使用实际材料重算…")
        worker.done.connect(self._show_result)
        worker.failed.connect(self._failed)
        worker.finished.connect(self._finished)
        worker.start()

    def _finished(self):
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.deleteLater()
        self._set_busy(False)

    def _failed(self, message):
        self._invalidate()
        self.result_status.setText("无法完成复核：" + message)
        self.output.setPlainText(message)

    def _show_result(self, result):
        self._result = result
        text = []
        for row, (key, label) in enumerate(OPERATIONS.items()):
            data = result[key]
            status = pqc_recheck.STATUS_TEXT[data["status"]]
            missing = [FIELD_NAMES.get(field, field) for field in data["missing"]]
            detail = data["detail"] + ("\n缺少：" + "；".join(missing) if missing else "")
            for col, value in enumerate((label, status, detail)):
                self.summary.setItem(row, col, QTableWidgetItem(value))
            steps = list(data["steps"]) + [pqc_recheck._step("输出与一致性结论", detail,
                                                            status=status, missing=missing, output=data["output"])]
            self.trace_views[key].set_trace({"algorithm": label, "parameters": {"session_id": result["input"]["session_id"],
                "group": result["input"].get("group_name", ""), "cipher": result["input"].get("cipher_suite", "")},
                "parameter_description": "实际连接参数", "parameter_reference": pqc_recheck.REFERENCE,
                "parameter_note": "读取原连接材料执行计算；秘密参数不自动导出。", "source": "原连接", "steps": steps})
            text += [label + "：" + status, detail, json.dumps(data["output"], ensure_ascii=False, indent=2), ""]
            if key == "records":
                for record in data["output"].get("records", []):
                    if record.get("authenticated") and record.get("content_type") == 23:
                        text += ["应用报文明文（UTF-8；完整原始字节见 content 十六进制）", record["utf8"], ""]
        self.summary.resizeRowsToContents()
        self.output.setPlainText("\n".join(text))
        self.input_view.setPlainText(json.dumps(result["input"], ensure_ascii=False, indent=2))
        states = [result[key]["status"] for key in OPERATIONS]
        self.result_status.setText("复核发现失败 / 不一致" if "failed" in states else
                                  "三项复核均通过" if all(s == "passed" for s in states) else "部分复核完成：请查看各项结论和缺失参数")
        self.pages.setCurrentIndex(0)

    def import_report(self, path):
        report = json.loads(Path(path).read_text(encoding="utf-8"))
        imported = []
        if "sessions" in report:
            for entry in report["sessions"]:
                if entry.get("recheck_session"):
                    imported.append(pqc_recheck.session_from_report(entry, label="导入抓包 %s → %s" % (entry.get("client", ""), entry.get("server", ""))))
                if entry.get("active_probe"):
                    imported.append(pqc_recheck.session_from_report(entry["active_probe"], label="导入的主动复测（独立连接）"))
        else:
            if report.get("schema") == "tls13-recheck-v1":
                report = {"recheck_session": report}
            imported.append(pqc_recheck.session_from_report(report))
        if not imported:
            raise ValueError("报告没有实际连接材料；请重新检测 / 导出抓包会话")
        self._imported.extend(imported)
        self.refresh_sessions()
        self.session_combo.setCurrentIndex(len(self._sessions) - len(imported))

    def import_keylog(self, path):
        self.keylog_edit.setPlainText(Path(path).read_text(encoding="utf-8"))

    def _pick_report(self):
        path, _ = QFileDialog.getOpenFileName(self, "导入实际连接报告", "", "JSON (*.json)")
        if path:
            try:
                self.import_report(path)
            except (ValueError, OSError, TypeError) as exc:
                self._failed(str(exc))

    def _pick_secrets(self):
        path, _ = QFileDialog.getOpenFileName(self, "导入同次连接秘密参数", "", "JSON (*.json)")
        if path:
            try:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
                self.secret_edit.setPlainText(json.dumps(data, ensure_ascii=False, indent=2))
            except (ValueError, OSError) as exc:
                self._failed(str(exc))

    def _pick_keylog(self):
        path, _ = QFileDialog.getOpenFileName(self, "导入原连接 Key Log", "", "Key Log (*.log *.txt);;所有文件 (*)")
        if path:
            try:
                self.import_keylog(path)
            except (OSError, ValueError) as exc:
                self._failed(str(exc))

    def _clear(self):
        self._imported, self._sessions = [], []
        self.session_combo.clear()
        self.secret_edit.clear()
        self.keylog_edit.clear()
        self.input_view.clear()
        self._invalidate()
        self.source_status.setText("已清空复核材料；刷新可再次选择前面的会话")
        self.btn_run.setEnabled(False)
