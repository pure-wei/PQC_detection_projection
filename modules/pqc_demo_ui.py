# -*- coding: utf-8 -*-
"""Qt pages for the offline PQC algorithm demonstrations."""

from html import escape

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QGroupBox, QHBoxLayout,
    QHeaderView, QLabel, QPlainTextEdit, QPushButton, QSplitter, QTextEdit,
    QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from modules import pqc_demo
from modules.mlkem_trace_ui import CalculationTraceView


_CAPTURE_DEMO_GROUPS = {
    0x0200: ("kem", None, "ML-KEM-512"),
    0x0201: ("kem", None, "ML-KEM-768"),
    0x0202: ("kem", None, "ML-KEM-1024"),
    0x11EB: ("hybrid", "P-256", "ML-KEM-768"),
    0x11EC: ("hybrid", "X25519", "ML-KEM-768"),
    0x11ED: ("hybrid", "P-384", "ML-KEM-1024"),
    0x11EE: ("hybrid", "X25519", "ML-KEM-1024"),
}


class _DemoWorker(QThread):
    done = Signal(dict)
    failed = Signal(str)

    def __init__(self, operation, message, algorithm="", classical_algorithm="X25519", parent=None):
        super().__init__(parent)
        self.operation = operation
        self.message = message
        self.algorithm = algorithm
        self.classical_algorithm = classical_algorithm

    def run(self):
        try:
            if self.operation == "kem":
                result = pqc_demo.run_kem_demo(self.algorithm)
            elif self.operation == "hybrid":
                result = pqc_demo.run_hybrid_demo(
                    self.message, self.algorithm, self.classical_algorithm)
            elif self.operation == "hybrid_sign":
                result = pqc_demo.run_hybrid_signature_demo(
                    self.message, self.algorithm, self.classical_algorithm)
            else:
                result = pqc_demo.run_signature_demo(self.message, self.algorithm)
        except Exception as exc:
            self.failed.emit("%s: %s" % (type(exc).__name__, exc))
        else:
            self.done.emit(result)


class PqcDemoTab(QWidget):
    """KEM, hybrid encryption, PQC signatures and hybrid signature demos."""

    def __init__(self, parent=None, *, capture_provider=None):
        super().__init__(parent)
        self._worker = None
        self._capture_provider = capture_provider
        self._captured_brief = ""
        root = QVBoxLayout(self)

        intro = QLabel("离线算法演示 · 每次使用临时密钥。‘参数与计算过程’展示本轮真实数值与临时秘密；原生库未返回的数据会注明。仅供教学，不自动保存。输入消息最多 4096 字节。")
        intro.setWordWrap(True)
        root.addWidget(intro)

        capture_box = QGroupBox("检测抓取参数")
        capture_layout = QHBoxLayout(capture_box)
        self.capture_status = QLabel("未导入检测结果；也可手动选择参数运行演示。")
        self.capture_status.setWordWrap(True)
        capture_layout.addWidget(self.capture_status, 1)
        self.btn_import_capture = QPushButton("导入最近检测结果")
        self.btn_import_capture.setEnabled(capture_provider is not None)
        self.btn_import_capture.clicked.connect(self.import_captured_parameters)
        capture_layout.addWidget(self.btn_import_capture)
        root.addWidget(capture_box)

        self.main_splitter = QSplitter(Qt.Orientation.Vertical)
        root.addWidget(self.main_splitter, 1)

        message_box = QGroupBox("输入消息（UTF-8；供混合加密与数字签名使用）")
        self.message_box = message_box
        mv = QVBoxLayout(message_box)
        self.message_edit = QPlainTextEdit("你好，后量子密码！")
        self.message_edit.setMinimumHeight(50)
        mv.addWidget(self.message_edit)
        self.main_splitter.addWidget(message_box)

        self.pages = QTabWidget()
        self.main_splitter.addWidget(self.pages)
        self.main_splitter.setStretchFactor(0, 1)
        self.main_splitter.setStretchFactor(1, 4)
        self.main_splitter.setSizes([110, 500])

        standalone = QWidget()
        kv = QVBoxLayout(standalone)
        kem_hint = QLabel("无需输入消息。接收方生成密钥，发送方封装，接收方解封装；运行后可展开随机采样、矩阵、NTT、压缩编码和隐式拒绝的实际计算。")
        kem_hint.setWordWrap(True)
        kv.addWidget(kem_hint)
        kem_controls = QHBoxLayout()
        kem_controls.addWidget(QLabel("参数组"))
        self.standalone_kem_combo = QComboBox()
        self.standalone_kem_combo.addItems(pqc_demo.KEM_VARIANTS)
        kem_controls.addWidget(self.standalone_kem_combo)
        self.btn_kem = QPushButton("运行密钥封装演示")
        self.btn_kem.setObjectName("primary")
        self.btn_kem.clicked.connect(lambda: self._start("kem"))
        kem_controls.addWidget(self.btn_kem)
        kem_controls.addStretch(1)
        kv.addLayout(kem_controls)
        kem_result = QGroupBox("执行过程与结论")
        kr = QVBoxLayout(kem_result)
        self.kem_status = QLabel("等待运行")
        kr.addWidget(self.kem_status)
        self.kem_output = QTextEdit()
        self.kem_output.setReadOnly(True)
        self.kem_output.setPlaceholderText("选择参数组并运行，查看封装、解封装和验证结果。")
        self.kem_result_tabs = QTabWidget()
        self.kem_trace_view = CalculationTraceView()
        self.kem_result_tabs.addTab(self.kem_output, "执行摘要")
        self.kem_result_tabs.addTab(self.kem_trace_view, "参数与计算过程")
        kr.addWidget(self.kem_result_tabs, 1)
        kv.addWidget(kem_result, 1)
        self.kem_raw_checkbox = QCheckBox("显示公钥与封装密文（Base64）")
        kv.addWidget(self.kem_raw_checkbox)
        self.kem_raw_output = QPlainTextEdit()
        self.kem_raw_output.setReadOnly(True)
        self.kem_raw_output.setVisible(False)
        self.kem_raw_checkbox.toggled.connect(self.kem_raw_output.setVisible)
        kv.addWidget(self.kem_raw_output, 1)
        self.pages.addTab(standalone, "① ML-KEM 密钥封装")

        hybrid = QWidget()
        hv = QVBoxLayout(hybrid)
        hint = QLabel("选择 ECDH 曲线与 ML-KEM 参数组，现场生成临时密钥；HKDF-SHA256 派生 AES-256-GCM 密钥，演示加解密和篡改检测。")
        hint.setWordWrap(True)
        hv.addWidget(hint)
        hybrid_controls = QHBoxLayout()
        hybrid_controls.addWidget(QLabel("经典密钥交换"))
        self.classical_combo = QComboBox()
        self.classical_combo.addItems(pqc_demo.CLASSICAL_VARIANTS)
        hybrid_controls.addWidget(self.classical_combo)
        hybrid_controls.addWidget(QLabel("后量子密钥封装"))
        self.kem_combo = QComboBox()
        self.kem_combo.addItems(pqc_demo.KEM_VARIANTS)
        self.kem_combo.setCurrentText("ML-KEM-768")
        hybrid_controls.addWidget(self.kem_combo)
        self.btn_hybrid = QPushButton("运行混合加密演示")
        self.btn_hybrid.setObjectName("primary")
        self.btn_hybrid.clicked.connect(lambda: self._start("hybrid"))
        hybrid_controls.addWidget(self.btn_hybrid)
        hybrid_controls.addStretch(1)
        hv.addLayout(hybrid_controls)
        hybrid_result = QGroupBox("执行过程与结论")
        hr = QVBoxLayout(hybrid_result)
        self.hybrid_status = QLabel("等待运行")
        hr.addWidget(self.hybrid_status)
        self.hybrid_output = QTextEdit()
        self.hybrid_output.setReadOnly(True)
        self.hybrid_output.setPlaceholderText("输入消息并运行，查看密钥协商、加解密和篡改检测结果。")
        self.hybrid_result_tabs = QTabWidget()
        self.hybrid_trace_view = CalculationTraceView()
        self.hybrid_result_tabs.addTab(self.hybrid_output, "执行摘要")
        self.hybrid_result_tabs.addTab(self.hybrid_trace_view, "参数与计算过程")
        hr.addWidget(self.hybrid_result_tabs, 1)
        hv.addWidget(hybrid_result, 1)
        self.hybrid_raw_checkbox = QCheckBox("显示原始数据（Base64）")
        hv.addWidget(self.hybrid_raw_checkbox)
        self.hybrid_raw_output = QPlainTextEdit()
        self.hybrid_raw_output.setReadOnly(True)
        self.hybrid_raw_output.setVisible(False)
        self.hybrid_raw_checkbox.toggled.connect(self.hybrid_raw_output.setVisible)
        hv.addWidget(self.hybrid_raw_output, 1)
        self.pages.addTab(hybrid, "② 混合加密")

        signing = QWidget()
        sv = QVBoxLayout(signing)
        shint = QLabel("选一种签名算法，现场生成密钥、签名并验签；同时用改动后的消息验证签名失效。Falcon 对应的 FIPS 206 仍在制定中。")
        shint.setWordWrap(True)
        sv.addWidget(shint)
        controls = QHBoxLayout()
        controls.addWidget(QLabel("签名算法"))
        self.signature_combo = QComboBox()
        self.signature_combo.addItems(pqc_demo.SIGNATURE_VARIANTS)
        self.signature_combo.setCurrentText("ML-DSA-65")
        controls.addWidget(self.signature_combo)
        self.btn_sign = QPushButton("生成签名并验签")
        self.btn_sign.setObjectName("primary")
        self.btn_sign.clicked.connect(lambda: self._start("sign"))
        controls.addWidget(self.btn_sign)
        controls.addStretch(1)
        sv.addLayout(controls)
        signature_result = QGroupBox("执行过程与结论")
        sr = QVBoxLayout(signature_result)
        self.signature_status = QLabel("等待运行")
        sr.addWidget(self.signature_status)
        self.signature_output = QTextEdit()
        self.signature_output.setReadOnly(True)
        self.signature_output.setPlaceholderText("输入消息并运行，查看签名和验签结果。")
        self.signature_result_tabs = QTabWidget()
        self.signature_trace_view = CalculationTraceView()
        self.signature_result_tabs.addTab(self.signature_output, "执行摘要")
        self.signature_result_tabs.addTab(self.signature_trace_view, "参数与计算过程")
        sr.addWidget(self.signature_result_tabs, 1)
        sv.addWidget(signature_result, 1)
        self.signature_raw_checkbox = QCheckBox("显示原始数据（Base64）")
        sv.addWidget(self.signature_raw_checkbox)
        self.signature_raw_output = QPlainTextEdit()
        self.signature_raw_output.setReadOnly(True)
        self.signature_raw_output.setVisible(False)
        self.signature_raw_checkbox.toggled.connect(self.signature_raw_output.setVisible)
        sv.addWidget(self.signature_raw_output, 1)
        self.pages.addTab(signing, "③ 后量子数字签名")

        hybrid_signing = QWidget()
        hsv = QVBoxLayout(hybrid_signing)
        hybrid_sign_hint = QLabel("传统算法与后量子算法共同签名，必须两份签名都通过才接受；分别演示消息、传统签名和后量子签名被篡改后的拒绝结果。")
        hybrid_sign_hint.setWordWrap(True)
        hsv.addWidget(hybrid_sign_hint)
        hybrid_sign_controls = QHBoxLayout()
        hybrid_sign_controls.addWidget(QLabel("传统签名"))
        self.hybrid_signature_classical_combo = QComboBox()
        self.hybrid_signature_classical_combo.addItems(pqc_demo.CLASSICAL_SIGNATURE_VARIANTS)
        hybrid_sign_controls.addWidget(self.hybrid_signature_classical_combo)
        hybrid_sign_controls.addWidget(QLabel("后量子签名"))
        self.hybrid_signature_combo = QComboBox()
        self.hybrid_signature_combo.addItems(pqc_demo.SIGNATURE_VARIANTS)
        self.hybrid_signature_combo.setCurrentText("ML-DSA-65")
        hybrid_sign_controls.addWidget(self.hybrid_signature_combo)
        self.btn_hybrid_sign = QPushButton("生成混合签名并验签")
        self.btn_hybrid_sign.setObjectName("primary")
        self.btn_hybrid_sign.clicked.connect(lambda: self._start("hybrid_sign"))
        hybrid_sign_controls.addWidget(self.btn_hybrid_sign)
        hybrid_sign_controls.addStretch(1)
        hsv.addLayout(hybrid_sign_controls)
        hybrid_signature_result = QGroupBox("执行过程与结论")
        hsr = QVBoxLayout(hybrid_signature_result)
        self.hybrid_signature_status = QLabel("等待运行")
        hsr.addWidget(self.hybrid_signature_status)
        self.hybrid_signature_output = QTextEdit()
        self.hybrid_signature_output.setReadOnly(True)
        self.hybrid_signature_output.setPlaceholderText("输入消息并运行，查看两份签名、混合验签和篡改拒绝结果。")
        self.hybrid_signature_result_tabs = QTabWidget()
        self.hybrid_signature_trace_view = CalculationTraceView()
        self.hybrid_signature_result_tabs.addTab(self.hybrid_signature_output, "执行摘要")
        self.hybrid_signature_result_tabs.addTab(self.hybrid_signature_trace_view, "参数与计算过程")
        hsr.addWidget(self.hybrid_signature_result_tabs, 1)
        hsv.addWidget(hybrid_signature_result, 1)
        self.hybrid_signature_raw_checkbox = QCheckBox("显示两份公钥与签名（Base64）")
        hsv.addWidget(self.hybrid_signature_raw_checkbox)
        self.hybrid_signature_raw_output = QPlainTextEdit()
        self.hybrid_signature_raw_output.setReadOnly(True)
        self.hybrid_signature_raw_output.setVisible(False)
        self.hybrid_signature_raw_checkbox.toggled.connect(self.hybrid_signature_raw_output.setVisible)
        hsv.addWidget(self.hybrid_signature_raw_output, 1)
        self.pages.addTab(hybrid_signing, "④ 混合数字签名")
        self.pages.currentChanged.connect(self._sync_message_visibility)
        self._sync_message_visibility(self.pages.currentIndex())

    def showEvent(self, event):
        super().showEvent(event)
        if self._capture_provider is not None:
            self.import_captured_parameters()

    def import_captured_parameters(self):
        if self._capture_provider is None:
            self.capture_status.setText("当前未连接检测结果。")
            return False
        try:
            report = self._capture_provider() or {}
        except Exception as exc:
            self.capture_status.setText("读取检测结果失败：%s" % exc)
            return False
        transport = report.get("transport") or {}
        mapping = _CAPTURE_DEMO_GROUPS.get(transport.get("group_id"))
        if not mapping:
            selected = transport.get("group_name") or "未取得 ML-KEM 组"
            self.capture_status.setText(
                "最近检测结果未选中 ML-KEM / 混合组（%s），请先检测或手动选择参数。" % selected)
            return False
        demo_kind, classical_algorithm, kem_algorithm = mapping
        if demo_kind == "hybrid":
            self.classical_combo.setCurrentText(classical_algorithm)
            self.kem_combo.setCurrentText(kem_algorithm)
            self.pages.setCurrentIndex(1)
            demo_name = "%s + %s 混合加密" % (classical_algorithm, kem_algorithm)
        else:
            self.standalone_kem_combo.setCurrentText(kem_algorithm)
            self.pages.setCurrentIndex(0)
            demo_name = "%s 密钥封装" % kem_algorithm

        cert = report.get("cert") or {}
        offered = "、".join(transport.get("offered") or []) or "—"
        summary = "\n".join(filter(None, [
            "TLS 检测目标：%s:%s" % (report.get("host", ""), report.get("port", "")),
            "ClientHello 提供组：%s" % offered,
            "ServerHello 选中组：%s（0x%04X）" % (
                transport.get("group_name", ""), transport.get("group_id", 0)),
            "服务器 key_share：%d 字节（规范 %d 字节，%s）" % (
                transport.get("key_share_body", 0), transport.get("expect_body", 0),
                "一致" if transport.get("size_ok") else "不一致"),
            "协商套件：%s" % (transport.get("cipher_suite") or "—"),
            "证书主体：%s" % (cert.get("subject_cn") or "—"),
        ]))
        self.message_edit.setPlainText(summary)
        self._captured_brief = "来源：%s · %s" % (report.get("host", "检测目标"), demo_name)
        self.capture_status.setText("已导入 %s，可运行对应演示。" % self._captured_brief)
        return True

    def _sync_message_visibility(self, index):
        self.message_box.setVisible(index != 0)

    def _calculation_widgets(self, operation):
        return {"kem": (self.kem_trace_view, self.kem_result_tabs),
                "hybrid": (self.hybrid_trace_view, self.hybrid_result_tabs),
                "sign": (self.signature_trace_view, self.signature_result_tabs),
                "hybrid_sign": (self.hybrid_signature_trace_view, self.hybrid_signature_result_tabs)}[operation]

    def _start(self, operation):
        if self._worker is not None and self._worker.isRunning():
            return
        message = self.message_edit.toPlainText().encode("utf-8")
        outputs = {"kem": self.kem_output, "hybrid": self.hybrid_output,
                   "sign": self.signature_output,
                   "hybrid_sign": self.hybrid_signature_output}
        output = outputs[operation]
        view, tabs = self._calculation_widgets(operation)
        view.clear()
        tabs.setCurrentIndex(0)
        {"kem": self.kem_raw_output, "hybrid": self.hybrid_raw_output,
         "sign": self.signature_raw_output,
         "hybrid_sign": self.hybrid_signature_raw_output}[operation].clear()
        if operation != "kem" and len(message) > 4096:
            output.setPlainText("输入消息超过 4096 字节（UTF-8）；请缩短后重试。")
            self._set_status(operation, "输入过长", False)
            return
        algorithm = {"kem": self.standalone_kem_combo.currentText(),
                     "hybrid": self.kem_combo.currentText(),
                     "sign": self.signature_combo.currentText(),
                     "hybrid_sign": self.hybrid_signature_combo.currentText()}[operation]
        output.setPlainText("正在执行真实密码运算…")
        self._set_status(operation, "运行中…", None)
        self.btn_kem.setEnabled(False)
        self.btn_hybrid.setEnabled(False)
        self.btn_sign.setEnabled(False)
        self.btn_hybrid_sign.setEnabled(False)
        classical_algorithm = (self.hybrid_signature_classical_combo.currentText()
                               if operation == "hybrid_sign" else self.classical_combo.currentText())
        worker = _DemoWorker(operation, message, algorithm,
                             classical_algorithm, self)
        self._worker = worker
        worker.done.connect(lambda data: self._show_result(operation, data))
        worker.failed.connect(lambda error: self._show_failure(operation, error))
        worker.finished.connect(self._finished)
        worker.start()

    def _set_status(self, operation, message, success):
        label = {"kem": self.kem_status, "hybrid": self.hybrid_status,
                 "sign": self.signature_status,
                 "hybrid_sign": self.hybrid_signature_status}[operation]
        color = "#166534" if success else "#b91c1c" if success is False else "#475569"
        background = "#dcfce7" if success else "#fee2e2" if success is False else "#e2e8f0"
        label.setText(message)
        label.setStyleSheet("QLabel { color: %s; background: %s; padding: 8px 12px; border-radius: 6px; font-weight: 600; }" % (color, background))

    def _show_failure(self, operation, error):
        {"kem": self.kem_output, "hybrid": self.hybrid_output,
         "sign": self.signature_output,
         "hybrid_sign": self.hybrid_signature_output}[operation].setPlainText("运行失败：" + error)
        self._set_status(operation, "运行失败", False)

    @staticmethod
    def _render_report(output, lines):
        """Present the algorithm, numbered stages and findings as readable blocks."""
        blocks = []
        for index, line in enumerate(lines):
            if not line:
                continue
            safe = escape(line).replace("\n", "<br>")
            if index == 0:
                blocks.append('<p style="font-weight:600;color:#1e3a8a;font-size:14px;">%s</p>' % safe)
            elif line[0] in "①②③④":
                blocks.append('<p style="margin-top:14px;color:#2563eb;font-weight:600;">%s</p>' % safe)
            else:
                blocks.append('<p style="margin-left:16px;margin-top:3px;">%s</p>' % safe)
        output.setHtml("<html><body style='font-family:sans-serif;color:#1f2937;'>%s</body></html>" % "".join(blocks))

    def _finished(self):
        self.btn_kem.setEnabled(True)
        self.btn_hybrid.setEnabled(True)
        self.btn_sign.setEnabled(True)
        self.btn_hybrid_sign.setEnabled(True)
        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None

    def _show_result(self, operation, data):
        view, tabs = self._calculation_widgets(operation)
        view.set_trace(data["calculation_trace"])
        tabs.setCurrentIndex(1)
        if operation == "kem":
            success = (data["shared_secret_matches"] and
                       data["changed_ciphertext_changes_secret"])
            self._set_status(operation, "验证通过 · 双方得到相同的共享秘密" if success else "验证未通过", success)
            self._render_report(self.kem_output, [
                "算法：%s（纯后量子密钥封装）" % data["algorithm"],
                self._captured_brief,
                "① 接收方生成密钥对",
                "   公钥：%d 字节；私钥仅用于本次解封装" % data["public_key_bytes"],
                "② 发送方用公钥封装",
                "   封装密文：%d 字节；共享秘密：%d 字节" % (
                    data["ciphertext_bytes"], data["shared_secret_bytes"]),
                "③ 接收方用私钥解封装",
                "   双方共享秘密一致：%s" % ("是" if data["shared_secret_matches"] else "否"),
                "   秘密指纹（SHA-256 前 16 位）：发送方 %s / 接收方 %s" % (
                    data["sender_fingerprint"], data["receiver_fingerprint"]),
                "④ 修改封装密文再解封装",
                "   修改封装密文后秘密不同：%s" % (
                    "是" if data["changed_ciphertext_changes_secret"] else "否"),
                "   说明：ML-KEM 的隐式拒绝会产生另一份秘密，不表示抛出认证错误。",
            ])
            self.kem_raw_output.setPlainText("\n".join([
                "公钥（Base64）：", data["public_key_base64"],
                "封装密文（Base64）：", data["ciphertext_base64"],
            ]))
        elif operation == "hybrid":
            success = (data["ecdh_shared_secret_matches"] and
                       data["kem_shared_secret_matches"] and data["tamper_rejected"])
            self._set_status(operation, "验证通过 · 解密成功且篡改已拒绝" if success else "验证未通过", success)
            lines = [
                "算法：%s + %s / HKDF-SHA256 / AES-256-GCM" % (
                    data["classical_algorithm"], data["kem_algorithm"]),
                self._captured_brief,
                "① 生成临时密钥并完成两路密钥交换",
                "%s 公钥：%d 字节" % (
                    data["classical_algorithm"], data["classical_public_key_bytes"]),
                "ML-KEM 公钥：%d 字节；封装密文：%d 字节" % (
                    data["kem_public_key_bytes"], data["kem_ciphertext_bytes"]),
                "双方 ECDH 秘密一致：%s" % ("是" if data["ecdh_shared_secret_matches"] else "否"),
                "双方 KEM 秘密一致：%s" % ("是" if data["kem_shared_secret_matches"] else "否"),
                "② HKDF 派生密钥，AES-GCM 加密后解密",
                "解密结果：%s" % data["recovered"].decode("utf-8"),
                "③ 修改密文并验证认证标签",
                "篡改检测：%s" % ("已拒绝" if data["tamper_rejected"] else "未拒绝"),
            ]
            self._render_report(self.hybrid_output, lines)
            self.hybrid_raw_output.setPlainText("\n".join([
                "经典发送方公钥（Base64）：", data["sender_public_key_base64"],
                "ML-KEM 接收方公钥（Base64）：", data["kem_public_key_base64"],
                "AES-GCM 密文（Base64，含认证标签）：", data["ciphertext_base64"],
                "ML-KEM 封装密文（Base64）：", data["kem_ciphertext_base64"],
                "Nonce（Base64）：", data["nonce_base64"],
            ]))
        elif operation == "hybrid_sign":
            checks = data["checks"]
            original = checks["original"]
            success = (original["verified"] and
                       all(not check["verified"] for name, check in checks.items()
                           if name != "original"))
            self._set_status(operation, "验证通过 · 两份签名均有效，篡改已拒绝" if success else "验证未通过", success)
            lines = [
                "算法：%s + %s" % (data["classical_algorithm"], data["pq_algorithm"]),
                "① 生成两组临时签名密钥对",
                "传统公钥：%d 字节（%s）；后量子公钥：%d 字节" % (
                    data["classical_public_key_bytes"], data["classical_public_key_encoding"],
                    data["pq_public_key_bytes"]),
                "② 对绑定同一消息的两份数据分别签名",
                "传统签名：%d 字节（%s）；后量子签名：%d 字节；两份合计：%d 字节" % (
                    data["classical_signature_bytes"], data["classical_signature_encoding"],
                    data["pq_signature_bytes"], data["signature_bytes"]),
                "③ 分别验签，按 AND 规则接受",
                "传统签名验签：%s" % ("通过" if original["classical_verified"] else "失败"),
                "后量子签名验签：%s" % ("通过" if original["pq_verified"] else "失败"),
                "混合验签（AND）：%s" % ("通过" if original["verified"] else "失败"),
                "④ 独立篡改后重新验签",
            ]
            for title, check_name in (
                    ("改动消息", "changed_message"),
                    ("篡改传统签名", "changed_classical_signature"),
                    ("篡改后量子签名", "changed_pq_signature")):
                check = checks[check_name]
                lines.append("%s：%s（传统验签：%s；后量子验签：%s）" % (
                    title, "异常通过" if check["verified"] else "已拒绝",
                    "通过" if check["classical_verified"] else "失败",
                    "通过" if check["pq_verified"] else "失败"))
            self._render_report(self.hybrid_signature_output, lines)
            self.hybrid_signature_raw_output.setPlainText("\n".join([
                "传统公钥（Base64；%s）：" % data["classical_public_key_encoding"],
                data["classical_public_key_base64"],
                "后量子公钥（Base64）：", data["pq_public_key_base64"],
                "传统签名（Base64）：", data["classical_signature_base64"],
                "后量子签名（Base64）：", data["pq_signature_base64"],
            ]))
        else:
            success = data["verified"] and not data["altered_verified"]
            self._set_status(operation, "验证通过 · 原消息有效，改动消息已拒绝" if success else "验证未通过", success)
            lines = [
                "算法：" + data["algorithm"],
                "",
                "① 生成临时签名密钥对",
                "公钥：%d 字节；签名：%d 字节" % (
                    data["public_key_bytes"], data["signature_bytes"]),
                "② 对输入消息签名并验签",
                "原消息验签：%s" % ("通过" if data["verified"] else "失败"),
                "③ 修改消息后再次验签",
                "改动消息验签：%s" % ("异常通过" if data["altered_verified"] else "已拒绝"),
            ]
            self._render_report(self.signature_output, lines)
            self.signature_raw_output.setPlainText("\n".join([
                "公钥（Base64）：", data["public_key_base64"],
                "签名（Base64）：", data["signature_base64"],
            ]))


class PqcCompareTab(QWidget):
    """Representative classical and PQC parameter comparison."""

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        note = QLabel("传统与后量子公钥算法对比。表中的传统算法不具备抗量子安全性；密钥交换、密钥封装和签名的输出用途不同。EC 公钥按未压缩点计，RSA 公钥按 SPKI DER 计（指数 65537），其余为原始字节；ECDSA 的 DER 签名长度可变。NIST 等级不能直接等同于经典算法的安全位数。Falcon 的标准仍在制定中。")
        note.setWordWrap(True)
        root.addWidget(note)
        rows = pqc_demo.comparison_rows()
        self.table = QTableWidget(len(rows), 6)
        self.table.setHorizontalHeaderLabels(["算法", "用途", "公钥（字节）", "密文 / 签名 / 秘密", "标准状态", "数学基础"])
        keys = ["name", "kind", "public_size", "output_size", "standard", "basis"]
        for row_index, row in enumerate(rows):
            for col_index, key in enumerate(keys):
                self.table.setItem(row_index, col_index, QTableWidgetItem(row[key]))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table, 1)
