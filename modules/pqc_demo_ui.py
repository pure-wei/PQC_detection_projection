# -*- coding: utf-8 -*-
"""Qt pages for the offline PQC algorithm demonstrations."""

import base64
import json
import os
from html import escape

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QGridLayout, QGroupBox, QHBoxLayout,
    QHeaderView, QLabel, QPlainTextEdit, QPushButton, QSplitter, QTextEdit,
    QTableWidget, QTableWidgetItem, QTabWidget,
    QVBoxLayout, QWidget,
    QFileDialog,
)

from modules import pqc_demo
from modules.mlkem_trace_ui import CalculationTraceView
from modules import pqc_replay
from modules.pqc_replay import ReplayInputError


_CAPTURE_DEMO_GROUPS = {
    0x0200: ("kem", None, "ML-KEM-512"),
    0x0201: ("kem", None, "ML-KEM-768"),
    0x0202: ("kem", None, "ML-KEM-1024"),
    0x11EB: ("hybrid", "P-256", "ML-KEM-768"),
    0x11EC: ("hybrid", "X25519", "ML-KEM-768"),
    0x11ED: ("hybrid", "P-384", "ML-KEM-1024"),
    0x11EE: ("hybrid", "X25519", "ML-KEM-1024"),
}


class _DemoMaterialsView(QWidget):
    """Separate key fields above the message, with output below it."""

    def __init__(self):
        super().__init__()
        self._materials = {}
        self._input_encoding = ""
        self.keys_box = QGroupBox("临时密钥（运行后自动填充）")
        grid = QGridLayout(self.keys_box)
        row = QHBoxLayout()
        row.addWidget(QLabel("密钥 / 输出编码"))
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(["HEX", "Base64"])
        self.encoding_combo.currentTextChanged.connect(self._render)
        row.addWidget(self.encoding_combo)
        row.addWidget(QLabel("完整数据可选中复制。"))
        row.addStretch(1)
        grid.addLayout(row, 0, 0, 1, 2)
        self.private_edit = QPlainTextEdit()
        self.public_edit = QPlainTextEdit()
        for index, (label, editor) in enumerate((("私钥", self.private_edit), ("公钥", self.public_edit)), 1):
            editor.setReadOnly(True)
            editor.setMinimumHeight(45)
            editor.setPlaceholderText("运行演示后显示本轮完整%s" % label)
            grid.addWidget(QLabel(label), index, 0)
            grid.addWidget(editor, index, 1)
        grid.setColumnStretch(1, 1)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("运行后显示密文、签名、共享秘密或解密明文。")
        layout.addWidget(self.output, 1)

    def clear(self):
        self._materials = {}
        self._input_encoding = ""
        self.private_edit.clear()
        self.public_edit.clear()
        self.output.clear()

    def set_materials(self, materials, input_encoding=""):
        self._materials = materials
        self._input_encoding = input_encoding
        self._render()

    def _render(self):
        encoding = self.encoding_combo.currentText()
        def format_fields(fields):
            lines = []
            for label, value in fields.items():
                shown = value.hex() if encoding == "HEX" else base64.b64encode(value).decode("ascii")
                lines.extend(["%s（%s，%d 字节）：" % (label, encoding, len(value)), shown, ""])
                if label == "解密明文":
                    try:
                        lines.extend(["%s（UTF-8）：%s" % (label, json.dumps(value.decode("utf-8"), ensure_ascii=False)), ""])
                    except UnicodeDecodeError:
                        pass
            return "\n".join(lines)

        keys = self._materials.get("keys", {})
        self.private_edit.setPlainText(format_fields({k: v for k, v in keys.items() if "私钥" in k}))
        self.public_edit.setPlainText(format_fields({k: v for k, v in keys.items() if "公钥" in k}))
        lines = []
        if self._input_encoding:
            lines.append("输入编码：" + self._input_encoding)
        outputs = self._materials.get("outputs", {})
        if outputs:
            lines.extend(["【输出】", format_fields(outputs)])
        parameters = {k: v for k, v in self._materials.get("inputs", {}).items() if k != "消息原始字节"}
        if parameters:
            lines.extend(["【计算参数】", format_fields(parameters)])
        self.output.setPlainText("\n".join(lines))


class _DemoMessageBox(QGroupBox):
    """A permanent input form owned by a single demonstration page."""

    changed = Signal()

    def __init__(self, operation):
        titles = {"kem": "封装输入 m（32 字节）", "hybrid": "输入消息（加解密明文）",
                  "sign": "输入消息（待签名消息）", "hybrid_sign": "输入消息（待混合签名消息）"}
        super().__init__(titles[operation])
        self.is_kem = operation == "kem"
        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("输入编码" if self.is_kem else "消息编码"))
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(["UTF-8", "HEX", "Base64"])
        self.encoding_combo.setCurrentText("HEX" if self.is_kem else "UTF-8")
        row.addWidget(self.encoding_combo)
        self.info = QLabel()
        row.addWidget(self.info, 1)
        if self.is_kem:
            self.btn_random = QPushButton("随机生成 32 字节")
            self.btn_random.clicked.connect(self._random_input)
            row.addWidget(self.btn_random)
        self.btn_file = QPushButton("导入消息文件…" if not self.is_kem else "导入输入文件…")
        self.btn_file.clicked.connect(self._pick_file)
        row.addWidget(self.btn_file)
        layout.addLayout(row)
        self.edit = QPlainTextEdit(os.urandom(32).hex() if self.is_kem else "你好，后量子密码！")
        self.edit.setMinimumHeight(50)
        self.edit.setPlaceholderText("输入 32 字节封装输入 m，可使用上方按钮随机生成" if self.is_kem
                                     else "输入消息；支持 UTF-8 / HEX / Base64 或文件导入")
        layout.addWidget(self.edit)
        self.edit.textChanged.connect(self._edited)
        self.encoding_combo.currentTextChanged.connect(self._edited)
        self.refresh_info()

    def message_bytes(self):
        text = self.edit.toPlainText()
        encoding = self.encoding_combo.currentText()
        try:
            if encoding == "HEX":
                data = bytes.fromhex(text)
            elif encoding == "Base64":
                data = base64.b64decode("".join(text.split()), validate=True)
            else:
                data = text.encode("utf-8")
        except ValueError as exc:
            raise ValueError("%s 编码无效，请检查输入内容。" % encoding) from exc
        if self.is_kem and len(data) != 32:
            raise ValueError("封装输入 m 必须为 32 字节，当前为 %d 字节。" % len(data))
        return data

    def refresh_info(self):
        try:
            data = self.message_bytes()
            self.info.setText("字节数：%d / %d | HEX 预览：%s" % (
                len(data), 32 if self.is_kem else 4096, data[:8].hex()))
        except ValueError as exc:
            self.info.setText(str(exc))

    def _edited(self):
        self.refresh_info()
        self.changed.emit()

    def _random_input(self):
        self.encoding_combo.setCurrentText("HEX")
        self.edit.setPlainText(os.urandom(32).hex())

    def _pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择输入文件", "", "所有文件 (*)")
        if path:
            self.load_file(path)

    def load_file(self, path):
        try:
            with open(path, "rb") as handle:
                data = handle.read(4097)
            if self.is_kem and len(data) != 32:
                raise ValueError("封装输入文件必须为 32 字节。")
            if len(data) > 4096:
                raise ValueError("消息文件超过 4096 字节，请选择更小的文件。")
        except (OSError, ValueError) as exc:
            self.info.setText("导入失败：%s" % exc)
            return
        self.encoding_combo.setCurrentText("HEX")
        self.edit.setPlainText(data.hex())


class _DemoWorker(QThread):
    done = Signal(dict)
    failed = Signal(str)

    def __init__(self, operation, message, algorithm="", classical_algorithm="X25519", parent=None,
                 message_encoding="UTF-8"):
        super().__init__(parent)
        self.operation = operation
        self.message = message
        self.algorithm = algorithm
        self.classical_algorithm = classical_algorithm
        self.message_encoding = message_encoding

    def run(self):
        try:
            if self.operation == "kem":
                result = pqc_demo.run_kem_demo(self.algorithm, self.message)
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
            result["input_encoding"] = self.message_encoding
            self.done.emit(result)


class PqcDemoTab(QWidget):
    """Offline PQC demos, with an optional legacy connection replay page."""

    def __init__(self, parent=None, *, capture_provider=None, session_provider=None,
                 include_replay=False):
        super().__init__(parent)
        self._worker = None
        self._include_replay = include_replay
        self._capture_provider = capture_provider
        self._session_provider = session_provider
        self._replay_sessions = []
        self._captured_brief = ""
        root = QVBoxLayout(self)

        intro = QLabel("本页现场生成临时公钥 / 私钥，演示密钥封装、混合密钥交换、后量子签名与混合签名，并展示实际参数、计算过程及验证结果。")
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
        capture_box.setVisible(capture_provider is not None)

        self.pages = QTabWidget()
        root.addWidget(self.pages, 1)

        standalone = QWidget()
        kv = QVBoxLayout(standalone)
        kem_hint = QLabel("输入或随机生成 32 字节封装输入 m，接收方生成密钥，发送方封装，接收方解封装；可展开实际计算过程。")
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
        self.pages.addTab(standalone, "① ML-KEM 密钥封装")

        hybrid = QWidget()
        hv = QVBoxLayout(hybrid)
        hint = QLabel("选择 ECDHE 曲线与 ML-KEM 参数组，现场生成临时密钥；HKDF-SHA256 派生 AES-256-GCM 密钥，演示加解密和篡改检测。")
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
        self.btn_hybrid = QPushButton("运行混合密钥交换演示")
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
        self.pages.addTab(hybrid, "② 混合密钥交换")

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
        self.pages.addTab(signing, "③ 后量子数字签名")

        hybrid_signing = QWidget()
        hsv = QVBoxLayout(hybrid_signing)
        hybrid_sign_hint = QLabel("选择传统与后量子签名算法，现场生成两组密钥并对同一消息签名；两份签名均验签通过才接受，同时检查改动消息或任一签名后的拒绝结果。")
        hybrid_sign_hint.setWordWrap(True)
        hsv.addWidget(hybrid_sign_hint)
        hybrid_sign_controls = QHBoxLayout()
        hybrid_sign_controls.addWidget(QLabel("传统签名"))
        self.hybrid_classical_signature_combo = QComboBox()
        self.hybrid_classical_signature_combo.addItems(pqc_demo.CLASSICAL_SIGNATURE_VARIANTS)
        hybrid_sign_controls.addWidget(self.hybrid_classical_signature_combo)
        hybrid_sign_controls.addWidget(QLabel("后量子签名"))
        self.hybrid_pq_signature_combo = QComboBox()
        self.hybrid_pq_signature_combo.addItems(pqc_demo.SIGNATURE_VARIANTS)
        self.hybrid_pq_signature_combo.setCurrentText("ML-DSA-65")
        hybrid_sign_controls.addWidget(self.hybrid_pq_signature_combo)
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
        self.hybrid_signature_output.setPlaceholderText("输入消息并运行，查看两份签名、AND 验签和独立篡改检测结果。")
        self.hybrid_signature_result_tabs = QTabWidget()
        self.hybrid_signature_trace_view = CalculationTraceView()
        self.hybrid_signature_result_tabs.addTab(self.hybrid_signature_output, "执行摘要")
        self.hybrid_signature_result_tabs.addTab(self.hybrid_signature_trace_view, "参数与计算过程")
        hsr.addWidget(self.hybrid_signature_result_tabs, 1)
        hsv.addWidget(hybrid_signature_result, 1)
        self.pages.addTab(hybrid_signing, "④ 后量子混合签名")

        self.material_views = {}
        self.message_inputs = {}
        self._form_splitters = []
        for index, (operation, button) in enumerate((
                ("kem", self.btn_kem), ("hybrid", self.btn_hybrid),
                ("sign", self.btn_sign), ("hybrid_sign", self.btn_hybrid_sign))):
            view = _DemoMaterialsView()
            self.material_views[operation] = view
            result_tabs = self._calculation_widgets(operation)[1]
            result_tabs.addTab(view, "输出数据")
            result_tabs.setCurrentWidget(view)
            page_layout = self.pages.widget(index).layout()
            result_box = page_layout.takeAt(page_layout.count() - 1).widget()
            result_box.setTitle("输出与验证结果")
            actions = QHBoxLayout()
            actions.addWidget(button)
            actions.addStretch(1)
            result_box.layout().insertLayout(0, actions)
            splitter = QSplitter(Qt.Orientation.Vertical)
            splitter.addWidget(view.keys_box)
            message_box = _DemoMessageBox(operation)
            self.message_inputs[operation] = message_box
            message_box.changed.connect(lambda op=operation: self._message_changed(op))
            splitter.addWidget(message_box)
            splitter.addWidget(result_box)
            splitter.setStretchFactor(2, 1)
            splitter.setSizes([190, 130, 350])
            page_layout.addWidget(splitter, 1)
            self._form_splitters.append(splitter)
        self._parameter_combos = (
            self.standalone_kem_combo, self.kem_combo, self.classical_combo,
            self.signature_combo, self.hybrid_classical_signature_combo,
            self.hybrid_pq_signature_combo)
        for combo, operation in zip(self._parameter_combos,
                                    ("kem", "hybrid", "hybrid", "sign", "hybrid_sign", "hybrid_sign")):
            combo.currentTextChanged.connect(
                lambda _text, op=operation: self._clear_result(op, "参数已修改，请重新运行"))

        if include_replay:
            self._add_replay_page()
        self.pages.currentChanged.connect(self._sync_message_visibility)
        self._sync_message_visibility(self.pages.currentIndex())

    def _add_replay_page(self):
        replay = QWidget()
        rv = QVBoxLayout(replay)
        replay_hint = QLabel("选择前面深度检测生成的同次连接材料，或导入抓包证据 JSON；可在下方补充客户端临时私钥、流量密钥和期望明文。复算不会生成替代数据。")
        replay_hint.setWordWrap(True)
        rv.addWidget(replay_hint)
        replay_controls = QHBoxLayout()
        replay_controls.addWidget(QLabel("会话"))
        self.replay_session_combo = QComboBox()
        replay_controls.addWidget(self.replay_session_combo, 1)
        self.btn_refresh_replay = QPushButton("刷新会话")
        self.btn_refresh_replay.clicked.connect(self.refresh_replay_sessions)
        replay_controls.addWidget(self.btn_refresh_replay)
        self.btn_open_replay = QPushButton("导入证据包")
        self.btn_open_replay.clicked.connect(self.open_replay_bundle)
        replay_controls.addWidget(self.btn_open_replay)
        self.btn_replay = QPushButton("执行实际连接复算")
        self.btn_replay.setObjectName("primary")
        self.btn_replay.clicked.connect(self.run_selected_replay)
        replay_controls.addWidget(self.btn_replay)
        rv.addLayout(replay_controls)
        self.replay_bundle_edit = QPlainTextEdit()
        self.replay_bundle_edit.setPlaceholderText("选择会话后自动填充；也可粘贴证据包 JSON 并补充必要秘密。")
        rv.addWidget(self.replay_bundle_edit, 1)
        self.replay_status = QLabel("等待实际连接材料")
        self.replay_status.setWordWrap(True)
        rv.addWidget(self.replay_status)
        self.replay_result_tabs = QTabWidget()
        self.replay_output = QTextEdit()
        self.replay_output.setReadOnly(True)
        self.replay_result_tabs.addTab(self.replay_output, "过程与结论")
        self.replay_input_view = QPlainTextEdit()
        self.replay_input_view.setReadOnly(True)
        self.replay_result_tabs.addTab(self.replay_input_view, "实际输入")
        self.replay_result_json = QPlainTextEdit()
        self.replay_result_json.setReadOnly(True)
        self.replay_result_tabs.addTab(self.replay_result_json, "完整输出 JSON")
        rv.addWidget(self.replay_result_tabs, 2)
        self.pages.addTab(replay, "⑤ 实际连接复算")
        self.replay_session_combo.currentIndexChanged.connect(self._load_selected_replay_bundle)

    def showEvent(self, event):
        super().showEvent(event)
        if self._capture_provider is not None:
            self.import_captured_parameters()
        if self._include_replay:
            self.refresh_replay_sessions()

    def refresh_replay_sessions(self):
        self.replay_session_combo.blockSignals(True)
        self.replay_session_combo.clear()
        self._replay_sessions = []
        try:
            reports = []
            if self._session_provider is not None:
                supplied = self._session_provider() or []
                reports = supplied if isinstance(supplied, list) else [supplied]
            elif self._capture_provider is not None:
                reports = [self._capture_provider() or {}]
            for report in reports:
                if not isinstance(report, dict):
                    continue
                bundle = (report.get("deep") or {}).get("replay_bundle")
                if not bundle:
                    continue
                label = "%s:%s · %s" % (report.get("host") or "目标", report.get("port") or "",
                                        bundle.get("key_exchange", {}).get("algorithm", "未知算法"))
                self._replay_sessions.append(bundle)
                self.replay_session_combo.addItem(label)
        except Exception as exc:
            self._set_replay_status("读取检测会话失败：%s" % exc, False)
        finally:
            self.replay_session_combo.blockSignals(False)
        if self.replay_session_combo.count():
            self.replay_session_combo.setCurrentIndex(0)
            self._load_selected_replay_bundle(0)
        else:
            self.replay_bundle_edit.setPlainText("")
            self._set_replay_status("没有可复算的深度检测会话；请先完成深度检测，或导入包含必要秘密的证据包。", None)

    def _load_selected_replay_bundle(self, index):
        if not 0 <= index < len(self._replay_sessions):
            return
        self.replay_bundle_edit.setPlainText(
            json.dumps(self._replay_sessions[index], ensure_ascii=False, indent=2))
        self._set_replay_status("已载入同次连接材料；可补充缺失秘密后执行复算。", None)

    def open_replay_bundle(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择实际连接证据包", "", "JSON (*.json);;所有文件 (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                bundle = pqc_replay.load_bundle(handle.read())
            self.replay_bundle_edit.setPlainText(json.dumps(bundle, ensure_ascii=False, indent=2))
            self.replay_session_combo.blockSignals(True)
            self.replay_session_combo.setCurrentIndex(-1)
            self.replay_session_combo.blockSignals(False)
            self._set_replay_status("已导入证据包：%s" % path, None)
        except Exception as exc:
            self._set_replay_status("导入证据包失败：%s" % exc, False)

    def _set_replay_status(self, message, success):
        color = "#166534" if success else "#b91c1c" if success is False else "#475569"
        background = "#dcfce7" if success else "#fee2e2" if success is False else "#e2e8f0"
        self.replay_status.setText(message)
        self.replay_status.setStyleSheet(
            "QLabel { color: %s; background: %s; padding: 8px 12px; border-radius: 6px; font-weight: 600; }"
            % (color, background))

    def run_selected_replay(self):
        source = self.replay_bundle_edit.toPlainText()
        self.replay_output.clear()
        self.replay_input_view.setPlainText(source)
        self.replay_result_json.clear()
        try:
            result = pqc_replay.run_replay(source)
        except ReplayInputError as exc:
            self.replay_output.setPlainText("证据包不可用：%s" % exc)
            self._set_replay_status("证据包不可用", False)
            return
        except Exception as exc:
            self.replay_output.setPlainText("复算失败：%s: %s" % (type(exc).__name__, exc))
            self._set_replay_status("复算失败", False)
            return
        self.replay_result_json.setPlainText(json.dumps(result, ensure_ascii=False, indent=2))
        self._render_replay_result(result)

    def _render_replay_result(self, result):
        lines = ["实际连接复算 · " + result["message"]]
        lines += ["", "① Certificate 列表严格解析（叶子优先）"]
        for cert in result["certificates"]:
            lines.append("%s / %s：SPKI OID %s，公钥 %d 字节，SHA-256 %s" % (
                cert["position"], cert["subject"], cert["spki_algorithm_oid"],
                cert["spki_public_key_bytes"], cert["spki_public_key_sha256"]))
            lines.append("证书签名：%s（OID %s，%d 字节）；证书指纹：%s" % (
                cert["signature_algorithm"], cert["signature_algorithm_oid"],
                cert["signature_bytes"], cert["certificate_sha256"]))
        exchange = result["key_exchange"]
        lines += ["", "② 密钥封装 / 交换复算：" + exchange["message"]]
        lines.append("算法：%s；服务器材料 %d 字节；计算秘密 SHA-256：%s" % (
            exchange.get("algorithm", "—"), exchange.get("server_material_bytes", 0),
            exchange.get("computed_shared_secret_sha256", "—")))
        lines.append("计算共享秘密（Base64）：%s" % exchange.get("computed_shared_secret_base64", "—"))
        lines.append("记录秘密 SHA-256：%s；一致性：%s" % (
            exchange.get("expected_shared_secret_sha256", "—"),
            "一致" if exchange.get("shared_secret_matches") else "不一致"))
        signature = result["handshake_signature"]
        lines += ["", "③ 握手签名验签：" + signature["message"]]
        lines.append("方案：%s（%s）；签名 %s 字节；叶子 SPKI SHA-256：%s" % (
            signature.get("scheme", "—"), signature.get("scheme_name", "—"),
            signature.get("signature_bytes", 0), signature.get("leaf_spki_public_key_sha256", "—")))
        lines += ["", "④ 加密报文认证解密"]
        if not result["encrypted_records"]:
            lines.append("未提供加密报文或流量密钥。")
        for record in result["encrypted_records"]:
            lines.append("记录 %d：%s；密文 %d 字节；明文 %d 字节；%s" % (
                record["index"] + 1, record.get("algorithm", "—"),
                record.get("ciphertext_bytes", 0), record.get("plaintext_bytes", 0),
                record["message"]))
        if result["missing"]:
            lines += ["", "缺少必要参数：" + "、".join(result["missing"])]
        lines += ["", "一致性结论：" + result["message"]]
        self._render_report(self.replay_output, lines)
        self._set_replay_status(
            "复算完成 · " + result["message"], result["conclusion"] == "verified")

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
        if demo_kind == "hybrid":
            self.message_encoding.setCurrentText("UTF-8")
            self.message_edit.setPlainText(summary)
        self._captured_brief = "来源：%s · %s" % (report.get("host", "检测目标"), demo_name)
        self.capture_status.setText("已导入 %s，可运行对应演示。" % self._captured_brief)
        return True

    def _sync_message_visibility(self, index):
        if 0 <= index < len(self._form_splitters):
            self.main_splitter = self._form_splitters[index]
            operation = ("kem", "hybrid", "sign", "hybrid_sign")[index]
            self.message_box = self.message_inputs[operation]
            self.message_edit = self.message_box.edit
            self.message_encoding = self.message_box.encoding_combo
            self.message_info = self.message_box.info
            self.btn_message_file = self.message_box.btn_file

    def _message_changed(self, operation):
        self._clear_result(operation, "输入已修改，请重新运行")

    def load_message_file(self, path):
        self.message_box.load_file(path)

    def _output_widget(self, operation):
        return {"kem": self.kem_output, "hybrid": self.hybrid_output,
                "sign": self.signature_output,
                "hybrid_sign": self.hybrid_signature_output}[operation]

    def _clear_result(self, operation, reason="等待运行"):
        self._output_widget(operation).clear()
        view, tabs = self._calculation_widgets(operation)
        view.clear()
        tabs.setCurrentWidget(self.material_views[operation])
        self.material_views[operation].clear()
        self._set_status(operation, reason, None)

    def _calculation_widgets(self, operation):
        return {"kem": (self.kem_trace_view, self.kem_result_tabs),
                "hybrid": (self.hybrid_trace_view, self.hybrid_result_tabs),
                "sign": (self.signature_trace_view, self.signature_result_tabs),
                "hybrid_sign": (self.hybrid_signature_trace_view,
                                self.hybrid_signature_result_tabs)}[operation]

    def _start(self, operation):
        if self._worker is not None and self._worker.isRunning():
            return
        self._clear_result(operation)
        output = self._output_widget(operation)
        try:
            message = self.message_inputs[operation].message_bytes()
        except ValueError as exc:
            output.setPlainText(str(exc))
            self._calculation_widgets(operation)[1].setCurrentIndex(0)
            self._set_status(operation, "输入错误", False)
            return
        if operation != "kem" and len(message) > 4096:
            output.setPlainText("输入消息解码后超过 4096 字节；请缩短后重试。")
            self._calculation_widgets(operation)[1].setCurrentIndex(0)
            self._set_status(operation, "输入过长", False)
            return
        algorithm = {"kem": self.standalone_kem_combo.currentText(),
                     "hybrid": self.kem_combo.currentText(),
                     "sign": self.signature_combo.currentText(),
                     "hybrid_sign": self.hybrid_pq_signature_combo.currentText()}[operation]
        output.setPlainText("正在执行真实密码运算…")
        self._set_status(operation, "运行中…", None)
        self.btn_kem.setEnabled(False)
        self.btn_hybrid.setEnabled(False)
        self.btn_sign.setEnabled(False)
        self.btn_hybrid_sign.setEnabled(False)
        self._set_inputs_enabled(False)
        classical_algorithm = (self.hybrid_classical_signature_combo.currentText()
                               if operation == "hybrid_sign" else self.classical_combo.currentText())
        worker = _DemoWorker(operation, message, algorithm,
                             classical_algorithm, self,
                             message_encoding=self.message_inputs[operation].encoding_combo.currentText())
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
        self._output_widget(operation).setPlainText("运行失败：" + error)
        self._calculation_widgets(operation)[1].setCurrentIndex(0)
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

    def _set_inputs_enabled(self, enabled):
        for widget in (*self.message_inputs.values(), *self._parameter_combos):
            widget.setEnabled(enabled)
        self.btn_import_capture.setEnabled(enabled and self._capture_provider is not None)

    def _finished(self):
        self.btn_kem.setEnabled(True)
        self.btn_hybrid.setEnabled(True)
        self.btn_sign.setEnabled(True)
        self.btn_hybrid_sign.setEnabled(True)
        self._set_inputs_enabled(True)
        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None

    def _show_result(self, operation, data):
        view, tabs = self._calculation_widgets(operation)
        view.set_trace(data["calculation_trace"])
        materials = self.material_views[operation]
        materials.set_materials(data["materials"], data.get("input_encoding", ""))
        tabs.setCurrentWidget(materials)
        if operation == "kem":
            success = (data["shared_secret_matches"] and
                       data["changed_ciphertext_changes_secret"])
            self._set_status(operation, "验证通过 · 双方得到相同的共享秘密" if success else "验证未通过", success)
            self._render_report(self.kem_output, [
                "算法：%s（纯后量子密钥封装）" % data["algorithm"],
                self._captured_brief,
                "① 接收方生成密钥对",
                "   公钥：%d 字节；完整公私钥见上方临时密钥区" % data["public_key_bytes"],
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
                "双方 ECDHE 秘密一致：%s" % ("是" if data["ecdh_shared_secret_matches"] else "否"),
                "双方 KEM 秘密一致：%s" % ("是" if data["kem_shared_secret_matches"] else "否"),
                "② HKDF 派生密钥，AES-GCM 加密后解密",
                "解密结果：%s" % self._display_message(data["recovered"]),
                "③ 修改密文并验证认证标签",
                "篡改检测：%s" % ("已拒绝" if data["tamper_rejected"] else "未拒绝"),
            ]
            self._render_report(self.hybrid_output, lines)
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

    @staticmethod
    def _display_message(message):
        try:
            return message.decode("utf-8")
        except UnicodeDecodeError:
            return "HEX：" + message.hex()


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
