"""Expandable calculation viewer shared by KEM and signature demonstrations."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QTextOption
from PySide6.QtWidgets import (
    QLabel, QPlainTextEdit, QSplitter, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)


def _format_value(name, value, indent=""):
    if isinstance(value, bytes):
        lines = [f"{indent}{name}（{len(value)} 字节，十六进制）"]
        lines += [f"{indent}  [{i:04d}] " + value[i:i + 16].hex(" ")
                  for i in range(0, len(value), 16)]
        return "\n".join(lines)
    if isinstance(value, dict):
        return f"{indent}{name}：\n" + "\n".join(
            _format_value(str(key), item, indent + "  ") for key, item in value.items())
    if isinstance(value, (list, tuple)):
        lines = [f"{indent}{name}（{len(value)} 项；索引从 0 开始）"]
        if all(isinstance(item, (int, bool)) for item in value):
            lines += [f"{indent}  [{i}..{min(i + 15, len(value) - 1)}] "
                      + ", ".join(str(x) for x in value[i:i + 16])
                      for i in range(0, len(value), 16)]
        else:
            lines += [_format_value(f"[{i}]", item, indent + "  ") for i, item in enumerate(value)]
        return "\n".join(lines)
    if isinstance(value, bool):
        value = "是 / True" if value else "否 / False"
    return f"{indent}{name} = {value}"


class CalculationTraceView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._entries = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        hint = QLabel("左侧选择步骤或变量，右侧查看公式、实际数值与计算示例。矩阵、多项式及字节均完整显示；拖动分隔条调整宽度。")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("计算步骤 / 变量")
        self.tree.setMinimumWidth(150)
        self.tree.setUniformRowHeights(True)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.splitter.addWidget(self.tree)
        self.splitter.addWidget(self.detail)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 2)
        self.splitter.setSizes([280, 560])
        layout.addWidget(self.splitter, 1)
        self.tree.currentItemChanged.connect(self._select)
        self.clear()

    def clear(self):
        self.tree.clear()
        self._entries.clear()
        self.detail.setPlainText("运行演示后，在这里查看本次算法的参数、实际数值与计算过程。")

    def _item(self, parent, title, entry):
        item = QTreeWidgetItem(parent, [title])
        index = len(self._entries)
        self._entries.append(entry)
        item.setData(0, Qt.ItemDataRole.UserRole, index)
        return item

    def _variables(self, parent, values):
        context = self._entries[parent.data(0, Qt.ItemDataRole.UserRole)]
        for name, value in values.items():
            count = f"（{len(value)} {'字节' if isinstance(value, bytes) else '项'}）" if isinstance(value, (bytes, list, tuple, dict)) else ""
            entry = {key: context[key] for key in ("formula", "reference", "example") if key in context}
            entry.update(title=context["title"] + " / " + name, values={name: value})
            item = self._item(parent, name + count, entry)
            if isinstance(value, dict):
                self._variables(item, value)
            elif isinstance(value, (list, tuple)) and value and isinstance(value[0], (list, tuple)):
                self._variables(item, {f"[{i}]": row for i, row in enumerate(value)})

    def _steps(self, parent, steps):
        for index, entry in enumerate(steps, 1):
            item = self._item(parent, f"{index}. {entry['title']}", entry)
            self._steps(item, entry.get("children", []))
            self._variables(item, entry["values"])

    def set_trace(self, trace):
        self.clear()
        parameters = self._item(self.tree, "参数总览 · " + trace["algorithm"], {
            "title": trace["algorithm"] + " 参数总览",
            "formula": trace.get("parameter_description", "n：多项式系数数目；q：模数；k：模块维数；η₁/η₂：噪声采样参数；du/dv：密文压缩位数。\n所有多项式均有 256 个系数；负数用模 q 剩余类表示（例如 −1 = 3328）。"),
            "reference": trace.get("parameter_reference", "FIPS 203，表 2；" + trace["source"]),
            "values": trace["parameters"],
            "example": trace.get("parameter_note", "这些值是本次计算的真实输入和中间量。教学实现用于逐步展示，不是恒定时间的生产密码实现；每次运行使用临时密钥，界面不会自动保存这些数据。"),
        })
        self._variables(parameters, trace["parameters"])
        self._steps(self.tree, trace["steps"])
        self.tree.setCurrentItem(parameters)

    def _select(self, item, previous=None):
        if item is None:
            return
        entry = self._entries[item.data(0, Qt.ItemDataRole.UserRole)]
        sections = [entry["title"]]
        if entry.get("formula"):
            sections.append("公式 / 运算规则\n" + entry["formula"])
        if entry.get("reference"):
            sections.append("依据\n" + entry["reference"])
        if entry.get("example"):
            sections.append("计算示例 / 说明\n" + entry["example"])
        sections.append("实际输入与输出\n" + "\n\n".join(
            _format_value(name, value) for name, value in entry["values"].items()))
        self.detail.setPlainText("\n\n".join(sections))


MlkemTraceView = CalculationTraceView  # Backwards-compatible existing import.
