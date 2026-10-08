import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication
from main import PqcDetectTab


@pytest.mark.parametrize("port", ["0", "-1", "65536", "99999", "abc"])
def test_invalid_port_is_rejected_before_starting_a_worker(port):
    app = QApplication.instance() or QApplication([])
    page = PqcDetectTab()
    try:
        page.host_edit.setText("example.test")
        page.port_edit.setText(port)
        with pytest.raises(ValueError, match="端口"):
            page._target()
        assert page._worker is None
    finally:
        page.close()


def test_certificate_file_is_algorithm_evidence_without_a_verified_handshake(tmp_path):
    from test_pqc_authenticity import _pqc_cert

    app = QApplication.instance() or QApplication([])
    page = PqcDetectTab()
    path = tmp_path / "pqc.der"
    path.write_bytes(_pqc_cert())
    try:
        page._load_cert_file(str(path))
        assert page._report["cert"]["cert_is_pqc"] is True
        assert page._report["overall_state"] == "partial"
        assert page._report["verification_status"] == "unverified"
        assert "未验证" in page.verdict.text()
    finally:
        page.close()
