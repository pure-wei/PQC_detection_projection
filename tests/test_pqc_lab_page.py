"""Execute the actual report renderer; synthetic evidence checks UI semantics only."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "pqc_lab" / "public" / "index.html"


@pytest.mark.parametrize("target,state", [
    ("127.0.0.1:8443", "passed"), ("127.0.0.1:9443", "passed"),
    ("127.0.0.1:65535", "passed"), ("127.0.0.1:0", "failed"),
    ("127.0.0.1:65536", "failed"), ("example.com:9443", "failed"),
])
def test_page_uses_validated_loopback_tls_port(target, state):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required to execute the laboratory report renderer")
    evidence = {
        "status": "passed", "generated_at": "2026-10-07T10:00:00Z", "target": target,
        "checks": [{"id": "synthetic", "label": "UI fixture", "passed": True, "detail": "UI fixture"}],
        "summary": {"finished_verified": True, "certificate_verify_verified": True,
                    "group_name": "X25519MLKEM768", "protocol": "TLS 1.3",
                    "certificate_algorithm": "ML-DSA-65"},
    }
    rendered = render_report(evidence)
    assert rendered["state"] == state
    if state == "passed":
        port = target.split(":")[1]
        assert rendered["endpoint"] == target
        assert rendered["address"] == "https://localhost:" + port + "/index.html"
        assert "--port " + port in rendered["command"]
        assert target in rendered["transport"]


def render_report(evidence):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required to execute the laboratory report renderer")
    script = PAGE.read_text(encoding="utf-8").split("<script>", 1)[1].split("</script>", 1)[0]
    script = script.rsplit("refreshReport();", 1)[0]
    # A small DOM boundary leaves all target validation and rendering to real page code.
    harness = r"""
const vm = require('vm');
const elements = {};
function element(id) {
  return elements[id] ||= {textContent: '', dataset: {}, classList: {add() {}},
    replaceChildren() {}, append() {}, addEventListener() {}};
}
const context = {document: {getElementById: element, createElement: () => element(Math.random()),
  querySelectorAll: () => []}, location: {protocol: 'http:'}, setTimeout, clearTimeout};
vm.createContext(context);
vm.runInContext(SCRIPT, context);
vm.runInContext('readReport(' + JSON.stringify(EVIDENCE) + ')', context);
process.stdout.write(JSON.stringify({state: element('statusPanel').dataset.state,
  address: element('httpsAddress').textContent, command: element('verifyCommand').textContent,
  endpoint: element('labTarget').textContent, transport: element('transportText').textContent,
  confidentiality: element('cipherSuite').textContent, signature: element('certAlgorithm').textContent,
  proof: element('certificateVerify').textContent, scope: element('trustDetails').textContent,
  root: element('rootArtifact').href}));
"""
    harness = "const SCRIPT = " + json.dumps(script) + "; const EVIDENCE = " + json.dumps(evidence) + ";\n" + harness
    result = subprocess.run([node, "-e", harness], text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize("fault", [None, "confidentiality", "signature", "classical", "protocol"])
def test_message_report_does_not_claim_tls_or_encryption(protocol, fault):
    evidence = {"status": "passed", "generated_at": "2026-10-07T10:00:00Z", "target": "127.0.0.1:9555",
        "profile": {"protocol": protocol, "group": "X25519MLKEM768", "signature": "Falcon-512",
                    "classical_signature": "Ed25519"},
        "checks": [{"id": name, "label": name, "detail": "UI fixture", "passed": True}
                   for name in ("message_exchange", "message_signature", "reject_replay")],
        "summary": {"protocol": protocol.upper(), "signature_algorithm": "Falcon-512",
                    "classical_signature_algorithm": "Ed25519", "message_signature_verified": True,
                    "pq_signature_verified": True, "classical_signature_verified": True,
                    "transport_confidentiality": False}}
    if fault == "confidentiality":
        evidence["summary"]["transport_confidentiality"] = True
    elif fault == "signature":
        evidence["summary"]["message_signature_verified"] = False
    elif fault == "classical":
        evidence["summary"]["classical_signature_verified"] = False
    elif fault == "protocol":
        evidence["summary"]["protocol"] = "TLS 1.3"
    rendered = render_report(evidence)
    assert rendered["state"] == ("failed" if fault else "passed")
    if not fault:
        assert rendered["address"] == protocol + "://127.0.0.1:9555"
        assert "明文" in rendered["confidentiality"]
        assert "Falcon-512" in rendered["signature"] and "Ed25519" in rendered["signature"]
        assert rendered["proof"] == "已验证"
        assert "固定公钥" in rendered["scope"]
        assert "--protocol " + protocol in rendered["command"]


def test_selected_tls_algorithms_and_certificate_link_follow_report():
    evidence = {"status": "passed", "generated_at": "2026-10-07T10:00:00Z", "target": "127.0.0.1:9555",
        "profile": {"protocol": "https", "group": "SecP384r1MLKEM1024", "signature": "ML-DSA-87",
                    "classical_signature": ""},
        "checks": [{"id": "https_get", "label": "HTTPS", "detail": "UI fixture", "passed": True}],
        "summary": {"protocol": "TLS 1.3", "group_name": "SecP384r1MLKEM1024（混合）",
                    "certificate_algorithm": "ML-DSA-87", "finished_verified": True,
                    "certificate_verify_verified": True}}
    rendered = render_report(evidence)
    assert rendered["state"] == "passed"
    assert rendered["signature"] == "ML-DSA-87"
    assert rendered["root"] == "./root.mldsa87.cert.pem"
