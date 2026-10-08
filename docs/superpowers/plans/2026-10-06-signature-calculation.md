# Signature Calculation Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline; checkbox steps track completion.

**Goal:** Show real parameters and calculations for every existing standalone/hybrid signature selection.

**Architecture:** Signature generation remains native. Family-specific replay modules decode and calculate actual signature intermediates, sharing the existing Trace records and Qt viewer. Public signing APIs keep public-only output.

**Tech Stack:** Python 3.9+, hashlib, cryptography, pqcrypto 0.3.0, PySide6, pytest.

**Spec:** `docs/superpowers/specs/2026-10-06-signature-calculation-design.md`

## Constraints and review focus

- No new dependencies or changes to TLS/signature generation protocols. Existing APIs and worker lifecycle preserved.
- Explicitly distinguish native unavailable randomness, reconstructed signing values, and direct verification arithmetic.
- SPHINCS+ backend message framing and bit/address ordering must match actual native output, not claim final-FIPS external encoding.
- Keep public `sign_hybrid_message` outputs free of private traces; large classical integers must cross Qt signals safely.
- Complete coefficients/hash paths remain selectable; clear old results on failure/oversized input; detail headers must match family.
- Checkout has no Git metadata; existing files backed up under `/tmp/crypto-analysis-tool-signature-trace.*`.

## Task 1: Family replay arithmetic

Create `modules/ml_dsa_trace.py`, `modules/slh_dsa_trace.py`, `modules/falcon_trace.py`, `modules/classical_signature_trace.py`, with focused independent and native interoperability tests in `tests/test_signature_trace.py`.

Interfaces: each `parameters(algorithm)` returns dict; each `calculate(algorithm,message,public,signature,trace,secret=None)` appends real Trace steps and returns verified bool. Classical calculate receives cryptography private key for educational signing reconstruction. Family modules expose verifier helpers used by replay tests.

- [x] Write failing tests for all PQ parameter sets, native valid/changed-message signatures, malformed encodings, independent NTT/ring math and RFC Ed25519 vector.
- [x] Observe expected missing feature failures.
- [x] Implement full family replay with real inputs/outputs, parameter differences and unavailable-value disclosures.
- [x] Verify all family tests and existing project suite.

## Task 2: Demo integration and common viewer

Modify `modules/pqc_demo.py`, `modules/mlkem_trace_ui.py`, `modules/pqc_demo_ui.py`; test `tests/test_pqc_demo.py`, `tests/test_hybrid_signature.py`, `tests/test_pqc_demo_ui.py`.

Interfaces: `calculation_trace` uses algorithm/parameters/source/steps plus optional parameter_description/reference/note. General `CalculationTraceView` keeps `MlkemTraceView` alias for existing consumers. Demo signature traces include native operation inputs and checks, hybrid length-prefix binding and both family traces.

- [x] Write failing output consistency, public-only API and UI signature variable/reset tests.
- [x] Integrate actual-run traces, AND checks and both signature result tabs.
- [x] Generalize headers while preserving all ML-KEM behavior.
- [x] Verify core/UI tests, complete integer signal transfer and prior regression suite.

## Task 3: Documentation and final validation

- [x] Update README and project documentation with coverage, reconstruction/unknown limits and primary citations.
- [x] Run `python -m pytest -q`, visually inspect both signature views and request one fresh independent read-only review.
- [x] Fix material findings with regression evidence; record final checks here.

## Verification ledger

- Task 1: failing missing-feature tests observed; all 24 arithmetic/native replay tests passed, covering all 17 PQ variants, all 5 classical variants, independent ring convolution and RFC 8032 example.
- Task 2: missing calculation_trace failures observed; 11 focused integration/UI checks passed.
- Full regression suite before final independent review: `python -m pytest -q` → 180 passed in 21.61 s.
- Reviewer dispatched on the completed feature; no implementation agents used.

- Final independent review: no Critical, Important or Minor findings; ready for teaching scope. Reviewer ran 109 focused tests and 168 native/replay differential cases without mismatches.
- Visual validation: actual ML-DSA, SLH WOTS+ and ECDSA-P384 hybrid displays inspected; full variable context and large integer transfer worked.
- Review scope: native randomness/rejections, constant-time production hardening and certification remain outside these teaching traces. The Ed25519 replay helper rejects crafted small-order public keys more strictly than the native verifier; generated demo keys are unaffected, and public hybrid verification stays unchanged.
- Final state: no code changes after the 180-pass full suite; documentation and implementation checklist complete.
