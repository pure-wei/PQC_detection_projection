# ML-KEM Calculation Trace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Show the actual randomness, parameters and arithmetic used by the standalone and hybrid ML-KEM demonstrations.

**Architecture:** A pure Python teaching implementation emits hierarchical trace records. The existing native pqcrypto library verifies interoperability in both directions. A reusable Qt tree/details view consumes those records.

**Tech Stack:** Python 3.9+, hashlib, existing pqcrypto/cryptography/PySide6, pytest.

**Spec:** `docs/superpowers/specs/2026-10-06-mlkem-calculation-design.md`

## Global Constraints

- Scope: ML-KEM-512/768/1024 and the ML-KEM component of hybrid encryption.
- No new dependencies; no TLS or detection implementation changes.
- Random seeds and secrets are ephemeral teaching data, displayed in calculation details and never automatically persisted.
- Preserve existing demo return fields and input/worker lifecycle behavior.
- This checkout has no Git metadata; use local backups for review rather than commits/worktrees.

## Review Focus

- ML-KEM-512 uses η1=3; ML-KEM-1024 uses du=11/dv=5. Test all variants against independent official vectors.
- Matrix index ordering and inverse NTT scaling can yield internally consistent but incompatible results. Test native interoperability and independent convolution.
- Invalid public-key modulus, corrupt private-key hash and malformed ciphertext must fail input checks.
- Trace data must describe this run, not a separate native run; reconstruct output from its seeds and encoded polynomials.
- Large coefficient arrays must stay selectable/readable, and stale trace data must clear on retry/failure.

## Task 1: Traced ML-KEM arithmetic

**Files:** `modules/mlkem_trace.py`, `tests/test_mlkem_trace.py`, `tests/fixtures/mlkem_acvp_examples.json`.
**Produces:** `MLKEM(algorithm).keygen(d, z, trace=None) -> (ek, dk)`, `.encaps(ek, m, trace=None) -> (ciphertext, key)`, `.decaps(dk, ciphertext, trace=None) -> key`; `Trace.steps`; `run_calculation(algorithm, native) -> dict` with raw outputs and trace.

- [x] Add pinned official ACVP samples and failing arithmetic/interoperability/input/trace tests.
- [x] Run tests and confirm missing implementation failures.
- [x] Implement sampling, transforms, arithmetic, encoding and KEM with hierarchical snapshots.
- [x] Run Task 1 tests and confirm exact official/native output agreement.

## Task 2: Integrate both demonstrations

**Files:** `modules/pqc_demo.py`, `tests/test_pqc_demo.py`.
**Consumes:** Task 1 interfaces.
**Produces:** Existing result dictionaries plus `calculation_trace`; hybrid HKDF/AES data appended to its actual ML-KEM trace.

- [x] Add failing tests for trace/output consistency and hybrid derivation inputs.
- [x] Replace opaque ML-KEM demo calls with traced calculation and native cross-checks.
- [x] Run core demo tests, preserving prior behaviors.

## Task 3: Calculation viewer and documentation

**Files:** `modules/mlkem_trace_ui.py`, `modules/pqc_demo_ui.py`, `tests/test_pqc_demo_ui.py`, `README.md`, `项目说明文档.md`.
**Consumes:** `calculation_trace` with hierarchical steps, named values, formula, example and reference.
**Produces:** Selectable steps/variables with full coefficients and actual values in standalone and hybrid result tabs.

- [x] Add failing UI tests for real runs, variable selection, full values, reset and validation failure.
- [x] Implement the viewer, result tabs and updated teaching-data labels.
- [x] Update established documentation and source links.
- [x] Run `python -m pytest -q`; visually inspect both pages; request one independent code review and fix material findings.

## Verification evidence

- Arithmetic, demos, GUI and existing project regression suite: `python -m pytest -q` → **145 passed**.
- Independent review verified pinned source SHA-256/fixture provenance and all 75 encapsulation plus 30 decapsulation examples in the source. No arithmetic discrepancies.
- Offscreen previews inspected standalone parameters/randomness/NTT and hybrid HKDF; full coefficients remain selectable.
- Review identified missing formula/source context when selecting a variable. Added a failing direct-selection regression assertion, inherited the producing step context, then reran the suite.
- No new dependencies; existing TLS/detection and signature algorithms unchanged.
