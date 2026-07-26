#!/usr/bin/env python3
"""Reproduce and classify the manuscript-relevant local test result."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "paper" / "code_test_audit.json"

SUITES = (
    {
        "id": "layer0",
        "paths": ("PII/layer_0/tests",),
        "expected": {"passed": 89, "failed": 0, "returncode": 0},
    },
    {
        "id": "fuzzer",
        "paths": (
            "PII/fuzzer/test_account_generation.py",
            "PII/fuzzer/test_address_generation.py",
            "PII/fuzzer/test_medical_record_generation.py",
            "PII/fuzzer/test_name_generation.py",
            "PII/fuzzer/test_prescription_generation.py",
            "PII/fuzzer/test_transaction_generation.py",
        ),
        "expected": {"passed": 34, "failed": 8, "returncode": 1},
    },
    {
        "id": "v0_2_contract",
        "paths": ("korean_pii_guardrail_v0_2/tests",),
        "expected": {"passed": 3, "failed": 0, "returncode": 0},
    },
)

EXPECTED_FUZZER_FAILURES = {
    "PII/fuzzer/test_account_generation.py"
    "::AccountGenerationTests"
    "::test_output_fuzzer_emits_account_korean_mutations",
    "PII/fuzzer/test_account_generation.py"
    "::AccountGenerationTests"
    "::test_single_pii_fuzzer_emits_account_korean_mutations",
    "PII/fuzzer/test_medical_record_generation.py"
    "::MedicalRecordGenerationTests"
    "::test_input_fuzzer_emits_medical_record_korean_mutations",
    "PII/fuzzer/test_medical_record_generation.py"
    "::MedicalRecordGenerationTests"
    "::test_output_fuzzer_emits_medical_record_korean_mutations",
    "PII/fuzzer/test_prescription_generation.py"
    "::PrescriptionGenerationTests"
    "::test_input_fuzzer_prescription_payloads_are_marked_valid",
    "PII/fuzzer/test_prescription_generation.py"
    "::PrescriptionGenerationTests"
    "::test_output_fuzzer_prescription_payloads_are_marked_valid",
    "PII/fuzzer/test_transaction_generation.py"
    "::TransactionGenerationTests"
    "::test_input_fuzzer_emits_transaction_korean_mutations",
    "PII/fuzzer/test_transaction_generation.py"
    "::TransactionGenerationTests"
    "::test_output_fuzzer_emits_transaction_korean_mutations",
}

HASHED_INPUTS = (
    "PII/layer_0/korean_normalizer.py",
    "PII/layer_0/korean_pii_detector.py",
    "PII/layer_0/tests/test_detector.py",
    "PII/layer_0/tests/test_normalizer.py",
    "PII/fuzzer/korean_pii_fuzzer_v4.py",
    "PII/fuzzer/korean_pii_output_fuzzer_v4.py",
    "PII/fuzzer/test_account_generation.py",
    "PII/fuzzer/test_address_generation.py",
    "PII/fuzzer/test_medical_record_generation.py",
    "PII/fuzzer/test_name_generation.py",
    "PII/fuzzer/test_prescription_generation.py",
    "PII/fuzzer/test_transaction_generation.py",
    "korean_pii_guardrail_v0_2/pyproject.toml",
    "korean_pii_guardrail_v0_2/tests/test_contract_smoke.py",
    "paper/validation-requirements.txt",
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_counts(output: str) -> tuple[int, int]:
    passed_matches = re.findall(r"(\d+) passed", output)
    failed_matches = re.findall(r"(\d+) failed", output)
    passed = int(passed_matches[-1]) if passed_matches else 0
    failed = int(failed_matches[-1]) if failed_matches else 0
    return passed, failed


def run_suite(
    suite: dict[str, Any], base_temp: Path
) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--tb=no",
        "--basetemp",
        str(base_temp / suite["id"]),
        *suite["paths"],
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    output = completed.stdout + completed.stderr
    passed, failed = parse_counts(output)
    failure_nodeids = sorted(
        match.group(1).strip()
        for match in re.finditer(r"^FAILED\s+(.+?)\s*$", output, re.MULTILINE)
    )
    actual = {
        "passed": passed,
        "failed": failed,
        "returncode": completed.returncode,
    }
    if actual != suite["expected"]:
        raise AssertionError((suite["id"], actual, suite["expected"], output))
    if suite["id"] == "fuzzer":
        if set(failure_nodeids) != EXPECTED_FUZZER_FAILURES:
            raise AssertionError((failure_nodeids, EXPECTED_FUZZER_FAILURES))
    elif failure_nodeids:
        raise AssertionError((suite["id"], failure_nodeids))
    return {
        "id": suite["id"],
        "paths": list(suite["paths"]),
        **actual,
        "failure_nodeids": failure_nodeids,
    }


def build_snapshot(audit_date: str) -> dict[str, Any]:
    version_probe = subprocess.run(
        [sys.executable, "-m", "pytest", "--version"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    pytest_version = version_probe.stdout.strip()
    with tempfile.TemporaryDirectory(prefix="paper-code-test-audit-") as temp:
        base_temp = Path(temp)
        suites = [run_suite(suite, base_temp) for suite in SUITES]

    totals = {
        "passed": sum(row["passed"] for row in suites),
        "failed": sum(row["failed"] for row in suites),
        "tests": sum(row["passed"] + row["failed"] for row in suites),
    }
    if totals != {"passed": 126, "failed": 8, "tests": 134}:
        raise AssertionError(totals)

    required_corpora = {
        "PII/fuzzer/data/tagged_korean_names.jsonl": False,
        "PII/fuzzer/data/tagged_korean_addresses.jsonl": False,
    }
    for relative, expected_exists in required_corpora.items():
        if (ROOT / relative).exists() != expected_exists:
            raise AssertionError(relative)

    return {
        "schema_version": 1,
        "audit_date": audit_date,
        "environment": {
            "python": platform.python_version(),
            "pytest": pytest_version,
            "platform": platform.system(),
        },
        "input_sha256": {
            relative: sha256_file(ROOT / relative)
            for relative in HASHED_INPUTS
        },
        "suites": suites,
        "totals": totals,
        "required_corpora_present": required_corpora,
        "finding": {
            "state": "CORE_TESTS_PASS_FUZZER_CORPORA_MISSING",
            "core_layer0": "89/89 passed",
            "v0_2_contract": "3/3 passed",
            "fuzzer": "34 passed, 8 failed",
            "failure_classification": (
                "All eight failures stop at the required name-corpus guard "
                "because tagged_korean_names.jsonl is absent. The required "
                "address corpus is also absent and would block default "
                "evaluation after the name corpus is restored."
            ),
            "paper_impact": (
                "The result supports the manuscript's disclosed limitation "
                "that the original generation pipeline is not cleanly "
                "reproducible; it does not contradict the separately "
                "recalculated audit of stored outputs or the passing Layer 0 "
                "detector and normalizer tests."
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    if args.write:
        snapshot = build_snapshot(dt.date.today().isoformat())
        OUTPUT.write_text(
            json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        status = "written"
    else:
        baseline = json.loads(OUTPUT.read_text(encoding="utf-8"))
        snapshot = build_snapshot(baseline["audit_date"])
        if snapshot != baseline:
            raise SystemExit("CODE_TEST_AUDIT_VERIFY_FAILED: source changed")
        status = "verified"

    print(
        json.dumps(
            {
                "status": status,
                "audit_date": snapshot["audit_date"],
                **snapshot["totals"],
                **snapshot["finding"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
