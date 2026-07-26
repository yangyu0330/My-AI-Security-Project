#!/usr/bin/env python3
"""Build immutable, human-reviewable packets for 77 Layer 0 findings.

The source text is public official prose. This script re-fetches it through the
two existing audit programs, verifies the live extraction against the committed
baselines, and then emits one evidence packet plus two decision-isolated forms.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


PAPER_DIR = Path(__file__).resolve().parent
LAW_BASELINE = PAPER_DIR / "public_law_hard_negative_audit.json"
SERVICE_BASELINE = PAPER_DIR / "public_service_hard_negative_audit.json"
PACKET_PATH = PAPER_DIR / "overblocking_review_packet_77.json"
REVIEWER_A_PATH = PAPER_DIR / "과잉차단_검토자_A_독립판정표.md"
REVIEWER_B_PATH = PAPER_DIR / "과잉차단_검토자_B_독립판정표.md"
INSTRUCTIONS_PATH = PAPER_DIR / "과잉차단_2인독립검토_실행안내.md"


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run_audit(script_name: str) -> dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        [sys.executable, str(PAPER_DIR / script_name), "--review"],
        cwd=PAPER_DIR.parent,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
    )
    return json.loads(completed.stdout)


def require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label} mismatch: {actual!r} != {expected!r}")


def verify_law(live: dict[str, Any], baseline: dict[str, Any]) -> None:
    require_equal(live["aggregate"], baseline["aggregate"], "law aggregate")
    require_equal(
        live["implementation_sha256"],
        baseline["implementation_sha256"],
        "law implementation",
    )
    require_equal(set(live["sources"]), set(baseline["sources"]), "law source IDs")
    fields = (
        "official_api_url",
        "title",
        "xml_sha256",
        "documents",
        "flagged_documents",
        "finding_types",
    )
    for source_id, expected in baseline["sources"].items():
        actual = live["sources"][source_id]
        for field in fields:
            require_equal(
                actual[field], expected[field], f"law {source_id} {field}"
            )
    require_equal(len(live["review_packet"]), 29, "law review count")


def verify_service(live: dict[str, Any], baseline: dict[str, Any]) -> None:
    require_equal(
        live["extraction"]["corpus_sha256"],
        baseline["corpus_sha256"],
        "service corpus hash",
    )
    require_equal(live["domains"], baseline["domains"], "service domains")
    require_equal(live["aggregate"], baseline["aggregate"], "service aggregate")
    require_equal(
        live["implementation_sha256"],
        baseline["implementation_sha256"],
        "service implementation",
    )
    expected_sources = {row["id"]: row for row in baseline["sources"]}
    actual_sources = {row["id"]: row for row in live["sources"]}
    require_equal(set(actual_sources), set(expected_sources), "service source IDs")
    fields = (
        "domain",
        "official_url",
        "eligible_text_sha256",
        "eligible_units",
    )
    for source_id, expected in expected_sources.items():
        actual = actual_sources[source_id]
        for field in fields:
            require_equal(
                actual[field], expected[field], f"service {source_id} {field}"
            )
    require_equal(len(live["review_packet"]), 48, "service review count")


def law_case(row: dict[str, Any]) -> dict[str, Any]:
    article = "전문" if not row["article_number"] else f"제{row['article_number']}조"
    if row["article_branch"]:
        article += f"의{row['article_branch']}"
    return {
        "case_id": row["case_id"],
        "corpus": "law",
        "domain": "public_law",
        "source_id": row["law_id"],
        "source_title": row["law_title"],
        "location": {
            "document_ordinal": row["document_ordinal"],
            "tag": row["tag"],
            "article": article,
            "article_title": row["article_title"],
        },
        "official_url": row["official_api_url"],
        "finding_types": row["finding_types"],
        "reason_codes": row["reason_codes"],
        "text_sha256": row["text_sha256"],
        "official_public_text": row["official_public_law_text"],
    }


def service_case(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": row["case_id"],
        "corpus": "service",
        "domain": row["domain"],
        "source_id": row["source_id"],
        "source_title": row["source_title"],
        "location": {"unit_ordinal": row["unit_ordinal"]},
        "official_url": row["official_url"],
        "finding_types": row["finding_types"],
        "reason_codes": row["reason_codes"],
        "text_sha256": row["text_sha256"],
        "official_public_text": row["official_public_text"],
    }


def make_packet() -> dict[str, Any]:
    law_live = run_audit("audit_public_law_hard_negatives.py")
    service_live = run_audit("audit_public_service_hard_negatives.py")
    law_baseline = load_json(LAW_BASELINE)
    service_baseline = load_json(SERVICE_BASELINE)
    verify_law(law_live, law_baseline)
    verify_service(service_live, service_baseline)

    cases = [law_case(row) for row in law_live["review_packet"]]
    cases.extend(service_case(row) for row in service_live["review_packet"])
    case_ids = [row["case_id"] for row in cases]
    require_equal(len(cases), 77, "combined review count")
    require_equal(len(set(case_ids)), 77, "unique combined case IDs")
    for row in cases:
        require_equal(
            sha256_text(row["official_public_text"]),
            row["text_sha256"],
            f"{row['case_id']} text hash",
        )

    case_set_sha256 = sha256_text(canonical_json(cases))
    return {
        "schema_version": 1,
        "generated_date": law_live["audit_date"],
        "status": "UNREVIEWED_CANDIDATES",
        "decision_labels": {
            "FP": "특정 개인에게 귀속되지 않는 공개 일반 문맥의 과잉차단",
            "TP": "식별 가능한 자연인에게 귀속되는 실제 개인정보의 적정 차단",
            "U": "주어진 문맥만으로 판정 불가",
        },
        "counts": {
            "total": 77,
            "law": 29,
            "service": 48,
            "medical": 44,
            "developer": 4,
        },
        "law_baseline_sha256": hashlib.sha256(LAW_BASELINE.read_bytes()).hexdigest(),
        "service_baseline_sha256": hashlib.sha256(
            SERVICE_BASELINE.read_bytes()
        ).hexdigest(),
        "case_set_sha256": case_set_sha256,
        "cases": cases,
    }


def reviewer_form(reviewer: str, packet: dict[str, Any]) -> str:
    lines = [
        f"# 과잉차단 후보 77건 — 검토자 {reviewer} 독립 판정표",
        "",
        f"- 증거 패킷: `overblocking_review_packet_77.json`",
        f"- 사례 집합 SHA-256: `{packet['case_set_sha256']}`",
        "- 허용 판정: `FP`, `TP`, `U`",
        "- 독립성 원칙: 상대 검토자의 파일을 열어보지 않은 상태에서 완성한다.",
        "- 원문 확인: 증거 패킷에서 동일 `case_id`의 공식 URL·원문·탐지근거를 확인한다.",
        "",
        "판정 칸에는 세 값 중 하나만 입력한다. 근거는 한 줄로 작성하고 `|` 문자는 쓰지 않는다.",
        "",
        "| Case ID | 판정(FP/TP/U) | 판정 근거 |",
        "|---|---|---|",
    ]
    lines.extend(f"| {row['case_id']} |  |  |" for row in packet["cases"])
    lines.extend(
        [
            "",
            "## 검토자 확인",
            "",
            "- 성명:",
            "- 소속/전문분야:",
            "- 독립 판정 완료일:",
            "- 상대 검토자의 판정을 보지 않고 완료했음: [ ]",
        ]
    )
    return "\n".join(lines) + "\n"


def instructions(packet: dict[str, Any]) -> str:
    return f"""# 과잉차단 후보 77건 2인 독립 검토 실행안내

## 목적

법령 29건과 서비스 문서 48건을 두 사람이 독립적으로 판정하고, 합의 전 자동 탐지값을 확정 오탐으로 과장하지 않기 위한 절차다.

## 고정 증거

- 증거 파일: `paper/overblocking_review_packet_77.json`
- 사례 집합 SHA-256: `{packet['case_set_sha256']}`
- 법령 후보: 29건
- 서비스 후보: 48건(의료 44건, 개발문서 4건)

각 사례에는 공식 URL, 정확한 공개 원문, 원문 SHA-256, 탐지 유형과 탐지 근거가 들어 있다. 생성 시 법령·서비스 감사의 저장 기준선과 실시간 공식 원문 추출 결과가 모두 일치해야 한다.

## 실행 순서

1. 담당자가 `python paper/build_overblocking_review_packets.py --verify`로 패킷 무결성을 확인한다.
2. 검토자 A에게 `과잉차단_검토자_A_독립판정표.md`만 배정한다.
3. 검토자 B에게 `과잉차단_검토자_B_독립판정표.md`만 배정한다.
4. 두 검토자는 상대 파일을 열지 않고 증거 패킷의 동일 사례 원문을 확인해 `FP`, `TP`, `U` 중 하나를 입력한다.
5. 두 파일이 모두 잠긴 뒤 담당자가 다음 명령을 실행한다.

```powershell
python paper/compile_overblocking_reviews.py
```

6. 두 파일이 모두 완성되면 아래 명령으로 독립판정의 단순 일치율·Cohen's κ와 불일치 조정표를 생성한다.

```powershell
python paper/compile_overblocking_reviews.py --require-complete --emit-adjudication paper/과잉차단_불일치조정표.md
```

7. 불일치 사례는 두 검토자가 원문을 함께 재확인하고 생성된 표에 합의 판정과 이유를 기록한다.
8. 다음 명령으로 합의 표를 검증하고 최종 JSON 집계를 만든다.

```powershell
python paper/compile_overblocking_reviews.py --require-complete --adjudication paper/과잉차단_불일치조정표.md --summary-output paper/과잉차단_2인검토_최종집계.json
```

9. 합의 결과가 완성되기 전까지 논문에는 “과잉차단 후보 77건”으로만 표현한다.

## 판정 경계

- `FP`: 특정 개인에게 귀속되지 않는 법령·공공교육·기술 예문을 PII로 차단
- `TP`: 식별 가능한 자연인에게 귀속되는 실제 개인정보를 차단
- `U`: 문맥 부족 또는 전문가 판단 필요

이 표본은 자동 탐지된 사례만 모은 조건부 목적표본이다. 합의 FP 비율이나 κ를 실제 서비스 전체 오탐률로 일반화하지 않는다.
"""


def expected_outputs() -> dict[Path, str]:
    packet = make_packet()
    return {
        PACKET_PATH: json.dumps(packet, ensure_ascii=False, indent=2) + "\n",
        REVIEWER_A_PATH: reviewer_form("A", packet),
        REVIEWER_B_PATH: reviewer_form("B", packet),
        INSTRUCTIONS_PATH: instructions(packet),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    outputs = expected_outputs()
    if args.write:
        for path, content in outputs.items():
            path.write_text(content, encoding="utf-8", newline="\n")
        print(
            json.dumps(
                {
                    "status": "written",
                    "files": [str(path) for path in outputs],
                    "case_set_sha256": json.loads(outputs[PACKET_PATH])[
                        "case_set_sha256"
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    mismatches = []
    for path, content in outputs.items():
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            mismatches.append(str(path))
    if mismatches:
        raise SystemExit("PACKET_VERIFY_FAILED: " + ", ".join(mismatches))
    packet = json.loads(outputs[PACKET_PATH])
    print(
        json.dumps(
            {
                "status": "verified",
                "files": len(outputs),
                "cases": packet["counts"]["total"],
                "case_set_sha256": packet["case_set_sha256"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
