#!/usr/bin/env python3
"""Validate two isolated review forms and calculate inter-rater agreement."""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any


PAPER_DIR = Path(__file__).resolve().parent
DEFAULT_PACKET = PAPER_DIR / "overblocking_review_packet_77.json"
DEFAULT_A = PAPER_DIR / "과잉차단_검토자_A_독립판정표.md"
DEFAULT_B = PAPER_DIR / "과잉차단_검토자_B_독립판정표.md"
LABELS = ("FP", "TP", "U")
ROW_RE = re.compile(
    r"^\|\s*((?:law|service)-[^| ]+)\s*\|\s*([^|]*)\|\s*([^|]*)\|\s*$"
)
ADJUDICATION_ROW_RE = re.compile(
    r"^\|\s*((?:law|service)-[^| ]+)\s*\|\s*(FP|TP|U)\s*\|\s*"
    r"(FP|TP|U)\s*\|\s*([^|]*)\|\s*([^|]*)\|\s*$",
    re.IGNORECASE,
)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def sha256_text(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_packet(path: Path) -> dict[str, Any]:
    packet = json.loads(path.read_text(encoding="utf-8"))
    cases = packet["cases"]
    if sha256_text(canonical_json(cases)) != packet["case_set_sha256"]:
        raise ValueError("evidence packet case_set_sha256 mismatch")
    if len(cases) != 77 or len({row["case_id"] for row in cases}) != 77:
        raise ValueError("evidence packet must contain 77 unique cases")
    return packet


def parse_form(path: Path, expected_hash: str) -> dict[str, dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    if f"`{expected_hash}`" not in text:
        raise ValueError(f"{path.name}: case-set hash missing or stale")
    rows: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        match = ROW_RE.match(line)
        if not match:
            continue
        case_id, decision, rationale = (part.strip() for part in match.groups())
        if case_id in rows:
            raise ValueError(f"{path.name}: duplicate case ID {case_id}")
        decision = decision.upper()
        if decision and decision not in LABELS:
            raise ValueError(
                f"{path.name}: {case_id} decision must be FP, TP, U, or blank"
            )
        if decision and not rationale:
            raise ValueError(f"{path.name}: {case_id} decision requires rationale")
        if rationale and not decision:
            raise ValueError(f"{path.name}: {case_id} rationale has no decision")
        rows[case_id] = {"decision": decision, "rationale": rationale}
    return rows


def kappa(pairs: list[tuple[str, str]]) -> float | None:
    if not pairs:
        return None
    n = len(pairs)
    observed = sum(a == b for a, b in pairs) / n
    count_a = Counter(a for a, _ in pairs)
    count_b = Counter(b for _, b in pairs)
    expected = sum((count_a[label] / n) * (count_b[label] / n) for label in LABELS)
    if math.isclose(expected, 1.0):
        return None
    return (observed - expected) / (1.0 - expected)


def summarize(
    packet: dict[str, Any],
    form_a: dict[str, dict[str, str]],
    form_b: dict[str, dict[str, str]],
) -> dict[str, Any]:
    case_ids = [row["case_id"] for row in packet["cases"]]
    expected = set(case_ids)
    for label, form in (("A", form_a), ("B", form_b)):
        missing_rows = expected - set(form)
        extra_rows = set(form) - expected
        if missing_rows or extra_rows:
            raise ValueError(
                f"reviewer {label} row set mismatch: "
                f"missing={len(missing_rows)}, extra={len(extra_rows)}"
            )

    complete_a = [case_id for case_id in case_ids if form_a[case_id]["decision"]]
    complete_b = [case_id for case_id in case_ids if form_b[case_id]["decision"]]
    paired_ids = [
        case_id
        for case_id in case_ids
        if form_a[case_id]["decision"] and form_b[case_id]["decision"]
    ]
    pairs = [
        (form_a[case_id]["decision"], form_b[case_id]["decision"])
        for case_id in paired_ids
    ]
    agreements = [case_id for case_id, (a, b) in zip(paired_ids, pairs) if a == b]
    disagreements = [
        {
            "case_id": case_id,
            "reviewer_A": a,
            "reviewer_B": b,
        }
        for case_id, (a, b) in zip(paired_ids, pairs)
        if a != b
    ]
    return {
        "status": (
            "READY_FOR_ADJUDICATION"
            if len(complete_a) == len(complete_b) == 77
            else "INCOMPLETE_INDEPENDENT_REVIEW"
        ),
        "case_set_sha256": packet["case_set_sha256"],
        "total_cases": 77,
        "reviewer_A_completed": len(complete_a),
        "reviewer_B_completed": len(complete_b),
        "paired_completed": len(paired_ids),
        "reviewer_A_distribution": Counter(
            form_a[case_id]["decision"] for case_id in complete_a
        ),
        "reviewer_B_distribution": Counter(
            form_b[case_id]["decision"] for case_id in complete_b
        ),
        "agreements": len(agreements),
        "simple_agreement": (
            len(agreements) / len(paired_ids) if paired_ids else None
        ),
        "cohen_kappa": kappa(pairs),
        "kappa_note": (
            "not computable when expected agreement is 1 or no paired decisions exist"
            if kappa(pairs) is None
            else None
        ),
        "disagreement_count": len(disagreements),
        "disagreements": disagreements,
    }


def make_adjudication_form(summary: dict[str, Any]) -> str:
    if summary["status"] != "READY_FOR_ADJUDICATION":
        raise ValueError("both reviewers must complete all 77 cases first")
    lines = [
        "# 과잉차단 후보 독립판정 불일치 조정표",
        "",
        f"- 사례 집합 SHA-256: `{summary['case_set_sha256']}`",
        f"- 독립판정 단순 일치율: {summary['simple_agreement']:.6f}",
        f"- 독립판정 Cohen's κ: {summary['cohen_kappa']}",
        f"- 불일치 사례: {summary['disagreement_count']}건",
        "",
        "합의 판정은 `FP`, `TP`, `U` 중 하나만 입력하고 합의 근거를 반드시 기록한다.",
        "",
        "| Case ID | 검토자 A | 검토자 B | 합의(FP/TP/U) | 합의 근거 |",
        "|---|---|---|---|---|",
    ]
    lines.extend(
        f"| {row['case_id']} | {row['reviewer_A']} | {row['reviewer_B']} |  |  |"
        for row in summary["disagreements"]
    )
    lines.extend(
        [
            "",
            "## 조정 확인",
            "",
            "- 조정자:",
            "- 조정 완료일:",
            "- 공식 원문과 두 독립 판정 근거를 재확인했음: [ ]",
        ]
    )
    return "\n".join(lines) + "\n"


def parse_adjudication(
    path: Path,
    expected_hash: str,
    disagreements: list[dict[str, str]],
) -> dict[str, dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    if f"`{expected_hash}`" not in text:
        raise ValueError(f"{path.name}: case-set hash missing or stale")
    rows: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        match = ADJUDICATION_ROW_RE.match(line)
        if not match:
            continue
        case_id, reviewer_a, reviewer_b, consensus, rationale = (
            part.strip() for part in match.groups()
        )
        consensus = consensus.upper()
        if not consensus:
            continue
        if consensus not in LABELS:
            raise ValueError(f"{path.name}: {case_id} invalid consensus")
        if not rationale:
            raise ValueError(f"{path.name}: {case_id} consensus requires rationale")
        rows[case_id] = {
            "reviewer_A": reviewer_a.upper(),
            "reviewer_B": reviewer_b.upper(),
            "consensus": consensus,
            "rationale": rationale,
        }

    expected = {row["case_id"]: row for row in disagreements}
    if set(rows) != set(expected):
        raise ValueError(
            f"{path.name}: adjudication row set mismatch "
            f"(expected {len(expected)}, completed {len(rows)})"
        )
    for case_id, row in rows.items():
        source = expected[case_id]
        if (
            row["reviewer_A"] != source["reviewer_A"]
            or row["reviewer_B"] != source["reviewer_B"]
        ):
            raise ValueError(f"{path.name}: {case_id} reviewer decisions changed")
    return rows


def finalize_summary(
    summary: dict[str, Any],
    form_a: dict[str, dict[str, str]],
    adjudication: dict[str, dict[str, str]],
) -> dict[str, Any]:
    consensus: dict[str, str] = {}
    disagreement_ids = {row["case_id"] for row in summary["disagreements"]}
    for case_id, row in form_a.items():
        if case_id not in disagreement_ids:
            consensus[case_id] = row["decision"]
    consensus.update(
        {case_id: row["consensus"] for case_id, row in adjudication.items()}
    )
    if len(consensus) != 77:
        raise ValueError("final consensus must contain all 77 cases")
    output = dict(summary)
    output["status"] = "FINALIZED_AFTER_ADJUDICATION"
    output["consensus_distribution"] = Counter(consensus.values())
    output["consensus_by_case"] = consensus
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", type=Path, default=DEFAULT_PACKET)
    parser.add_argument("--reviewer-a", type=Path, default=DEFAULT_A)
    parser.add_argument("--reviewer-b", type=Path, default=DEFAULT_B)
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="exit non-zero unless both reviewers completed all 77 cases",
    )
    parser.add_argument(
        "--emit-adjudication",
        type=Path,
        help="after complete independent reviews, write a form for disagreements",
    )
    parser.add_argument(
        "--adjudication",
        type=Path,
        help="validate a completed disagreement form and report final consensus",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        help="also write the validated JSON summary to this path",
    )
    args = parser.parse_args()

    packet = load_packet(args.packet)
    form_a = parse_form(args.reviewer_a, packet["case_set_sha256"])
    form_b = parse_form(args.reviewer_b, packet["case_set_sha256"])
    summary = summarize(packet, form_a, form_b)
    if args.emit_adjudication:
        content = make_adjudication_form(summary)
        args.emit_adjudication.write_text(content, encoding="utf-8", newline="\n")
    if args.adjudication:
        if summary["status"] != "READY_FOR_ADJUDICATION":
            raise ValueError("independent reviews are not complete")
        adjudication = parse_adjudication(
            args.adjudication,
            packet["case_set_sha256"],
            summary["disagreements"],
        )
        summary = finalize_summary(summary, form_a, adjudication)
    rendered = json.dumps(summary, ensure_ascii=False, indent=2, default=dict) + "\n"
    print(rendered, end="")
    if args.summary_output:
        args.summary_output.write_text(rendered, encoding="utf-8", newline="\n")
    if args.require_complete and summary["status"] not in {
        "READY_FOR_ADJUDICATION",
        "FINALIZED_AFTER_ADJUDICATION",
    }:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
