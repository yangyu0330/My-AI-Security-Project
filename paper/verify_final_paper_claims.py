"""Reproduce the local numeric claims in 범죄와정책_최종논문_검증반영.md.

Run from the repository root:

    python paper/verify_final_paper_claims.py

The script uses only Python's standard library and performs no network calls or
file writes. It exits non-zero if a headline value differs from the manuscript.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import re
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "PII" / "results" / "data"

L0 = "korean-layer0"
L4 = "gpt4o-pii-judge"
BASE3 = {"Presidio PII", "Bedrock Guardrail", "Lakera"}
CONFIGS = {
    "A": ("eval_10k_l1l3.json", BASE3),
    "B": ("eval_10k_l1l4_full.json", BASE3 | {L4}),
    "C": ("eval_10k_l0_l1l3.json", BASE3 | {L0}),
    "D": ("eval_10k_l0_l1l4_full.json", BASE3 | {L0, L4}),
}


def load_results(filename: str) -> list[dict]:
    with (DATA_DIR / filename).open(encoding="utf-8") as handle:
        return json.load(handle)["results"]


def load_payloads(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)["payloads"]


def present_final(pii_value: str, text: str) -> bool:
    """Matcher used by run_e_final_4way.py."""
    if not pii_value or not text:
        return False
    if pii_value in text:
        return True
    pii_digits = re.sub(r"\D", "", pii_value)
    text_digits = re.sub(r"\D", "", text)
    return len(pii_digits) >= 6 and pii_digits in text_digits


def present_enhanced(pii_value: str, text: str) -> bool:
    """Additional normalization used by analyze_true_detection.py."""
    if not pii_value or not text:
        return False
    if pii_value in text:
        return True
    pii_digits = re.sub(r"\D", "", pii_value)
    text_digits = re.sub(r"\D", "", text)
    if len(pii_digits) >= 6 and pii_digits in text_digits:
        return True
    fullwidth = {chr(0xFF10 + i): str(i) for i in range(10)}
    normalized = "".join(fullwidth.get(char, char) for char in text)
    if pii_value in normalized:
        return True
    normalized_digits = re.sub(r"\D", "", normalized)
    if len(pii_digits) >= 6 and pii_digits in normalized_digits:
        return True
    circled = {chr(0x2460 + i): str(i + 1) for i in range(9)}
    circled["⓪"] = "0"
    normalized = "".join(circled.get(char, char) for char in text)
    normalized_digits = re.sub(r"\D", "", normalized)
    return len(pii_digits) >= 6 and pii_digits in normalized_digits


def classify(case: dict, layers: set[str], matcher=present_final) -> str:
    pii_value = case.get("pii_value", "") or case.get("original", "") or ""
    mutated = case.get("mutated", "")
    any_true = False
    any_false = False
    for layer_result in case.get("layer_results", []):
        if layer_result.get("layer") not in layers:
            continue
        if layer_result.get("error") or layer_result.get("action") == "ERROR":
            continue
        output = layer_result.get("output", "")
        if output == mutated or output == "":
            continue
        if output == "[BLOCKED]":
            any_true = True
        elif matcher(pii_value, output):
            any_false = True
        else:
            any_true = True
    if any_true:
        return "TRUE"
    if any_false:
        return "FALSE"
    return "BYPASS"


def classify_exact(case: dict, layers: set[str]) -> str:
    """Classify cases whose original PII is literally present after mutation."""
    pii_value = case["pii_value"]
    mutated = case["mutated"]
    any_true = False
    any_false = False
    for layer_result in case.get("layer_results", []):
        if layer_result.get("layer") not in layers:
            continue
        if layer_result.get("error") or layer_result.get("action") == "ERROR":
            continue
        output = layer_result.get("output", "")
        if output == mutated or output == "":
            continue
        if output == "[BLOCKED]":
            any_true = True
        elif pii_value in output:
            any_false = True
        else:
            any_true = True
    if any_true:
        return "TRUE"
    if any_false:
        return "FALSE"
    return "BYPASS"


def classify_analyzer(case: dict) -> str:
    """Case aggregation implemented by analyze_true_detection.py."""
    pii_value = case.get("pii_value", "") or ""
    mutated = case.get("mutated", "")
    classifications: list[str] = []
    for layer_result in case.get("layer_results", []):
        output = layer_result.get("output", "")
        if output == mutated or output == "":
            classifications.append("NO_CHANGE")
        elif output == "[BLOCKED]":
            classifications.append("TRUE")
        elif present_enhanced(pii_value, output):
            classifications.append("FALSE")
        else:
            classifications.append("TRUE")
    if "TRUE" in classifications:
        return "TRUE"
    if "FALSE" in classifications:
        return "FALSE"
    return "BYPASS"


VIN_VALUES = {
    **{str(number): number for number in range(10)},
    **dict(zip("ABCDEFGH", range(1, 9))),
    **dict(zip("JKLMNPR", (1, 2, 3, 4, 5, 7, 9))),
    **dict(zip("STUVWXYZ", (2, 3, 4, 5, 6, 7, 8, 9))),
}
VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def valid_vin_check_digit(vin: str) -> bool:
    if len(vin) != 17 or any(char not in VIN_VALUES for char in vin):
        return False
    remainder = sum(
        VIN_VALUES[char] * weight for char, weight in zip(vin, VIN_WEIGHTS)
    ) % 11
    expected = "X" if remainder == 10 else str(remainder)
    return vin[8] == expected


def percentile(values: list[int], probability: float) -> int:
    ordered = sorted(values)
    index = max(0, math.ceil(probability * len(ordered)) - 1)
    return ordered[index]


def count_detector_dicts(path: Path) -> dict[str, int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    counts: dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Dict):
            continue
        for target in node.targets:
            if isinstance(target, ast.Attribute) and target.attr in {
                "regex_patterns",
                "keyword_dict",
            }:
                counts[target.attr] = len(node.value.keys)
    return counts


def main() -> None:
    payloads = load_payloads(DATA_DIR / "payloads_10k.json")
    results = {
        name: load_results(filename) for name, (filename, _) in CONFIGS.items()
    }
    indexed = {
        name: {case["id"]: case for case in cases} for name, cases in results.items()
    }

    summary: dict[str, object] = {
        "dataset": {
            "payloads": len(payloads),
            "pii_types": len({row["pii_type"] for row in payloads}),
            "mutation_names": len({row["mutation_name"] for row in payloads}),
            "languages": Counter(row["lang"] for row in payloads),
            "exact_original_absent": sum(
                row["original"] not in row["mutated"] for row in payloads
            ),
            "untrackable_by_final_matcher": sum(
                not present_final(row["original"], row["mutated"]) for row in payloads
            ),
        }
    }

    exact_ids = [
        case_id
        for case_id, case in indexed["A"].items()
        if case.get("pii_value")
        and case["pii_value"] in case.get("mutated", "")
        and case_id in indexed["C"]
    ]
    exact_pairs = Counter()
    level_stats: dict[int, dict[str, int]] = defaultdict(
        lambda: {"n": 0, "a_blocked": 0, "c_blocked": 0, "c_only": 0}
    )
    layer0_actions = Counter()
    for case_id in exact_ids:
        a_case = indexed["A"][case_id]
        c_case = indexed["C"][case_id]
        a_blocked = classify_exact(a_case, BASE3) == "TRUE"
        c_blocked = classify_exact(c_case, BASE3 | {L0}) == "TRUE"
        exact_pairs[(a_blocked, c_blocked)] += 1
        level = int(a_case["mutation_level"])
        level_stats[level]["n"] += 1
        level_stats[level]["a_blocked"] += int(a_blocked)
        level_stats[level]["c_blocked"] += int(c_blocked)
        level_stats[level]["c_only"] += int(not a_blocked and c_blocked)
        if not a_blocked and c_blocked:
            for layer_result in c_case["layer_results"]:
                if layer_result.get("layer") == L0:
                    layer0_actions[
                        (
                            layer_result.get("action"),
                            layer_result.get("output"),
                        )
                    ] += 1

    original_ids = [
        case_id for case_id in exact_ids if indexed["A"][case_id]["mutation_level"] == 0
    ]
    mutated_ids = [
        case_id for case_id in exact_ids if indexed["A"][case_id]["mutation_level"] > 0
    ]

    def unblocked(case_ids: list[str], configuration: str, layers: set[str]) -> int:
        return sum(
            classify_exact(indexed[configuration][case_id], layers) != "TRUE"
            for case_id in case_ids
        )

    summary["conservative_exact_subset"] = {
        "n": len(exact_ids),
        "A_blocked": sum(
            classify_exact(indexed["A"][case_id], BASE3) == "TRUE"
            for case_id in exact_ids
        ),
        "A_unblocked": unblocked(exact_ids, "A", BASE3),
        "C_blocked": sum(
            classify_exact(indexed["C"][case_id], BASE3 | {L0}) == "TRUE"
            for case_id in exact_ids
        ),
        "C_unblocked": unblocked(exact_ids, "C", BASE3 | {L0}),
        "paired": {
            "both_blocked": exact_pairs[(True, True)],
            "A_only": exact_pairs[(True, False)],
            "C_only": exact_pairs[(False, True)],
            "neither": exact_pairs[(False, False)],
        },
        "layer0_actions_for_C_only": {
            f"{action}:{output}": count
            for (action, output), count in layer0_actions.items()
        },
        "original": {
            "n": len(original_ids),
            "A_unblocked": unblocked(original_ids, "A", BASE3),
            "C_unblocked": unblocked(original_ids, "C", BASE3 | {L0}),
        },
        "mutated": {
            "n": len(mutated_ids),
            "A_unblocked": unblocked(mutated_ids, "A", BASE3),
            "C_unblocked": unblocked(mutated_ids, "C", BASE3 | {L0}),
        },
        "by_level": dict(sorted(level_stats.items())),
    }

    evaluator_counts: dict[str, dict[str, int]] = {}
    for configuration, (_, layers) in CONFIGS.items():
        evaluator_counts[configuration] = {
            "final": sum(
                classify(case, layers, present_final) == "TRUE"
                for case in results[configuration]
            ),
            "enhanced": sum(
                classify_analyzer(case) == "TRUE"
                for case in results[configuration]
            ),
        }
    summary["evaluator_true_counts"] = evaluator_counts

    vins = [row["original"] for row in payloads if row["pii_type"] == "vin"]
    summary["vin"] = {
        "rows": len(vins),
        "unique": len(set(vins)),
        "check_digit_pass": sum(valid_vin_check_digit(vin) for vin in vins),
    }

    latency_values: dict[str, list[int]] = {L0: [], L4: []}
    for configuration, layer_name in (("C", L0), ("B", L4)):
        for case in results[configuration]:
            for layer_result in case["layer_results"]:
                if (
                    layer_result.get("layer") == layer_name
                    and isinstance(layer_result.get("latency_ms"), (int, float))
                ):
                    latency_values[layer_name].append(layer_result["latency_ms"])
    summary["latency_ms"] = {
        layer: {
            "n": len(values),
            "mean": statistics.fmean(values),
            "median": statistics.median(values),
            "p99": percentile(values, 0.99),
            "min": min(values),
            "max": max(values),
        }
        for layer, values in latency_values.items()
    }
    summary["latency_ms"]["L4_to_L0_mean_ratio"] = (
        summary["latency_ms"][L4]["mean"] / summary["latency_ms"][L0]["mean"]
    )

    evaluation_payloads = load_payloads(ROOT / "PII" / "evaluation" / "payloads_10k.json")
    summary["same_name_payload_files"] = {
        "PII/results/data/payloads_10k.json": len(payloads),
        "PII/evaluation/payloads_10k.json": len(evaluation_payloads),
    }
    summary["required_corpora_present"] = {
        "tagged_korean_names.jsonl": (
            ROOT / "PII" / "fuzzer" / "data" / "tagged_korean_names.jsonl"
        ).exists(),
        "tagged_korean_addresses.jsonl": (
            ROOT / "PII" / "fuzzer" / "data" / "tagged_korean_addresses.jsonl"
        ).exists(),
    }
    summary["layer0_detector"] = count_detector_dicts(
        ROOT / "PII" / "layer_0" / "korean_pii_detector.py"
    )

    expected = {
        "dataset": {
            "payloads": 10000,
            "pii_types": 95,
            "mutation_names": 36,
            "exact_original_absent": 5287,
            "untrackable_by_final_matcher": 2647,
        },
        "exact": {
            "n": 4713,
            "A_unblocked": 1063,
            "C_unblocked": 64,
            "C_only": 999,
            "A_only": 0,
            "original_n": 1246,
            "original_A_unblocked": 89,
            "mutated_n": 3467,
            "mutated_A_unblocked": 974,
            "mutated_C_unblocked": 57,
        },
        "evaluator": {
            "A": (8015, 7901),
            "B": (9096, 9067),
            "C": (9432, 9373),
            "D": (9723, 9711),
        },
        "vin": (72, 10, 0),
        "payload_files": (10000, 3538),
        "detector": (45, 22),
    }

    for key, value in expected["dataset"].items():
        assert summary["dataset"][key] == value, (key, summary["dataset"][key], value)
    exact = summary["conservative_exact_subset"]
    assert exact["n"] == expected["exact"]["n"]
    assert exact["A_unblocked"] == expected["exact"]["A_unblocked"]
    assert exact["C_unblocked"] == expected["exact"]["C_unblocked"]
    assert exact["paired"]["C_only"] == expected["exact"]["C_only"]
    assert exact["paired"]["A_only"] == expected["exact"]["A_only"]
    assert exact["original"]["n"] == expected["exact"]["original_n"]
    assert (
        exact["original"]["A_unblocked"]
        == expected["exact"]["original_A_unblocked"]
    )
    assert exact["mutated"]["n"] == expected["exact"]["mutated_n"]
    assert (
        exact["mutated"]["A_unblocked"] == expected["exact"]["mutated_A_unblocked"]
    )
    assert (
        exact["mutated"]["C_unblocked"] == expected["exact"]["mutated_C_unblocked"]
    )
    assert exact["layer0_actions_for_C_only"] == {"BLOCK:[BLOCKED]": 999}
    for configuration, values in expected["evaluator"].items():
        assert (
            summary["evaluator_true_counts"][configuration]["final"],
            summary["evaluator_true_counts"][configuration]["enhanced"],
        ) == values
    assert (
        summary["vin"]["rows"],
        summary["vin"]["unique"],
        summary["vin"]["check_digit_pass"],
    ) == expected["vin"]
    assert tuple(summary["same_name_payload_files"].values()) == expected["payload_files"]
    assert (
        summary["layer0_detector"]["regex_patterns"],
        summary["layer0_detector"]["keyword_dict"],
    ) == expected["detector"]

    postmutation_process = subprocess.run(
        [sys.executable, str(ROOT / "paper" / "analyze_postmutation_gold.py")],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    postmutation = json.loads(postmutation_process.stdout)
    assert postmutation["gold_recovery"]["recovered"] == 9964
    assert postmutation["postmutation_gold_performance"]["A"]["unblocked"] == 2060
    assert postmutation["postmutation_gold_performance"]["C"]["unblocked"] == 706
    assert postmutation["configuration_pairs"]["C_only"] == 1354
    assert postmutation["configuration_pairs"]["A_only"] == 0
    assert (
        postmutation["configuration_pairs"]["C_only_with_direct_layer0_block"]
        == 1353
    )
    assert (
        postmutation["matched_original_mutation"]["korean"]["pairs"] == 2305
    )
    assert (
        postmutation["matched_original_mutation"]["target_changed"]["pairs"]
        == 2160
    )
    assert (
        postmutation["layer0_false_positive_audit"]["false_positive_documents"]
        == 0
    )

    public_law_audit = json.loads(
        (ROOT / "paper" / "public_law_hard_negative_audit.json").read_text(
            encoding="utf-8"
        )
    )
    assert public_law_audit["aggregate"] == {
        "documents": 1519,
        "flagged_documents": 29,
        "flagged_document_rate": 29 / 1519,
        "finding_types": {"dept": 18, "nationality": 11},
    }
    assert public_law_audit["explicit_hard_negative_fixture_audit"][
        "flagged_documents"
    ] == 1
    assert public_law_audit["ai_basic_act_article_effective_dates"] == {
        article: "20260122" for article in ("31", "33", "34", "35", "43")
    }

    public_service_audit = json.loads(
        (
            ROOT / "paper" / "public_service_hard_negative_audit.json"
        ).read_text(encoding="utf-8")
    )
    assert public_service_audit["corpus_sha256"] == (
        "151fb6488a3e934dd467612e680bcae7319120a4acb50147b521d03bf31c3d3e"
    )
    assert len(public_service_audit["sources"]) == 21
    assert len({source["id"] for source in public_service_audit["sources"]}) == 21
    assert {
        source["domain"] for source in public_service_audit["sources"]
    } == {"medical", "finance", "support", "developer"}
    assert public_service_audit["domains"] == {
        "medical": {
            "documents": 265,
            "flagged_documents": 44,
            "flagged_document_rate": 44 / 265,
            "finding_types": {
                "allergy": 1,
                "course_grade": 1,
                "diagnosis": 41,
                "mental": 7,
                "prescription": 4,
            },
            "duplicate_units_removed": 0,
        },
        "finance": {
            "documents": 29,
            "flagged_documents": 0,
            "flagged_document_rate": 0.0,
            "finding_types": {},
            "duplicate_units_removed": 0,
        },
        "support": {
            "documents": 144,
            "flagged_documents": 0,
            "flagged_document_rate": 0.0,
            "finding_types": {},
            "duplicate_units_removed": 5,
        },
        "developer": {
            "documents": 255,
            "flagged_documents": 4,
            "flagged_document_rate": 4 / 255,
            "finding_types": {"course_grade": 4},
            "duplicate_units_removed": 0,
        },
    }
    assert public_service_audit["aggregate"] == {
        "documents": 693,
        "flagged_documents": 48,
        "flagged_document_rate": 48 / 693,
        "finding_types": {
            "allergy": 1,
            "course_grade": 5,
            "diagnosis": 41,
            "mental": 7,
            "prescription": 4,
        },
        "globally_unique_documents": 693,
    }

    review_packet = json.loads(
        (ROOT / "paper" / "overblocking_review_packet_77.json").read_text(
            encoding="utf-8"
        )
    )
    review_cases = review_packet["cases"]
    canonical_cases = json.dumps(
        review_cases,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert hashlib.sha256(canonical_cases.encode("utf-8")).hexdigest() == (
        review_packet["case_set_sha256"]
    )
    assert review_packet["counts"] == {
        "total": 77,
        "law": 29,
        "service": 48,
        "medical": 44,
        "developer": 4,
    }
    assert len(review_cases) == 77
    assert len({case["case_id"] for case in review_cases}) == 77
    assert Counter(case["corpus"] for case in review_cases) == {
        "law": 29,
        "service": 48,
    }
    assert Counter(case["domain"] for case in review_cases) == {
        "public_law": 29,
        "medical": 44,
        "developer": 4,
    }
    for case in review_cases:
        assert case["official_url"].startswith("https://")
        assert hashlib.sha256(
            case["official_public_text"].encode("utf-8")
        ).hexdigest() == case["text_sha256"]
        assert case["finding_types"]
        assert case["reason_codes"]
    review_form_pattern = re.compile(
        r"(?m)^\|\s*((?:law|service)-[^| ]+)\s*\|\s*[^|]*\|\s*[^|]*\|\s*$"
    )
    for form_name in (
        "과잉차단_검토자_A_독립판정표.md",
        "과잉차단_검토자_B_독립판정표.md",
    ):
        form_text = (ROOT / "paper" / form_name).read_text(encoding="utf-8")
        assert f"`{review_packet['case_set_sha256']}`" in form_text
        form_ids = review_form_pattern.findall(form_text)
        assert len(form_ids) == 77
        assert set(form_ids) == {case["case_id"] for case in review_cases}

    manuscript = (
        ROOT / "paper" / "범죄와정책_최종논문_검증반영.md"
    ).read_text(encoding="utf-8")
    required_manuscript_claims = (
        "# 생성형 AI의 한국어 개인식별정보(PII) 유출 위험과 정규화 기반 Layer 0의 필요성",
        "Korean Personally Identifiable Information Leakage Risks in Generative AI",
        "9,964건(99.64%)",
        "2,060건(20.67%)",
        "706건(7.09%)",
        "1,354건",
        "2,305쌍",
        "9.12%에서 18.75%",
        "필요하지만 충분하지 않은",
        "한국어를 “Optimized and supported”",
        "A Lifestyle-Routine Activity Theory (LRAT) Approach to Cybercrime Victimization: An Empirical Assessment of SNS Lifestyle Exposure Activities",
        "블라데미르 T. 콩고·여승준·최진혁",
        "대통령령 제36340호",
        "presidio.dataprivacystack.org/supported_entities/",
        "1,519개 중 29개(1.91%)",
        "조문별 시행일은 국가법령정보센터 공식 XML에서 모두 2026년 1월 22일",
        "693개 중 48개(6.93%)",
        "의료 265개 중 44개(16.60%)",
        "개발문서 255개 중 4개(1.57%)",
        "금융 29개와 AWS 지원문서 144개에서는 탐지가 없었다",
        "서비스도메인_오탐_2인독립검토표.md",
        "## 목 차",
        "# ABSTRACT",
    )
    for claim in required_manuscript_claims:
        assert claim in manuscript, claim
    forbidden_primary_claims = (
        "변이 사례의 미차단율은 원형보다 3.93배",
        "기존 계층이 놓친 999건",
        "2026년 7월 21일 시행된 「인공지능 발전과 신뢰 기반 조성 등에 관한 기본법」",
        "2026. 7. 21. 시행.",
        "# 생성형 AI의 한국어 민감정보 유출 위험과 정규화 기반 Layer 0의 필요성",
        "Korean Sensitive-Information Leakage Risks in Generative AI",
        "서비스 도메인의 자연발생 hard negative가 여전히 필요하다",
    )
    for claim in forbidden_primary_claims:
        assert claim not in manuscript, claim
    manuscript_order = (
        "## 국문초록",
        "## 목 차",
        "# I. 서론",
        "# 참고문헌",
        "# ABSTRACT",
    )
    manuscript_positions = [manuscript.index(marker) for marker in manuscript_order]
    assert manuscript_positions == sorted(manuscript_positions)
    korean_abstract = re.search(
        r"## 국문초록\s+(.+?)\s+\*\*주제어:",
        manuscript,
        flags=re.DOTALL,
    ).group(1).strip()
    english_abstract = re.search(
        r"# ABSTRACT\s+## .+?\s+(.+?)\s+\*\*Key Words:",
        manuscript,
        flags=re.DOTALL,
    ).group(1).strip()
    assert 550 <= len(korean_abstract) <= 800
    assert 1000 <= len(english_abstract) <= 1600
    table_numbers = re.findall(r"\*\*<표 ([1-9])>[^*]+\*\*", manuscript)
    assert table_numbers == [str(number) for number in range(1, 10)]
    assert manuscript.count("\n자료:") == 9

    submission_record = (
        ROOT / "paper" / "범죄와정책_공식투고규격_원문검증기록.md"
    ).read_text(encoding="utf-8")
    required_submission_record_claims = (
        "https://ksoc.re.kr/범죄와-정책-소개",
        "https://ksoc.re.kr/편집규정",
        "https://ksoc.re.kr/온라인-투고-시스템",
        "ea0838598796954c438af84da87719abb0fdf68949c74b4bddac74336097c0a0",
        "4fd3e6a3b01efc9413948fc3c354aca1e95df7020451631e9fb070d9d514bfeb",
        "b1948be27639b35a70b8f2a7a7eee6183277a6a5e3d291f2c16e08879211ee81",
        "공백 포함 644자",
        "공백 포함 1,239자",
        "Microsoft Word 계산 20쪽",
        "주민등록번호",
        "팀 검토 단계에서는 HWP를 만들지 않는다",
    )
    for claim in required_submission_record_claims:
        assert claim in submission_record, claim

    citation_audit = json.loads(
        (ROOT / "paper" / "citation_source_audit.json").read_text(
            encoding="utf-8"
        )
    )
    academic_sources = citation_audit["sources"]
    assert len(academic_sources) == 13
    assert len({source["id"] for source in academic_sources}) == 13
    assert {source["id"] for source in academic_sources} == {
        *(f"K{number}" for number in range(1, 6)),
        *(f"F{number}" for number in range(1, 9)),
    }
    manuscript_body, reference_list = manuscript.split("# 참고문헌", 1)
    for source in academic_sources:
        assert source["citation_marker"] in manuscript_body, source["id"]
        assert source["reference_marker"] in reference_list, source["id"]
        assert source["record"].startswith("https://"), source["id"]
    dois = [
        source["doi"] for source in academic_sources if source["doi"] is not None
    ]
    assert len(dois) == len(set(dois)) == 9
    assert citation_audit["result"] == {
        "academic_references": 13,
        "korean": 5,
        "international": 8,
        "unique_ids": 13,
        "all_have_primary_or_authoritative_records": True,
        "all_have_in_text_citation_markers": True,
        "all_have_reference_list_markers": True,
    }

    print(json.dumps(summary, ensure_ascii=False, indent=2, default=dict))
    print(
        "\nLEGACY, POST-MUTATION, LAW, SERVICE-DOMAIN, 77-CASE "
        "REVIEW-PACKET, AND 13-SOURCE CITATION ASSERTIONS PASSED"
    )


if __name__ == "__main__":
    main()
