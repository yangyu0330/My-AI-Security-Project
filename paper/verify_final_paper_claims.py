"""Reproduce the local numeric claims in 범죄와정책_최종논문_검증반영.md.

Run from the repository root:

    python paper/verify_final_paper_claims.py

The script uses only Python's standard library and performs no network calls or
file writes. It exits non-zero if a headline value differs from the manuscript.
"""

from __future__ import annotations

import ast
import json
import math
import re
import statistics
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

    print(json.dumps(summary, ensure_ascii=False, indent=2, default=dict))
    print("\nALL ASSERTIONS PASSED")


if __name__ == "__main__":
    main()
