"""Audit Layer 0 false positives on official Korean statutory text.

The stored ``normal_kr_10k.json`` set deliberately omits direct PII-like
patterns.  This audit adds an independently sourced lexical hard-negative set:
current statutory provisions from the Ministry of Government Legislation's
official LAW OPEN DATA XML service.

Only provision text is evaluated.  Administrative metadata, department contact
numbers, appendices, amendment reasons, and supplementary provisions are not
included.  The script prints aggregate counts and hashes only; it never prints
the statutory text or detector-matched substrings.

Run from the repository root:

    python paper/audit_public_law_hard_negatives.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAYER0_DIR = ROOT / "PII" / "layer_0"
HARD_CASES = (
    ROOT
    / "korean_pii_guardrail_v0_2"
    / "data"
    / "eval"
    / "hard_cases_v0.jsonl"
)

API_TEMPLATE = (
    "https://www.law.go.kr/DRF/lawService.do"
    "?OC=test&target=law&type=XML&ID={law_id}"
)
PROVISION_TAGS = {"조문내용", "항내용", "호내용", "목내용"}
MIN_DOCUMENT_LENGTH = 20

SOURCES = {
    "011357": {
        "title": "개인정보 보호법",
        "promulgation_date": "20250401",
        "promulgation_number": "20897",
        "overall_effective_date": "20251002",
        "xml_sha256": (
            "d37c7d7d46ed639b7f6c0f6bdf0dea7cb5a1bde19d71f66"
            "df504ec502b080219"
        ),
        "documents": 842,
        "flagged_documents": 2,
        "finding_types": {"nationality": 2},
    },
    "014820": {
        "title": "인공지능 발전과 신뢰 기반 조성 등에 관한 기본법",
        "promulgation_date": "20260120",
        "promulgation_number": "21311",
        "overall_effective_date": "20260122",
        "xml_sha256": (
            "7e0ce3b69ef1dac4c02342109f9488f3508a6971ed480e5e"
            "50876e522e150d1f"
        ),
        "documents": 382,
        "flagged_documents": 18,
        "finding_types": {"dept": 18},
    },
    "001444": {
        "title": "대한민국헌법",
        "promulgation_date": "19871029",
        "promulgation_number": "00010",
        "overall_effective_date": "19880225",
        "xml_sha256": (
            "c9d783b15ac8fe90c2573a06cdcf202173f1cbd374f963315"
            "e92afe1857483ef"
        ),
        "documents": 295,
        "flagged_documents": 9,
        "finding_types": {"nationality": 9},
    },
}

AI_ACT_ARTICLE_EFFECTIVE_DATES = {
    "31": "20260122",
    "33": "20260122",
    "34": "20260122",
    "35": "20260122",
    "43": "20260122",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_xml(law_id: str) -> bytes:
    request = urllib.request.Request(
        API_TEMPLATE.format(law_id=law_id),
        headers={"User-Agent": "KPIIGD-paper-audit/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def element_text(root: ET.Element, tag: str) -> str:
    element = next(root.iter(tag), None)
    return (element.text or "").strip() if element is not None else ""


def extract_documents(root: ET.Element) -> list[str]:
    """Extract unique substantive provision units in source order."""
    documents: list[str] = []
    seen: set[str] = set()
    for element in root.iter():
        if element.tag not in PROVISION_TAGS:
            continue
        text = re.sub(r"\s+", " ", element.text or "").strip()
        if len(text) < MIN_DOCUMENT_LENGTH or text in seen:
            continue
        seen.add(text)
        documents.append(text)
    return documents


def article_effective_dates(root: ET.Element, article_numbers: set[str]) -> dict[str, str]:
    dates: dict[str, str] = {}
    for unit in root.iter("조문단위"):
        number = (unit.findtext("조문번호") or "").strip()
        if number in article_numbers:
            dates[number] = (unit.findtext("조문시행일자") or "").strip()
    return dates


def load_legacy_layer0():
    sys.path.insert(0, str(LAYER0_DIR))
    try:
        from korean_normalizer import KoreanNormalizer
        from korean_pii_detector import KoreanPIIDetector
    finally:
        sys.path.pop(0)
    return KoreanNormalizer(), KoreanPIIDetector()


def audit_documents(documents: list[str], normalizer, detector) -> dict:
    flagged_documents = 0
    finding_types: Counter[str] = Counter()
    for document in documents:
        findings = detector.detect(normalizer.normalize(document))
        if findings:
            flagged_documents += 1
            finding_types.update(finding.pii_type for finding in findings)
    return {
        "documents": len(documents),
        "flagged_documents": flagged_documents,
        "flagged_document_rate": flagged_documents / len(documents),
        "finding_types": dict(sorted(finding_types.items())),
    }


def audit_explicit_hard_negative_fixtures(normalizer, detector) -> dict:
    rows = [
        json.loads(line)
        for line in HARD_CASES.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    negatives = [row for row in rows if not row.get("labels")]
    finding_types: Counter[str] = Counter()
    flagged = 0
    for row in negatives:
        findings = detector.detect(normalizer.normalize(row["text"]))
        if findings:
            flagged += 1
            finding_types.update(finding.pii_type for finding in findings)
    return {
        "dataset": "synthetic explicit hard-negative fixtures; not a natural corpus",
        "documents": len(negatives),
        "flagged_documents": flagged,
        "flagged_document_rate": flagged / len(negatives),
        "finding_types": dict(sorted(finding_types.items())),
        "dataset_sha256": sha256_path(HARD_CASES),
    }


def main() -> None:
    normalizer, detector = load_legacy_layer0()
    source_results: dict[str, dict] = {}
    aggregate_documents = 0
    aggregate_flagged = 0
    aggregate_types: Counter[str] = Counter()
    ai_act_root: ET.Element | None = None

    for law_id, expected in SOURCES.items():
        xml_bytes = fetch_xml(law_id)
        root = ET.fromstring(xml_bytes)
        metadata = {
            "title": element_text(root, "법령명_한글"),
            "promulgation_date": element_text(root, "공포일자"),
            "promulgation_number": element_text(root, "공포번호"),
            "overall_effective_date": element_text(root, "시행일자"),
        }
        documents = extract_documents(root)
        audit = audit_documents(documents, normalizer, detector)
        result = {
            "official_api_url": API_TEMPLATE.format(law_id=law_id),
            **metadata,
            "xml_sha256": sha256_bytes(xml_bytes),
            **audit,
        }
        source_results[law_id] = result
        aggregate_documents += audit["documents"]
        aggregate_flagged += audit["flagged_documents"]
        aggregate_types.update(audit["finding_types"])

        for field in (
            "title",
            "promulgation_date",
            "promulgation_number",
            "overall_effective_date",
            "xml_sha256",
            "documents",
            "flagged_documents",
            "finding_types",
        ):
            assert result[field] == expected[field], (
                law_id,
                field,
                result[field],
                expected[field],
            )
        if law_id == "014820":
            ai_act_root = root

    assert ai_act_root is not None
    ai_act_dates = article_effective_dates(
        ai_act_root, set(AI_ACT_ARTICLE_EFFECTIVE_DATES)
    )
    assert ai_act_dates == AI_ACT_ARTICLE_EFFECTIVE_DATES

    fixture_audit = audit_explicit_hard_negative_fixtures(normalizer, detector)
    assert fixture_audit["documents"] == 4
    assert fixture_audit["flagged_documents"] == 1
    assert fixture_audit["finding_types"] == {"phone_kr": 1}
    assert aggregate_documents == 1519
    assert aggregate_flagged == 29
    assert aggregate_types == Counter({"dept": 18, "nationality": 11})

    output = {
        "audit_date": "2026-07-26",
        "scope": (
            "official statutory provision text; metadata, contacts, appendices, "
            "amendment reasons, and supplementary provisions excluded"
        ),
        "extraction": {
            "tags": sorted(PROVISION_TAGS),
            "minimum_characters": MIN_DOCUMENT_LENGTH,
            "deduplication": "exact text within each law",
        },
        "sources": source_results,
        "aggregate": {
            "documents": aggregate_documents,
            "flagged_documents": aggregate_flagged,
            "flagged_document_rate": aggregate_flagged / aggregate_documents,
            "finding_types": dict(sorted(aggregate_types.items())),
        },
        "explicit_hard_negative_fixture_audit": fixture_audit,
        "ai_basic_act_article_effective_dates": ai_act_dates,
        "implementation_sha256": {
            "normalizer": sha256_path(LAYER0_DIR / "korean_normalizer.py"),
            "detector": sha256_path(LAYER0_DIR / "korean_pii_detector.py"),
        },
        "interpretation_limit": (
            "The statutory units are authentic public-law text and contain no "
            "case-level personal data, but they do not represent medical, "
            "financial, customer-support, or production traffic."
        ),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
