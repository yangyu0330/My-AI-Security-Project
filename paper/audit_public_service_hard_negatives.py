"""Audit Layer 0 false positives on official Korean service-domain prose.

The original clean-Korean fixture deliberately excludes direct PII-like
patterns, and the public-law audit covers only one domain.  This script adds a
reproducible, independently sourced hard-negative audit across four domains:

* medical/health information from the Korea Disease Control and Prevention
  Agency (KDCA);
* consumer-finance education from the Financial Services Commission (FSC);
* customer-support documentation from Amazon Web Services (AWS); and
* developer documentation from the Python Software Foundation (PSF).

Only visible paragraph/list/heading/table-cell units of at least 20 characters
are evaluated.  Navigation, headers, footers, scripts, styles, forms, direct
identifier-like strings, contact metadata, and exact duplicate units are
excluded.  These are general public guidance pages, not case records.

The default output contains aggregate counts and hashes only.  ``--review``
also emits the flagged public text with source locators so two independent
reviewers can decide whether each flag is a true PII instance or lexical
overblocking.

Run from the repository root:

    python paper/audit_public_service_hard_negatives.py
    python paper/audit_public_service_hard_negatives.py --review
"""

from __future__ import annotations

import argparse
import hashlib
import html.parser
import json
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAYER0_DIR = ROOT / "PII" / "layer_0"
BASELINE_PATH = ROOT / "paper" / "public_service_hard_negative_audit.json"
MIN_DOCUMENT_LENGTH = 20

SOURCES = (
    {
        "id": "medical-kdca-portal",
        "domain": "medical",
        "owner": "질병관리청 국가건강정보포털",
        "title": "국가건강정보포털은?",
        "container": {"tag": "div", "id": "sub-content"},
        "url": (
            "https://health.kdca.go.kr/healthinfo/biz/health/intrcnYard/"
            "nationHlthinsPortalMain.do"
        ),
    },
    {
        "id": "medical-kdca-exercise",
        "domain": "medical",
        "owner": "질병관리청 국가건강정보포털",
        "title": "운동",
        "container": {"tag": "div", "id": "print-content"},
        "url": (
            "https://health.kdca.go.kr/healthinfo/biz/health/"
            "gnrlzHealthInfo/gnrlzHealthInfo/gnrlzHealthInfoView.do"
            "?cntnts_sn=5293"
        ),
    },
    {
        "id": "medical-kdca-older-exercise",
        "domain": "medical",
        "owner": "질병관리청 국가건강정보포털",
        "title": "노년기 운동, 어떻게 하면 좋을까요?",
        "container": {"tag": "div", "id": "print-content"},
        "url": (
            "https://health.kdca.go.kr/healthinfo/biz/health/ntcnInfo/"
            "healthSourc/thtimtCntnts/thtimtCntntsView.do"
            "?thtimt_cntnts_sn=44"
        ),
    },
    {
        "id": "medical-kdca-weight",
        "domain": "medical",
        "owner": "질병관리청 국가건강정보포털",
        "title": "노인의 체중관리 방법",
        "container": {"tag": "div", "id": "print-content"},
        "url": (
            "https://health.kdca.go.kr/healthinfo/biz/health/ntcnInfo/"
            "healthSourc/thtimtCntnts/thtimtCntntsView.do"
            "?thtimt_cntnts_sn=65"
        ),
    },
    {
        "id": "medical-kdca-checkup",
        "domain": "medical",
        "owner": "질병관리청 국가건강정보포털",
        "title": "알아두면 도움이 되는 건강검진",
        "container": {"tag": "div", "id": "print-content"},
        "url": (
            "https://health.kdca.go.kr/healthinfo/biz/health/ntcnInfo/"
            "healthSourc/thtimtCntnts/thtimtCntntsView.do"
            "?thtimt_cntnts_sn=7"
        ),
    },
    {
        "id": "finance-fsc-deposit",
        "domain": "finance",
        "owner": "금융위원회",
        "title": "예금·적금 가입 전 확인사항",
        "container": {"tag": "div", "class": "description"},
        "url": "https://www.fsc.go.kr/edu/cardnews?cnId=2259",
    },
    {
        "id": "finance-fsc-rates",
        "domain": "finance",
        "owner": "금융위원회",
        "title": "예금·대출 금리 비교공시",
        "container": {"tag": "div", "class": "description"},
        "url": "https://www.fsc.go.kr/edu/cardnews?cnId=1008",
    },
    {
        "id": "finance-fsc-youth",
        "domain": "finance",
        "owner": "금융위원회",
        "title": "청년 맞춤형 금융교육",
        "container": {"tag": "div", "class": "description"},
        "url": "https://www.fsc.go.kr/edu/cardnews?cnId=2133",
    },
    {
        "id": "finance-fsc-phishing",
        "domain": "finance",
        "owner": "금융위원회",
        "title": "보이스피싱 예방 캠페인",
        "container": {"tag": "div", "class": "description"},
        "url": "https://www.fsc.go.kr/no040101?cnId=525",
    },
    {
        "id": "finance-fsc-loan-fraud",
        "domain": "finance",
        "owner": "금융위원회",
        "title": "불법 대출 사기 예방법",
        "container": {"tag": "div", "class": "description"},
        "url": "https://www.fsc.go.kr/edu/cardnews?cnId=2313",
    },
    {
        "id": "finance-fsc-collection",
        "domain": "finance",
        "owner": "금융위원회",
        "title": "불법 채권추심으로부터 보호받는 방법",
        "container": {"tag": "div", "class": "description"},
        "url": "https://www.fsc.go.kr/edu/cardnews?cnId=2326",
    },
    {
        "id": "finance-fsc-overseas-card",
        "domain": "finance",
        "owner": "금융위원회",
        "title": "해외에서 신용카드 안전하게 사용하는 방법",
        "container": {"tag": "div", "class": "description"},
        "url": "https://www.fsc.go.kr/edu/cardnews?cnId=2332",
    },
    {
        "id": "finance-fsc-credit-score",
        "domain": "finance",
        "owner": "금융위원회",
        "title": "신용점수 관리방법",
        "container": {"tag": "div", "class": "description"},
        "url": "https://www.fsc.go.kr/edu/cardnews?cnId=2299",
    },
    {
        "id": "support-aws-plans",
        "domain": "support",
        "owner": "Amazon Web Services",
        "title": "AWS Support 플랜",
        "container": {"tag": "div", "id": "main-col-body"},
        "url": (
            "https://docs.aws.amazon.com/ko_kr/awssupport/latest/user/"
            "aws-support-plans.html"
        ),
    },
    {
        "id": "support-aws-access",
        "domain": "support",
        "owner": "Amazon Web Services",
        "title": "AWS Support Center 액세스 관리",
        "container": {"tag": "div", "id": "main-col-body"},
        "url": (
            "https://docs.aws.amazon.com/ko_kr/awssupport/latest/user/"
            "accessing-support.html"
        ),
    },
    {
        "id": "support-aws-interaction",
        "domain": "support",
        "owner": "Amazon Web Services",
        "title": "지원 상호 작용 생성",
        "container": {"tag": "div", "id": "main-col-body"},
        "url": (
            "https://docs.aws.amazon.com/ko_kr/awssupport/latest/user/"
            "create-support-interaction.html"
        ),
    },
    {
        "id": "support-aws-cases",
        "domain": "support",
        "owner": "Amazon Web Services",
        "title": "지원 사례 업데이트·해결·재개",
        "container": {"tag": "div", "id": "main-col-body"},
        "url": (
            "https://docs.aws.amazon.com/ko_kr/awssupport/latest/user/"
            "monitoring-your-case.html"
        ),
    },
    {
        "id": "developer-python-introduction",
        "domain": "developer",
        "owner": "Python Software Foundation",
        "title": "파이썬의 간략한 소개",
        "container": {"tag": "div", "class": "body", "role": "main"},
        "url": (
            "https://docs.python.org/ko/3.13/tutorial/introduction.html"
        ),
    },
    {
        "id": "developer-python-controlflow",
        "domain": "developer",
        "owner": "Python Software Foundation",
        "title": "기타 제어 흐름 도구",
        "container": {"tag": "div", "class": "body", "role": "main"},
        "url": (
            "https://docs.python.org/ko/3.13/tutorial/controlflow.html"
        ),
    },
    {
        "id": "developer-python-datastructures",
        "domain": "developer",
        "owner": "Python Software Foundation",
        "title": "자료 구조",
        "container": {"tag": "div", "class": "body", "role": "main"},
        "url": (
            "https://docs.python.org/ko/3.13/tutorial/datastructures.html"
        ),
    },
    {
        "id": "developer-python-errors",
        "domain": "developer",
        "owner": "Python Software Foundation",
        "title": "에러와 예외",
        "container": {"tag": "div", "class": "body", "role": "main"},
        "url": "https://docs.python.org/ko/3.13/tutorial/errors.html",
    },
)

BLOCK_TAGS = {
    "p",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "td",
    "th",
    "dd",
    "dt",
    "figcaption",
}
SKIP_TAGS = {
    "script",
    "style",
    "noscript",
    "svg",
    "button",
}
EXCLUDED_METADATA_MARKERS = (
    "담당부서",
    "담당자",
    "연락처",
    "개인정보처리방침",
    "저작권 정책",
    "copyright",
    "all rights reserved",
)
DIRECT_IDENTIFIER_PATTERNS = {
    "email": re.compile(r"(?i)[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"),
    "url": re.compile(r"(?i)(?:https?://|www\.)\S+"),
    "phone": re.compile(r"(?<!\d)0\d{1,2}[- .]?\d{3,4}[- .]?\d{4}(?!\d)"),
    "rrn": re.compile(r"(?<!\d)\d{6}[- ]?[1-8]\d{6}(?!\d)"),
    "card": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
    "ip": re.compile(
        r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"
    ),
    "mac": re.compile(
        r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}"
        r"(?![0-9a-f])"
    ),
    "aws_key": re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16,}"),
}


class VisibleUnitParser(html.parser.HTMLParser):
    """Collect visible semantic text units without site-specific selectors."""

    def __init__(self, container: dict[str, str]) -> None:
        super().__init__(convert_charrefs=True)
        self.container = container
        self.container_depth = 0
        self.skip_depth = 0
        self.active_blocks: list[dict[str, object]] = []
        self.units: list[str] = []

    def _matches_container(self, tag: str, attrs) -> bool:
        if tag != self.container["tag"]:
            return False
        attributes = dict(attrs)
        for name, value in self.container.items():
            if name == "tag":
                continue
            actual = attributes.get(name, "")
            if name == "class":
                if value not in actual.split():
                    return False
            elif actual != value:
                return False
        return True

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        if not self.container_depth:
            if self._matches_container(tag, attrs):
                self.container_depth = 1
            return
        if tag == self.container["tag"]:
            self.container_depth += 1
        if tag in SKIP_TAGS:
            self.skip_depth += 1
            return
        if self.skip_depth:
            return
        if tag in BLOCK_TAGS:
            for block in self.active_blocks:
                block["has_block_child"] = True
            self.active_blocks.append(
                {"tag": tag, "buffer": [], "has_block_child": False}
            )

    def handle_startendtag(self, tag: str, attrs) -> None:
        return

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if not self.container_depth:
            return
        if tag in SKIP_TAGS:
            if self.skip_depth:
                self.skip_depth -= 1
        elif not self.skip_depth and tag in BLOCK_TAGS:
            for index in range(len(self.active_blocks) - 1, -1, -1):
                block = self.active_blocks[index]
                if block["tag"] != tag:
                    continue
                self.active_blocks.pop(index)
                text = re.sub(
                    r"\s+", " ", " ".join(block["buffer"])
                ).strip()
                if text and not block["has_block_child"]:
                    self.units.append(text)
                break
        if tag == self.container["tag"]:
            self.container_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self.container_depth or self.skip_depth:
            return
        for block in self.active_blocks:
            block["buffer"].append(data)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_html(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "KPIIGD-paper-service-domain-audit/1.0",
            "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.5",
        },
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        content_type = response.headers.get("Content-Type", "")
        assert "html" in content_type.lower(), (url, content_type)
        return response.read()


def decode_html(raw: bytes) -> str:
    for encoding in ("utf-8", "euc-kr", "cp949"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("html", raw, 0, 1, "unsupported encoding")


def is_direct_identifier_like(text: str) -> bool:
    return any(pattern.search(text) for pattern in DIRECT_IDENTIFIER_PATTERNS.values())


def filter_units(units: list[str]) -> tuple[list[str], Counter[str]]:
    accepted: list[str] = []
    seen: set[str] = set()
    exclusions: Counter[str] = Counter()
    for unit in units:
        text = re.sub(r"\s+", " ", unit).strip(" \t\r\n•·¶")
        if len(text) < MIN_DOCUMENT_LENGTH:
            exclusions["short"] += 1
            continue
        lowered = text.casefold()
        if any(marker in lowered for marker in EXCLUDED_METADATA_MARKERS):
            exclusions["metadata"] += 1
            continue
        if is_direct_identifier_like(text):
            exclusions["direct_identifier_like"] += 1
            continue
        if not re.search(r"[가-힣]", text):
            exclusions["no_korean"] += 1
            continue
        if text in seen:
            exclusions["duplicate_within_source"] += 1
            continue
        seen.add(text)
        accepted.append(text)
    return accepted, exclusions


def load_legacy_layer0():
    sys.path.insert(0, str(LAYER0_DIR))
    try:
        from korean_normalizer import KoreanNormalizer
        from korean_pii_detector import KoreanPIIDetector
    finally:
        sys.path.pop(0)
    return KoreanNormalizer(), KoreanPIIDetector()


def finding_summary(findings) -> tuple[list[str], list[str]]:
    finding_types = sorted({finding.pii_type for finding in findings})
    reason_codes = sorted(
        {
            finding.context_keyword
            for finding in findings
            if finding.context_keyword
        }
    )
    return finding_types, reason_codes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--review",
        action="store_true",
        help="include flagged public text and stable source locators",
    )
    parser.add_argument(
        "--verify-baseline",
        action="store_true",
        help="assert current extracted text hashes and results match saved JSON",
    )
    args = parser.parse_args()

    normalizer, detector = load_legacy_layer0()
    per_source = []
    per_domain_records: dict[str, list[dict]] = {
        domain: [] for domain in ("medical", "finance", "support", "developer")
    }
    source_exclusions: Counter[str] = Counter()

    for source in SOURCES:
        raw = fetch_html(source["url"])
        unit_parser = VisibleUnitParser(source["container"])
        unit_parser.feed(decode_html(raw))
        units, exclusions = filter_units(unit_parser.units)
        source_exclusions.update(exclusions)
        assert units, f"no eligible public text extracted: {source['id']}"
        for ordinal, text in enumerate(units, 1):
            per_domain_records[source["domain"]].append(
                {
                    "source_id": source["id"],
                    "source_url": source["url"],
                    "source_title": source["title"],
                    "unit_ordinal": ordinal,
                    "text": text,
                }
            )
        per_source.append(
            {
                "id": source["id"],
                "domain": source["domain"],
                "owner": source["owner"],
                "title": source["title"],
                "official_url": source["url"],
                "container": source["container"],
                "eligible_text_sha256": sha256_bytes(
                    "\n".join(units).encode("utf-8")
                ),
                "eligible_units": len(units),
                "exclusions": dict(sorted(exclusions.items())),
            }
        )

    aggregate_types: Counter[str] = Counter()
    domain_results = {}
    review_packet = []
    global_seen: set[str] = set()

    for domain, records in per_domain_records.items():
        domain_seen: set[str] = set()
        unique_records = []
        duplicate_units = 0
        for record in records:
            text = record["text"]
            if text in domain_seen:
                duplicate_units += 1
                continue
            domain_seen.add(text)
            unique_records.append(record)
        flagged = 0
        finding_types: Counter[str] = Counter()
        for record in unique_records:
            text = record["text"]
            findings = detector.detect(normalizer.normalize(text))
            if findings:
                flagged += 1
                types, reasons = finding_summary(findings)
                finding_types.update(types)
                if args.review:
                    assert not is_direct_identifier_like(text)
                    review_packet.append(
                        {
                            "case_id": (
                                f"service-{domain}-{len(review_packet) + 1:04d}"
                            ),
                            "domain": domain,
                            "source_id": record["source_id"],
                            "source_title": record["source_title"],
                            "official_url": record["source_url"],
                            "unit_ordinal": record["unit_ordinal"],
                            "text_sha256": sha256_bytes(text.encode("utf-8")),
                            "finding_types": types,
                            "reason_codes": reasons,
                            "official_public_text": text,
                        }
                    )
            global_seen.add(text)
        aggregate_types.update(finding_types)
        domain_results[domain] = {
            "documents": len(unique_records),
            "flagged_documents": flagged,
            "flagged_document_rate": (
                flagged / len(unique_records) if unique_records else 0
            ),
            "finding_types": dict(sorted(finding_types.items())),
            "duplicate_units_removed": duplicate_units,
        }

    total_documents = sum(
        result["documents"] for result in domain_results.values()
    )
    total_flagged = sum(
        result["flagged_documents"] for result in domain_results.values()
    )
    output = {
        "audit_date": "2026-07-26",
        "scope": (
            "official Korean public service-domain prose; navigation, contact "
            "metadata, direct identifier-like strings, and duplicates excluded"
        ),
        "interpretation_limit": (
            "The pages are authentic general guidance, not a probability "
            "sample of production traffic. Results estimate lexical "
            "overblocking on this fixed public corpus only."
        ),
        "extraction": {
            "block_tags": sorted(BLOCK_TAGS),
            "minimum_characters": MIN_DOCUMENT_LENGTH,
            "requires_korean": True,
            "deduplication": "exact text within each domain",
            "excluded_unit_counts": dict(sorted(source_exclusions.items())),
            "corpus_sha256": sha256_bytes(
                "\n".join(
                    f"{source['id']}:{source['eligible_text_sha256']}"
                    for source in per_source
                ).encode("utf-8")
            ),
        },
        "sources": per_source,
        "domains": domain_results,
        "aggregate": {
            "documents": total_documents,
            "flagged_documents": total_flagged,
            "flagged_document_rate": (
                total_flagged / total_documents if total_documents else 0
            ),
            "finding_types": dict(sorted(aggregate_types.items())),
            "globally_unique_documents": len(global_seen),
        },
        "implementation_sha256": {
            "normalizer": sha256_bytes(
                (LAYER0_DIR / "korean_normalizer.py").read_bytes()
            ),
            "detector": sha256_bytes(
                (LAYER0_DIR / "korean_pii_detector.py").read_bytes()
            ),
        },
    }
    if args.review:
        output["review_packet_notice"] = (
            "Public non-case prose is included only for independent false-"
            "positive labeling. Reviewers must not infer production rates."
        )
        output["review_packet"] = review_packet

    if args.verify_baseline:
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        current_sources = [
            {
                "id": source["id"],
                "domain": source["domain"],
                "official_url": source["official_url"],
                "eligible_text_sha256": source["eligible_text_sha256"],
                "eligible_units": source["eligible_units"],
            }
            for source in output["sources"]
        ]
        assert output["extraction"]["corpus_sha256"] == baseline["corpus_sha256"]
        assert current_sources == baseline["sources"]
        assert output["domains"] == baseline["domains"]
        assert output["aggregate"] == baseline["aggregate"]
        assert output["implementation_sha256"] == baseline["implementation_sha256"]
        output["baseline_verification"] = "passed"

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
