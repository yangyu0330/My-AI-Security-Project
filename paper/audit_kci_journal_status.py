#!/usr/bin/env python3
"""Audit the target journal's current discoverability in the official KCI catalog."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import http.cookiejar
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


PAPER_DIR = Path(__file__).resolve().parent
OUTPUT = PAPER_DIR / "kci_target_journal_audit.json"
FORM_URL = "https://www.kci.go.kr/kciportal/po/search/poSereSear.kci"
RESULT_URL = (
    "https://www.kci.go.kr/kciportal/po/search/poSereSearList.kci"
)
TARGET_KOREAN = "범죄와 정책"
TARGET_ENGLISH = "The Korean Crime and Policy Review"
TARGET_PUBLISHER = "한국범죄학회"
QUERIES = (
    ("SERE_NM", TARGET_KOREAN, "unquoted_korean_title"),
    ("SERE_NM", f'"{TARGET_KOREAN}"', "quoted_korean_title"),
    ("SERE_NM", TARGET_ENGLISH, "english_title"),
    ("PUBI_INSI_NM", TARGET_PUBLISHER, "publisher_name"),
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def clean_html(value: str) -> str:
    without_tags = re.sub(r"<[^>]+>", "", value)
    return re.sub(r"\s+", " ", html.unescape(without_tags)).strip()


def parse_results(body: bytes) -> tuple[int, list[dict[str, str]]]:
    text = body.decode("utf-8")
    count_match = re.search(
        r"에 대한 검색 결과입니다\.\s*총\s*"
        r'<span[^>]*>([0-9,]+)\s*건</span>',
        text,
        flags=re.IGNORECASE,
    )
    if not count_match:
        raise AssertionError("could not parse KCI result count")
    result_count = int(count_match.group(1).replace(",", ""))
    items = [
        {
            "sere_id": match.group(1),
            "journal_title": clean_html(match.group(2)),
        }
        for match in re.finditer(
            r'<a href="[^"]*sereId=([^"]+)"[^>]*>(.*?)</a>',
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )
    ]
    if result_count != len(items):
        raise AssertionError((result_count, len(items)))
    return result_count, items


def build_snapshot(audit_date: str) -> dict[str, Any]:
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookies)
    )
    headers = {"User-Agent": "Mozilla/5.0"}
    form_request = urllib.request.Request(FORM_URL, headers=headers)
    with opener.open(form_request, timeout=60) as response:
        if response.status != 200:
            raise AssertionError(response.status)
        form_bytes = response.read()
    form_text = form_bytes.decode("utf-8")
    required_form_markers = (
        'action="/kciportal/po/search/poSereSearList.kci"',
        'name="poSearchBean.conditionList"',
        'value="SERE_NM"',
        'value="PUBI_INSI_NM"',
        'name="poSearchBean.keywordList"',
    )
    for marker in required_form_markers:
        if marker not in form_text:
            raise AssertionError(marker)

    query_results = []
    for condition, keyword, query_id in QUERIES:
        payload = urllib.parse.urlencode(
            {
                "poSearchBean.searType": "journal",
                "poSearchBean.startPg": "1",
                "from": "searchFromJournal",
                "poSearchBean.conditionList": condition,
                "poSearchBean.keywordList": keyword,
                "poSearchBean.sortName": "SCORE",
                "poSearchBean.sortDir": "desc",
                "poSearchBean.docsCount": "300",
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            RESULT_URL,
            data=payload,
            headers={
                **headers,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        with opener.open(request, timeout=60) as response:
            if response.status != 200:
                raise AssertionError((query_id, response.status))
            response_bytes = response.read()
        count, items = parse_results(response_bytes)
        query_results.append(
            {
                "query_id": query_id,
                "condition": condition,
                "keyword": keyword,
                "result_count": count,
                "items": items,
                "response_sha256": sha256_bytes(response_bytes),
            }
        )

    by_id = {row["query_id"]: row for row in query_results}
    exact_title_matches = [
        item
        for row in query_results
        for item in row["items"]
        if item["journal_title"].split(" (", 1)[0] == TARGET_KOREAN
        or TARGET_ENGLISH in item["journal_title"]
    ]
    if exact_title_matches:
        raise AssertionError(exact_title_matches)
    if by_id["unquoted_korean_title"]["items"] != [
        {
            "sere_id": "SER000006287",
            "journal_title": (
                "범죄와 경찰정책학회보 (Journal of Crime and Police Policy)"
            ),
        }
    ]:
        raise AssertionError(by_id["unquoted_korean_title"])
    if by_id["quoted_korean_title"]["result_count"] != 0:
        raise AssertionError(by_id["quoted_korean_title"])
    if by_id["english_title"]["result_count"] != 0:
        raise AssertionError(by_id["english_title"])

    return {
        "schema_version": 1,
        "audit_date": audit_date,
        "authority": "한국연구재단 한국학술지인용색인(KCI)",
        "form_url": FORM_URL,
        "result_url": RESULT_URL,
        "form_sha256": sha256_bytes(form_bytes),
        "target": {
            "korean_title": TARGET_KOREAN,
            "english_title": TARGET_ENGLISH,
            "publisher": TARGET_PUBLISHER,
        },
        "queries": query_results,
        "finding": {
            "exact_catalog_record_found": False,
            "state": "NO_EXACT_KCI_JOURNAL_RECORD_FOUND",
            "interpretation": (
                "No exact Korean- or English-title record was returned by the "
                "official KCI journal search on the audit date."
            ),
            "caveat": (
                "Search absence does not prove non-registration or non-indexing; "
                "catalog update lag is possible, so editor confirmation remains required."
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
            raise SystemExit("KCI_TARGET_JOURNAL_VERIFY_FAILED: source changed")
        status = "verified"

    print(
        json.dumps(
            {
                "status": status,
                "audit_date": snapshot["audit_date"],
                **snapshot["finding"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
