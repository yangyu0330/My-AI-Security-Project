#!/usr/bin/env python3
"""Verify the official Crime and Policy publication archive exposed by ksoc.re.kr."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


PAPER_DIR = Path(__file__).resolve().parent
OUTPUT = PAPER_DIR / "target_journal_archive_audit.json"
BASE_URL = "https://ksoc.re.kr"
ROBOTS_URL = f"{BASE_URL}/robots.txt"
PUBLICATION_URL = f"{BASE_URL}/「범죄와-정책」발간물"


def fetch(url: str) -> tuple[bytes, str]:
    encoded_url = urllib.parse.quote(url, safe=":/?=&%")
    request = urllib.request.Request(
        encoded_url,
        headers={"User-Agent": "Mozilla/5.0"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status != 200:
            raise AssertionError((url, response.status))
        return response.read(), response.headers.get_content_type()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def build_snapshot(audit_date: str) -> dict[str, Any]:
    robots_bytes, robots_type = fetch(ROBOTS_URL)
    robots_text = robots_bytes.decode("utf-8")
    sitemap_match = re.search(r"(?m)^Sitemap:\s*(https://\S+)\s*$", robots_text)
    if not sitemap_match:
        raise AssertionError("official robots.txt has no Sitemap line")
    sitemap_url = sitemap_match.group(1)

    sitemap_bytes, sitemap_type = fetch(sitemap_url)
    root = ET.fromstring(sitemap_bytes.decode("utf-8"))
    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locations = [
        node.text
        for node in root.findall("sm:url/sm:loc", namespace)
        if node.text
    ]
    publication_locations = [
        url
        for url in locations
        if url == PUBLICATION_URL
    ]
    if len(publication_locations) != 1:
        raise AssertionError(publication_locations)
    raw_publication_location = publication_locations[0]
    publication_url = PUBLICATION_URL

    page_bytes, page_type = fetch(publication_url)
    page_html = page_bytes.decode("utf-8")
    sid_match = re.search(r"""\bSID\s*:\s*["'](\d+)["']""", page_html)
    if not sid_match:
        raise AssertionError("could not resolve Creatorlink page identity")
    sid = sid_match.group(1)
    page_name = urllib.parse.unquote(
        urllib.parse.urlparse(publication_url).path.rsplit("/", 1)[-1]
    )
    if page_name != "「범죄와-정책」발간물":
        raise AssertionError(page_name)

    content_url = (
        f"{BASE_URL}/template/contents/sid/{sid}/page/"
        f"{urllib.parse.quote(page_name, safe='')}"
    )
    content_bytes, content_type = fetch(content_url)
    content = json.loads(content_bytes.decode("utf-8"))
    init_content = json.loads(content["initContent"])
    empty_element = {"eltag": "", "elcss": ""}
    is_empty = (
        content.get("contents") == [empty_element]
        and content.get("blocks_type") == []
        and init_content == [empty_element]
    )
    if not is_empty:
        raise AssertionError("official publication page is no longer empty")

    return {
        "schema_version": 1,
        "audit_date": audit_date,
        "official_domain": "ksoc.re.kr",
        "robots": {
            "url": ROBOTS_URL,
            "content_type": robots_type,
            "sha256": sha256_bytes(robots_bytes),
            "sitemap_url": sitemap_url,
        },
        "sitemap": {
            "url": sitemap_url,
            "content_type": sitemap_type,
            "sha256": sha256_bytes(sitemap_bytes),
            "page_count": len(locations),
            "publication_url": publication_url,
            "raw_publication_location": raw_publication_location,
            "raw_location_note": "Official sitemap location retained verbatim.",
        },
        "publication_page": {
            "url": publication_url,
            "content_type": page_type,
            "creatorlink_sid": sid,
            "page_name": page_name,
            "content_endpoint": content_url,
        },
        "content_endpoint": {
            "url": content_url,
            "content_type": content_type,
            "sha256": sha256_bytes(content_bytes),
            "response": content,
        },
        "finding": {
            "official_archive_entries": 0,
            "state": "EMPTY_OFFICIAL_PUBLICATION_PAGE",
            "interpretation": (
                "The official site exposes a publication page but no article "
                "entries; absence does not prove that no issues were published."
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
            raise SystemExit("TARGET_JOURNAL_ARCHIVE_VERIFY_FAILED: source changed")
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
