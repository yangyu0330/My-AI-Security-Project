#!/usr/bin/env python3
"""Audit every branch and preserved PR-head ref in the four KPIIGD repositories."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "paper" / "repository_scope_audit.json"
ORGANIZATION = "KPIIGD"
REPOSITORIES = {
    "kpiigd": "KPIIGD/My-AI-Security-Project",
    "kpiigd-data": "KPIIGD/My-AI-Security-Project-data",
    "kpiigd-internal": "KPIIGD/My-AI-Security-Project-internal",
    "kpiigd-kb": "KPIIGD/ai-security-kb",
}


def run(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    return completed.stdout


def parse_ls_remote(output: str, prefix: str) -> list[dict[str, str]]:
    rows = []
    for line in output.splitlines():
        if not line.strip():
            continue
        sha, ref = line.split("\t", 1)
        if not ref.startswith(prefix):
            raise AssertionError((ref, prefix))
        rows.append({"ref": ref.removeprefix(prefix), "sha": sha})
    return sorted(rows, key=lambda row: row["ref"])


def github_repository_metadata() -> dict[str, dict[str, Any]]:
    rows = json.loads(
        run(
            [
                "gh",
                "repo",
                "list",
                ORGANIZATION,
                "--limit",
                "100",
                "--json",
                "nameWithOwner,isPrivate,isArchived,defaultBranchRef",
            ]
        )
    )
    metadata = {row["nameWithOwner"]: row for row in rows}
    expected = set(REPOSITORIES.values())
    if set(metadata) != expected:
        raise AssertionError(
            f"organization repository set changed: {sorted(metadata)}"
        )
    return metadata


def latest_public_pr() -> dict[str, Any]:
    repository = REPOSITORIES["kpiigd"]
    rows = json.loads(
        run(
            [
                "gh",
                "pr",
                "list",
                "--repo",
                repository,
                "--state",
                "all",
                "--limit",
                "1",
                "--json",
                "number,title,state,headRefName,headRefOid,baseRefName,updatedAt",
            ]
        )
    )
    if len(rows) != 1:
        raise AssertionError("latest PR lookup did not return exactly one row")
    row = rows[0]
    details = json.loads(
        run(
            [
                "gh",
                "pr",
                "view",
                str(row["number"]),
                "--repo",
                repository,
                "--json",
                "files",
            ]
        )
    )
    files = sorted(details["files"], key=lambda item: item["path"])
    return {
        **row,
        "files": files,
        "paper_evidence_impact": (
            "none_workflow_only"
            if files and all(item["path"].startswith(".github/") for item in files)
            else "manual_review_required"
        ),
    }


def build_snapshot(audit_date: str) -> dict[str, Any]:
    metadata = github_repository_metadata()
    repositories = []
    for remote, full_name in REPOSITORIES.items():
        configured_url = run(["git", "remote", "get-url", remote]).strip()
        expected_url = f"https://github.com/{full_name}.git"
        if configured_url != expected_url:
            raise AssertionError((remote, configured_url, expected_url))
        branches = parse_ls_remote(
            run(["git", "ls-remote", "--heads", remote]),
            "refs/heads/",
        )
        pr_heads = parse_ls_remote(
            run(["git", "ls-remote", remote, "refs/pull/*/head"]),
            "refs/pull/",
        )
        normalized_pr_heads = []
        for row in pr_heads:
            number, suffix = row["ref"].split("/", 1)
            if suffix != "head" or not number.isdigit():
                raise AssertionError(row["ref"])
            normalized_pr_heads.append({"number": int(number), "sha": row["sha"]})
        normalized_pr_heads.sort(key=lambda row: row["number"])
        repo_metadata = metadata[full_name]
        default_branch = (repo_metadata["defaultBranchRef"] or {}).get("name")
        if default_branch != "main":
            raise AssertionError((full_name, default_branch))
        main = next((row for row in branches if row["ref"] == "main"), None)
        if main is None:
            raise AssertionError(f"{full_name} has no main branch")
        repositories.append(
            {
                "remote": remote,
                "repository": full_name,
                "private": repo_metadata["isPrivate"],
                "archived": repo_metadata["isArchived"],
                "default_branch": default_branch,
                "main_sha": main["sha"],
                "branch_count": len(branches),
                "branches": branches,
                "pr_head_count": len(normalized_pr_heads),
                "pr_heads": normalized_pr_heads,
            }
        )
    active_branches = sum(row["branch_count"] for row in repositories)
    pr_head_refs = sum(row["pr_head_count"] for row in repositories)
    return {
        "schema_version": 1,
        "audit_date": audit_date,
        "organization": ORGANIZATION,
        "repository_count": len(repositories),
        "repositories": repositories,
        "counts": {
            "active_branches": active_branches,
            "preserved_pr_heads": pr_head_refs,
            "total_refs": active_branches + pr_head_refs,
            "note": "branch and PR-head categories may point to the same commit",
        },
        "latest_public_pr": latest_public_pr(),
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
            raise SystemExit("REPOSITORY_SCOPE_VERIFY_FAILED: live refs changed")
        status = "verified"

    print(
        json.dumps(
            {
                "status": status,
                "repository_count": snapshot["repository_count"],
                **snapshot["counts"],
                "latest_public_pr": snapshot["latest_public_pr"]["number"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
