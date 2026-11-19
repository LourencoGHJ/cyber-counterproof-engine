#!/usr/bin/env python3
"""Read-only GitHub repository security hygiene auditor.

Uses GitHub REST API GET requests only. No repository or account changes are made.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"

WORKFLOW_HINTS = {
    "CI": ("ci.yml", "tests.yml", "test.yml"),
    "CodeQL": ("codeql.yml", "codeql-analysis.yml"),
    "Secret scanning": ("secrets.yml", "secret-scanning.yml", "gitleaks.yml"),
    "Dependency review or updates": ("dependabot.yml", "dependency-review.yml"),
    "Container scanning": ("container-security.yml", "trivy.yml"),
}


class GitHubAPIError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def request_json(path: str, token: str | None) -> Any:
    url = API_ROOT + path
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "github-security-auditor/0.2",
    }

    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise GitHubAPIError(
            f"GitHub API returned HTTP {exc.code}: {detail}", exc.code
        ) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise GitHubAPIError(f"Network/API request failed: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise GitHubAPIError("GitHub API returned invalid JSON") from exc


def check_result(
    name: str,
    status: str,
    details: str,
    url: str | None = None,
) -> dict[str, str | None]:
    return {
        "check": name,
        "status": status,
        "details": details,
        "evidence_url": url,
    }


def audit(
    owner: str,
    repo: str,
    token: str | None,
    ref: str | None = None,
) -> dict[str, Any]:

    base = f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"
    metadata = request_json(base, token)

    default_branch = metadata.get("default_branch", "main")
    audited_ref = ref or default_branch

    # Query parameter encoding and browser URL encoding are handled separately.
    ref_query = urllib.parse.quote(audited_ref, safe="")
    ref_url = urllib.parse.quote(audited_ref, safe="/")

    html_url = metadata.get(
        "html_url", f"https://github.com/{owner}/{repo}"
    )

    checks: list[dict[str, str | None]] = []

    security_url = f"{html_url}/blob/{ref_url}/SECURITY.md"

    try:
        request_json(
            base + "/contents/SECURITY.md?ref=" + ref_query,
            token,
        )
        checks.append(
            check_result(
                "Security policy (SECURITY.md)",
                "present",
                f"SECURITY.md exists on ref '{audited_ref}'.",
                security_url,
            )
        )
    except GitHubAPIError as exc:
        if exc.status == 404:
            checks.append(
                check_result(
                    "Security policy (SECURITY.md)",
                    "missing",
                    f"No SECURITY.md was found at the repository root on ref '{audited_ref}'.",
                    security_url,
                )
            )
        else:
            checks.append(
                check_result(
                    "Security policy (SECURITY.md)",
                    "unknown",
                    str(exc),
                    security_url,
                )
            )

    workflow_path = (
        base
        + "/contents/.github/workflows?ref="
        + ref_query
    )

    workflow_url = (
        f"{html_url}/tree/{ref_url}/.github/workflows"
    )

    try:
        entries = request_json(workflow_path, token)

        names = {
            entry.get("name", "")
            for entry in entries
            if isinstance(entry, dict)
        }
        paths = {
            entry.get("path", "").split("/")[-1]
            for entry in entries
            if isinstance(entry, dict)
        }

        for label, hints in WORKFLOW_HINTS.items():
            matches = sorted(set(hints) & (names | paths))

            if matches:
                checks.append(
                    check_result(
                        f"{label} workflow",
                        "present",
                        "Found: " + ", ".join(matches),
                        workflow_url,
                    )
                )
            else:
                checks.append(
                    check_result(
                        f"{label} workflow",
                        "unknown",
                        "No matching conventional filename found. "
                        "Equivalent controls may use another filename or location.",
                        workflow_url,
                    )
                )

    except GitHubAPIError as exc:
        for label in WORKFLOW_HINTS:
            checks.append(
                check_result(
                    f"{label} workflow",
                    "unknown",
                    str(exc),
                    workflow_url,
                )
            )

    return {
        "tool": "GitHub Security Auditor",
        "version": "0.2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": metadata.get(
            "full_name", f"{owner}/{repo}"
        ),
        "repository_url": html_url,
        "default_branch": default_branch,
        "audited_ref": audited_ref,
        "visibility": metadata.get("visibility", "unknown"),
        "checks": checks,
        "limitations": [
            "This is a read-only hygiene check, not a complete security audit.",
            "Workflow filename matching is heuristic and cannot prove that a control is correctly configured.",
            "Private security alerts are not queried in this version; their visibility depends on token permissions and repository settings.",
            "A missing or inaccessible resource is reported separately from a confirmed absence where possible.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only security hygiene audit using the GitHub REST API."
    )
    parser.add_argument(
        "--owner",
        required=True,
        help="GitHub account or organization",
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Repository name",
    )
    parser.add_argument(
        "--ref",
        help="Branch, tag, or commit to audit (default: repository default branch)",
    )
    parser.add_argument(
        "--output",
        help="Write JSON report to this path (default: stdout)",
    )

    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN")

    try:
        report = audit(
            args.owner,
            args.repo,
            token,
            args.ref,
        )
    except GitHubAPIError as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(
        report,
        indent=2,
        ensure_ascii=False,
    ) + "\n"

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
    else:
        sys.stdout.write(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
