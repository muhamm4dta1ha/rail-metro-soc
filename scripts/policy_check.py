#!/usr/bin/env python3
"""Repository policy checks used by CI (stdlib only, runnable locally).

  python scripts/policy_check.py branch --head feature/sim/M1-04-pis --base develop
  python scripts/policy_check.py attribution --file commit_messages.txt
  python scripts/policy_check.py files --base <sha> --head <sha> --max-mb 10

Exit code 0 = ok, 1 = policy violation, 2 = tool error.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

MODULES = "common|sim|attacks|detection|ml|docs|ci|repo"
BRANCH_RE = re.compile(rf"^(feature|fix|docs|chore|test)/({MODULES})/[A-Za-z0-9][A-Za-z0-9._-]*$")

# HC-15: no AI assistant is a contributor. Add patterns here if the team widens the rule.
AI_ATTRIBUTION_PATTERNS = (
    re.compile(r"(?i)^\s*co-authored-by:.*(claude|anthropic)"),
    re.compile(r"(?i)generated (?:with|by)\b.*(claude|anthropic)"),
    re.compile(r"(?i)noreply@anthropic\.com"),
)

# HC-20: no secrets in git.
FORBIDDEN_FILE_PATTERNS = (
    re.compile(r"(^|/)\.env$"),
    re.compile(r"\.(pem|key|p12|pfx|kdbx)$", re.IGNORECASE),
    re.compile(r"(^|/)id_(rsa|ed25519|ecdsa)$"),
)


def check_branch(head: str, base: str) -> list[str]:
    """Branch flow (HC-14): feature branches -> develop; only develop -> main."""
    if base == "develop":
        if BRANCH_RE.match(head):
            return []
        return [
            f"branch '{head}' is not allowed to target develop. Name it "
            f"<feature|fix|docs|chore|test>/<{MODULES}>/<TASK-ID>-<slug>, "
            "e.g. feature/sim/M1-04-pis-service"
        ]
    if base == "main":
        if head == "develop":
            return []
        return [f"PRs into main must come from 'develop' (release flow), not '{head}'"]
    return [f"PRs must target 'develop' (or 'main' for releases), not '{base}'"]


def find_ai_attribution(text: str) -> list[str]:
    """Return the lines that credit an AI assistant as author/contributor (HC-15)."""
    return [
        line.strip()
        for line in text.splitlines()
        if any(pattern.search(line) for pattern in AI_ATTRIBUTION_PATTERNS)
    ]


def check_files(paths: list[str], root: Path, max_bytes: int) -> list[str]:
    """Reject secret-looking files and oversized files (HC-20)."""
    errors: list[str] = []
    for rel in paths:
        norm = rel.replace("\\", "/")
        if any(pattern.search(norm) for pattern in FORBIDDEN_FILE_PATTERNS):
            errors.append(f"{rel}: looks like a secret/credential file - never commit it (HC-20)")
        candidate = root / rel
        if candidate.is_file() and candidate.stat().st_size > max_bytes:
            size_mb = candidate.stat().st_size / (1024 * 1024)
            errors.append(
                f"{rel}: {size_mb:.1f} MB exceeds the limit - keep big files outside git (HC-20)"
            )
    return errors


def _changed_files(base: str, head: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=AM", f"{base}...{head}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"git diff failed: {result.stderr.strip()}")
    return [line for line in result.stdout.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    branch = sub.add_parser("branch", help="check branch naming and PR flow")
    branch.add_argument("--head", required=True)
    branch.add_argument("--base", required=True)

    attribution = sub.add_parser("attribution", help="reject AI co-author / generated-by lines")
    attribution.add_argument("--file", required=True, help="text file with commit messages + PR text")

    files = sub.add_parser("files", help="reject secrets and oversized files in a PR")
    files.add_argument("--base", required=True)
    files.add_argument("--head", required=True)
    files.add_argument("--max-mb", type=float, default=10.0)

    args = parser.parse_args(argv)

    if args.cmd == "branch":
        errors = check_branch(args.head, args.base)
    elif args.cmd == "attribution":
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        errors = [f"AI attribution is not allowed (HC-15): {hit}" for hit in find_ai_attribution(text)]
    else:
        names = _changed_files(args.base, args.head)
        errors = check_files(names, Path.cwd(), int(args.max_mb * 1024 * 1024))

    for error in errors:
        print(f"POLICY VIOLATION: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
