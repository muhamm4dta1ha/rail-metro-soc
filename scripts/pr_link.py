#!/usr/bin/env python3
"""Print GitHub "open a pull request" links for local branches.

This tool only PRINTS links. It never pushes, never calls the GitHub API and never opens a
browser: humans (not AI assistants) push branches and click the link (hard constraint HC-15).

Examples
  python scripts/pr_link.py                # current branch -> develop
  python scripts/pr_link.py --all          # every local feature/fix/docs/chore/test branch ahead of develop
  python scripts/pr_link.py --release      # develop -> main (milestone release)
  python scripts/pr_link.py --repo OWNER/rail-metro-soc --head feature/sim/M1-04-pis --title "feat(sim): M1-04 PIS"
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

DEFAULT_BASE = "develop"
RELEASE_BASE = "main"
MAX_URL_LEN = 7500  # GitHub rejects very long query strings

TYPE_MAP = {"feature": "feat", "fix": "fix", "docs": "docs", "chore": "chore", "test": "test"}
SCOPE_MAP = {
    "common": "common",
    "sim": "sim",
    "attacks": "attacks",
    "detection": "detect",
    "ml": "ml",
    "docs": "docs",
    "ci": "ci",
    "repo": "repo",
}
REMOTE_RE = re.compile(
    r"^(?:https?://(?:[^@/]+@)?github\.com/|git@github\.com:|ssh://git@github\.com/)"
    r"(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+?)(?:\.git)?/?$"
)
BRANCH_RE = re.compile(r"^(?P<type>[a-z]+)/(?P<scope>[a-z]+)/(?P<rest>.+)$")
TASK_RE = re.compile(r"^(?P<id>[A-Z]{1,2}\d?-\d{2})(?:[-_](?P<slug>.*))?$")


def parse_remote_url(url: str) -> str:
    """Return OWNER/REPO from an https or ssh GitHub remote URL."""
    match = REMOTE_RE.match(url.strip())
    if not match:
        raise ValueError(f"not a GitHub remote URL: {url!r}")
    return f"{match['owner']}/{match['repo']}"


def suggest_title(branch: str) -> str:
    """feature/sim/M1-04-pis-service -> 'feat(sim): M1-04 pis service' (Conventional Commits)."""
    match = BRANCH_RE.match(branch)
    if not match:
        return branch.replace("-", " ").replace("_", " ")
    kind = TYPE_MAP.get(match["type"], "chore")
    scope = SCOPE_MAP.get(match["scope"], match["scope"])
    rest = match["rest"]
    task = TASK_RE.match(rest)
    if task:
        slug = (task["slug"] or "").replace("-", " ").replace("_", " ").strip()
        summary = f"{task['id']} {slug}".strip()
    else:
        summary = rest.replace("-", " ").replace("_", " ")
    return f"{kind}({scope}): {summary}"


def build_url(
    repo: str, base: str, head: str, title: str | None = None, body: str | None = None
) -> str:
    """GitHub compare URL that opens the 'create pull request' form (template auto-applies)."""
    url = f"https://github.com/{repo}/compare/{quote(base, safe='')}...{quote(head, safe='/')}"
    params = ["expand=1"]
    if title:
        params.append("title=" + quote(title, safe=""))
    if body:
        params.append("body=" + quote(body, safe=""))
    return url + "?" + "&".join(params)


def _git(*args: str) -> str:
    try:
        result = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    except FileNotFoundError:
        raise SystemExit("git is not installed or not on PATH") from None
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"git {' '.join(args)} failed: {exc.stderr.strip()}") from None
    return result.stdout.strip()


def branches_ahead(base: str) -> list[str]:
    """Local feature/fix/docs/chore/test branches that have commits not in `base`."""
    names = _git(
        "for-each-ref",
        "--format=%(refname:short)",
        "refs/heads/feature",
        "refs/heads/fix",
        "refs/heads/docs",
        "refs/heads/chore",
        "refs/heads/test",
    ).split()
    base_ref = base
    for candidate in (f"origin/{base}", base):
        try:
            _git("rev-parse", "--verify", "--quiet", candidate)
        except SystemExit:
            continue
        base_ref = candidate
        break
    return [n for n in names if int(_git("rev-list", "--count", f"{base_ref}..{n}") or 0) > 0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo", help="OWNER/REPO (default: parsed from the git remote)")
    parser.add_argument("--remote", default="origin", help="git remote to read the repo from")
    parser.add_argument("--head", help="branch to open the PR from (default: current branch)")
    parser.add_argument("--base", default=DEFAULT_BASE, help="target branch (default: develop)")
    parser.add_argument("--title", help="PR title (default: derived from the branch name)")
    parser.add_argument("--body", help="PR description (default: the PR template applies)")
    parser.add_argument("--body-file", help="read the PR description from a file")
    parser.add_argument("--release", action="store_true", help="develop -> main release PR")
    parser.add_argument("--all", action="store_true", help="links for all branches ahead of base")
    args = parser.parse_args(argv)

    repo = args.repo or parse_remote_url(_git("remote", "get-url", args.remote))
    body = Path(args.body_file).read_text(encoding="utf-8") if args.body_file else args.body

    if args.release:
        links = [("develop", RELEASE_BASE, args.title or "release: merge develop into main")]
    elif args.all:
        links = [(b, args.base, args.title or suggest_title(b)) for b in branches_ahead(args.base)]
        if not links:
            print(f"No local feature/fix/docs/chore/test branch is ahead of {args.base}.")
            return 0
    else:
        head = args.head or _git("rev-parse", "--abbrev-ref", "HEAD")
        if head in {"develop", "main"}:
            print(
                f"'{head}' cannot be the source of a feature PR. Create a branch first, e.g.\n"
                "  git switch develop && git switch -c feature/<module>/<TASK-ID>-<slug>",
                file=sys.stderr,
            )
            return 2
        links = [(head, args.base, args.title or suggest_title(head))]

    for head, base, title in links:
        url = build_url(repo, base, head, title, body)
        if len(url) > MAX_URL_LEN:
            print("(description too long for a URL - the PR template will be used instead)")
            url = build_url(repo, base, head, title)
        print(f"[{head} -> {base}]\n{url}\n")
    print("Push the branch first (git push -u origin <branch>), then open the link in a browser.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
