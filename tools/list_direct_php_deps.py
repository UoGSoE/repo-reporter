#!/usr/bin/env python3
"""
Quick debug utility: list unique direct PHP (composer) dependencies across repos.

Usage:
  uv run tools/list_direct_php_deps.py --repos-file test_repos.txt

Notes:
  - Clones each repo to a temp dir via `gh repo clone` (depth=1).
  - Reads composer.json at the repo root only.
  - Counts only direct production dependencies from `require`.
  - Excludes `php` and `ext-*` virtual requirements.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import List, Tuple


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="List unique direct composer dependencies across repos")
    p.add_argument("--repos-file", type=Path, default=Path("test_repos.txt"), help="Path to file with GitHub repo URLs")
    p.add_argument("--keep", action="store_true", help="Keep temp clones (for inspection)")
    return p.parse_args()


def normalize_repo_target(url: str) -> str:
    if url.startswith("https://github.com/"):
        return url.replace("https://github.com/", "").replace(".git", "")
    if url.startswith("git@github.com:"):
        return url.replace("git@github.com:", "").replace(".git", "")
    return url


def read_repos(file: Path) -> List[str]:
    lines = [l.strip() for l in file.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]
    return lines


def clone_repo(target: str, dest: Path) -> Tuple[bool, str]:
    try:
        # shallow clone for speed
        subprocess.run([
            "gh", "repo", "clone", target, str(dest), "--", "--depth", "1"
        ], check=True, text=True, capture_output=True, timeout=60)
        return True, ""
    except subprocess.CalledProcessError as e:
        return False, e.stderr or e.stdout or str(e)
    except Exception as e:
        return False, str(e)


def collect_direct_require(composer_json: Path) -> List[str]:
    try:
        data = json.loads(composer_json.read_text())
    except Exception:
        return []
    req = data.get("require", {}) or {}
    names: List[str] = []
    for name in req.keys():
        if name.startswith("php") or name.startswith("ext-"):
            continue
        names.append(name)
    return names


def main() -> int:
    args = parse_args()
    repos_file = args.repos_file
    if not repos_file.exists():
        print(f"Repos file not found: {repos_file}", file=sys.stderr)
        return 1

    repos = read_repos(repos_file)
    if not repos:
        print("No repositories listed", file=sys.stderr)
        return 1

    tmp_root = Path(tempfile.mkdtemp(prefix="composer-deps-"))
    all_unique = set()
    per_repo_counts = Counter()
    processed = 0
    with_composer = 0

    try:
        for url in repos:
            processed += 1
            target = normalize_repo_target(url)
            repo_dir = tmp_root / re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
            ok, err = clone_repo(target, repo_dir)
            if not ok:
                print(f"[skip] clone failed for {target}: {err}")
                continue
            composer = repo_dir / "composer.json"
            if not composer.exists():
                print(f"[skip] {target}: no composer.json")
                continue
            with_composer += 1
            direct = set(collect_direct_require(composer))
            for name in sorted(direct):
                all_unique.add(name)
                per_repo_counts[name] += 1

        # Summary
        print("\n=== Composer Direct Dependencies Summary ===")
        print(f"Repos processed: {processed}")
        print(f"Repos with composer.json: {with_composer}")
        print(f"Unique direct dependencies: {len(all_unique)}\n")

        print("Top dependencies (by repo usage):")
        for name, cnt in per_repo_counts.most_common(50):
            print(f"- {name}: {cnt}")

        print("\nFull list (sorted):")
        for name in sorted(all_unique):
            print(f"- {name}")

        return 0
    finally:
        if args.keep:
            print(f"Temp clones kept at: {tmp_root}")
        else:
            shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

