#!/usr/bin/env python3
"""
Validate that environment variables used in code are documented.

Behavior:

- Only processes "src" and "docs" directories.
- Starting from the given root (or '.'), walks *up* until it finds a directory
  containing "src" and/or "docs". Uses that as the project root.
- If nothing is found up to filesystem root, uses the starting directory and
  any src/docs beneath it (if present).

Python scan (under src only):
  - os.environ["VAR"]
  - self.environ["VAR"]
  - os.getenv("VAR")
  - self.getenv("VAR")
  - self.getenv_int("VAR")
Where VAR: first 3 chars uppercase letters, then [A-Z0-9_]*

Documentation scan (under src and docs):
  - Markdown files: *.md
      * Markdown tables: backticked items like:
            `VAR`
            `VAR=VALUE`
      * Fenced code blocks (``` or ~~~):
            VAR=VALUE
            VAR = VALUE
  - Env-style files: .env* (e.g. .env, .env.example, .env.local, etc.)
      * Any line containing: VAR=VALUE / VAR = VALUE

Where VAR follows same pattern (first 3 uppercase chars).

Output JSON:
{
  "used_and_documented": [...],
  "used_but_undocumented": [...],
  "documented_but_unused": [...]
}
"""

import argparse
import json
import re
from pathlib import Path
from typing import Iterable, Set

# Common env var name pattern: first 3 uppercase letters, then A-Z0-9_*
ENV_NAME_GROUP = r"([A-Z]{3}[A-Z0-9_]*)"

# Regexes to capture env var names (group 2) from Python code
PY_ENV_PATTERNS = [
    re.compile(r"environ\[\s*(['\"])" + ENV_NAME_GROUP + r"\1\s*]"),
    re.compile(r"get_?env\(\s*(['\"])" + ENV_NAME_GROUP + r"\1"),
    re.compile(r"get_?env_int\(\s*(['\"])" + ENV_NAME_GROUP + r"\1"),
    re.compile(r"get_?env_float\(\s*(['\"])" + ENV_NAME_GROUP + r"\1"),
    re.compile(r"get_?env_bool\(\s*(['\"])" + ENV_NAME_GROUP + r"\1"),
    re.compile(r"env_reader\.get\(\s*(['\"])" + ENV_NAME_GROUP + r"\1"),
    re.compile(r"env_reader\.get_int\(\s*(['\"])" + ENV_NAME_GROUP + r"\1"),
    re.compile(r"env_reader\.get_float\(\s*(['\"])" + ENV_NAME_GROUP + r"\1"),
    re.compile(r"env_reader\.get_bool\(\s*(['\"])" + ENV_NAME_GROUP + r"\1"),
]

# Markdown: `VAR` or `VAR=VALUE` inside table rows
MD_TABLE_BACKTICK_ENV = re.compile(r"`" + ENV_NAME_GROUP + r"(?:\s*=[^`]*)?`")

# Code-style assignment: VAR=something (spaces allowed around '=')
MD_CODE_ENV_ASSIGN = re.compile(r"\b" + ENV_NAME_GROUP + r"\s*=")


def find_project_root(start: Path) -> Path:
    """
    Walk up from 'start' until a directory containing 'src' and/or 'docs'
    is found. If none is found, return the original start.
    """
    start = start.resolve()
    cur = start

    while True:
        has_src = (cur / "src").is_dir()
        has_docs = (cur / "docs").is_dir()
        if has_src or has_docs:
            return cur

        if cur.parent == cur:  # reached filesystem root
            return start
        cur = cur.parent


def collect_used_env_vars(code_dirs: Iterable[Path]) -> Set[str]:
    used: Set[str] = set()

    for base in code_dirs:
        if not base.is_dir():
            continue
        for path in base.rglob("*.py"):
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            for pattern in PY_ENV_PATTERNS:
                for match in pattern.finditer(text):
                    # group(1) is the quote, group(2) is the env var name
                    var_name = match.group(2)
                    used.add(var_name)

    return used


def collect_documented_env_vars(doc_dirs: Iterable[Path]) -> Set[str]:
    documented: Set[str] = set()

    for base in doc_dirs:
        if base.is_dir():
            md_files = list(base.rglob("*.md"))
            env_files = list(base.rglob(".env*"))
        else:
            if base.name.endswith(".md"):
                md_files = [base]
                env_files = []
            elif base.name.startswith(".env"):
                md_files = []
                env_files = [base]
            else:
                continue

        # Process Markdown files
        for path in md_files:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            lines = text.splitlines()
            in_code_block = False

            for line in lines:
                stripped = line.strip()

                # Toggle fenced code blocks: ``` or ~~~
                if stripped.startswith("```") or stripped.startswith("~~~"):
                    in_code_block = not in_code_block
                    continue

                # 1) Markdown backticked VAR or VAR=VALUE
                for m in MD_TABLE_BACKTICK_ENV.finditer(line):
                    documented.add(m.group(1))

                # 2) Code blocks: VAR=VALUE / VAR = VALUE
                if in_code_block:
                    for m in MD_CODE_ENV_ASSIGN.finditer(line):
                        documented.add(m.group(1))

        # Process .env* files (treat entire file as "code")
        for path in env_files:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            for line in text.splitlines():
                for m in MD_CODE_ENV_ASSIGN.finditer(line):
                    documented.add(m.group(1))

    return documented


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate that environment variables used in code match documentation."
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Starting directory (default: current directory). "
             "The script will walk up to find src/docs.",
    )
    args = parser.parse_args()

    start = Path(args.root).resolve()
    project_root = find_project_root(start)

    src_dir = project_root / "src"
    docs_dir = project_root / "docs"

    code_dirs = [src_dir] if src_dir.is_dir() else []

    # Include both src_dir and docs_dir when collecting documented vars
    doc_dirs = []
    if docs_dir.is_dir():
        doc_dirs.append(docs_dir)
        doc_dirs.append(Path(docs_dir, "..", ".env.example"))
    if src_dir.is_dir():
        doc_dirs.append(src_dir)

    used = collect_used_env_vars(code_dirs)
    documented = collect_documented_env_vars(doc_dirs)

    used_and_documented = sorted(used & documented)
    used_but_undocumented = sorted(used - documented)
    documented_but_unused = sorted(documented - used)

    result = {
        "used_and_documented": used_and_documented,
        "used_but_undocumented": used_but_undocumented,
        "documented_but_unused": documented_but_unused,
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
