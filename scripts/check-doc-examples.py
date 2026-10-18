#!/usr/bin/env python3
"""Check that README code blocks are verbatim regions of compiled examples.

A README block is introduced by `<!-- example: PATH NAME -->`. PATH is a Gleam
source file whose `// docs:begin NAME` ... `// docs:end NAME` lines delimit the
region the block must equal. Every region in the examples directory must be
shown by some README block, so neither side can drift or be forgotten.
"""

import argparse
from pathlib import Path
import re
import sys

MARKER = re.compile(r"^<!-- example: (\S+) (\S+) -->$")
BEGIN = re.compile(r"^// docs:begin (\S+)$")
END = re.compile(r"^// docs:end (\S+)$")


def regions(source: Path) -> dict[str, str]:
    found: dict[str, list[str]] = {}
    open_name = None
    for line in source.read_text().splitlines():
        if (begin := BEGIN.match(line)) is not None:
            open_name = begin.group(1)
            found[open_name] = []
        elif (end := END.match(line)) is not None:
            open_name = None if open_name == end.group(1) else open_name
        elif open_name is not None:
            found[open_name].append(line)
    return {name: "\n".join(lines).strip("\n") for name, lines in found.items()}


def blocks(document: Path) -> list[tuple[str, str, str]]:
    """The (path, name, code) of every marked fence in a Markdown file."""
    lines = document.read_text().splitlines()
    shown = []
    for index, line in enumerate(lines):
        marker = MARKER.match(line)
        if marker is None:
            continue
        rest = lines[index + 1 :]
        start = next((n for n, text in enumerate(rest) if text == "```gleam"), None)
        if start is None or any(rest[:start]):
            shown.append((marker.group(1), marker.group(2), None))
            continue
        end = next((n for n, text in enumerate(rest[start + 1 :]) if text == "```"), None)
        code = None if end is None else "\n".join(rest[start + 1 : start + 1 + end])
        shown.append((marker.group(1), marker.group(2), code))
    return shown


def check(root: Path, documents: list[Path], examples: Path) -> list[str]:
    problems = []
    used = set()
    for document in documents:
        for path, name, code in blocks(document):
            label = f"{document.relative_to(root)}: example {path} {name}"
            source = root / path
            if not source.is_file():
                problems.append(f"{label}: no such file")
            elif name not in (available := regions(source)):
                problems.append(f"{label}: no `docs:begin {name}` region")
            elif code is None:
                problems.append(f"{label}: no ```gleam block follows the marker")
            elif code.strip("\n") != available[name]:
                problems.append(f"{label}: block differs from the compiled region")
                used.add((path, name))
            else:
                used.add((path, name))
    for source in sorted(examples.glob("**/*.gleam")):
        relative = str(source.relative_to(root))
        for name in regions(source):
            if (relative, name) not in used:
                problems.append(f"{relative}: region `{name}` is shown by no README block")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--examples", default="consumer/src/warden_reference/usage")
    parser.add_argument("documents", nargs="*", default=["README.md"])
    args = parser.parse_args()
    root = args.root.resolve()
    problems = check(root, [root / name for name in args.documents], root / args.examples)
    for problem in problems:
        print(f"check-doc-examples: {problem}", file=sys.stderr)
    if not problems:
        print("doc examples: ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
