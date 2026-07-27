#!/usr/bin/env python3
"""Reject generated runtime artifacts and protected-tree edits."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path, PurePosixPath

FORBIDDEN_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "dist", "build"}
FORBIDDEN_SUFFIXES = (".pyc", ".pyo", ".db", ".db-wal", ".db-shm", ".log", ".tar.gz")
RUNTIME_PREFIXES = ("storage/sqlite/", "storage/update/")
PLACEHOLDERS = {"storage/sqlite/.gitkeep", "storage/update/.gitkeep"}


def main() -> int:
    tracked = subprocess.run(
        ["git", "ls-files"], check=True, capture_output=True, text=True
    ).stdout.splitlines()
    violations: list[str] = []
    for name in tracked:
        path = PurePosixPath(name)
        runtime_artifact = name.startswith(RUNTIME_PREFIXES) and name not in PLACEHOLDERS
        forbidden = (
            any(part in FORBIDDEN_PARTS for part in path.parts)
            or name.endswith(FORBIDDEN_SUFFIXES)
            or runtime_artifact
        )
        if forbidden:
            violations.append(name)
    if violations:
        print("Tracked Gateway runtime/build artifacts are not allowed:")
        print("\n".join(f"- {name}" for name in violations))
        return 1
    missing = sorted(name for name in PLACEHOLDERS if name not in tracked and not Path(name).is_file())
    if missing:
        print("Required runtime directory placeholders are missing:")
        print("\n".join(f"- {name}" for name in missing))
        return 1
    print("Gateway repository hygiene check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
