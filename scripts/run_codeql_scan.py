#!/usr/bin/env python3
"""Run the CodeQL JS scan pipeline in a cross-platform way.

This script mirrors scripts/run_codeql_scan.sh but is designed to work on Windows
by invoking the CodeQL CLI executable directly.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

JS_TS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}


def resolve_codeql_bin(cli_arg: str | None) -> str | None:
    if cli_arg:
        return cli_arg

    env_bin = os.environ.get("CODEQL_BIN", "").strip()
    if env_bin:
        return env_bin

    for name in ("codeql", "codeql.exe"):
        found = shutil.which(name)
        if found:
            return found

    return None


def count_js_ts_files(target_dir: Path) -> int:
    count = 0
    for p in target_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in JS_TS_SUFFIXES:
            count += 1
    return count


def run_cmd(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CodeQL JS scan and produce SARIF/tree reports")
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target directory to scan (default: repository root)",
    )
    parser.add_argument(
        "--codeql",
        dest="codeql_bin",
        default=None,
        help="Path to CodeQL CLI executable (default: CODEQL_BIN or PATH lookup)",
    )
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parent.parent
    if args.target == ".":
        target_dir = root_dir
    else:
        target_dir = Path(args.target)
        if not target_dir.is_absolute():
            target_dir = (Path.cwd() / target_dir).resolve()

    if not target_dir.is_dir():
        alt = (root_dir / args.target).resolve()
        if alt.is_dir():
            target_dir = alt
        else:
            print(f"[error] target directory does not exist: {target_dir}")
            return 1

    codeql_bin = resolve_codeql_bin(args.codeql_bin)
    if not codeql_bin:
        print("[error] codeql CLI not found")
        print("hint: set CODEQL_BIN to codeql executable path, pass --codeql, or add codeql to PATH")
        return 1

    js_file_count = count_js_ts_files(target_dir)
    if js_file_count == 0:
        print(f"[error] no JavaScript/TypeScript source files found under: {target_dir}")
        print("hint: this query pack is JavaScript-specific (.env/process.env flow).")
        print("hint: run against a JS/TS project path, for example:")
        print("      python scripts/run_codeql_scan.py examples/js-demo")
        return 2

    db_dir = root_dir / ".codeql-db-js"
    query_file = root_dir / "queries" / "javascript-security-and-quality" / "env-to-exfil.ql"
    query_pack_dir = root_dir / "queries" / "javascript-security-and-quality"
    sarif_out = root_dir / "output" / "env-flow.sarif"
    json_out = root_dir / "output" / "env-flow-tree.json"
    md_out = root_dir / "output" / "env-flow-report.md"

    shutil.rmtree(db_dir, ignore_errors=True)
    (root_dir / "output").mkdir(parents=True, exist_ok=True)

    try:
        print(f"[1/4] Creating CodeQL database from: {target_dir}")
        run_cmd(
            [
                codeql_bin,
                "database",
                "create",
                str(db_dir),
                "--language=javascript",
                "--source-root",
                str(target_dir),
            ]
        )

        (db_dir / "results").mkdir(parents=True, exist_ok=True)

        print("[2/4] Installing query pack dependencies")
        run_cmd([codeql_bin, "pack", "install", str(query_pack_dir)])

        print("[3/4] Analyzing with custom query")
        run_cmd(
            [
                codeql_bin,
                "database",
                "analyze",
                str(db_dir),
                str(query_file),
                "--format=sarif-latest",
                "--output",
                str(sarif_out),
                "--threads=0",
            ]
        )

        print("[4/4] Building triage-friendly tree report")
        run_cmd(
            [
                sys.executable,
                str(root_dir / "scripts" / "sarif_to_tree.py"),
                str(sarif_out),
                str(json_out),
                str(md_out),
            ]
        )
    except subprocess.CalledProcessError as exc:
        print(f"[error] command failed with exit code {exc.returncode}: {' '.join(exc.cmd)}")
        return exc.returncode or 1

    print("Done")
    print(f"- SARIF: {sarif_out}")
    print(f"- Tree JSON: {json_out}")
    print(f"- Analyst report: {md_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
