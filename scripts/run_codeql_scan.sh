#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${1:-$ROOT_DIR}"
DB_DIR="$ROOT_DIR/.codeql-db-js"
QUERY_FILE="$ROOT_DIR/queries/javascript-security-and-quality/env-to-exfil.ql"
QUERY_PACK_DIR="$ROOT_DIR/queries/javascript-security-and-quality"
SARIF_OUT="$ROOT_DIR/output/env-flow.sarif"
JSON_OUT="$ROOT_DIR/output/env-flow-tree.json"
MD_OUT="$ROOT_DIR/output/env-flow-report.md"

if [[ ! -d "$TARGET_DIR" ]]; then
  # Convenience: allow paths relative to repository root even when invoked from scripts/.
  if [[ -d "$ROOT_DIR/$TARGET_DIR" ]]; then
    TARGET_DIR="$ROOT_DIR/$TARGET_DIR"
  else
    echo "[error] target directory does not exist: $TARGET_DIR"
    exit 1
  fi
fi

CODEQL_BIN="${CODEQL_BIN:-}"
if [[ -z "$CODEQL_BIN" ]]; then
  if command -v codeql >/dev/null 2>&1; then
    CODEQL_BIN="$(command -v codeql)"
  elif [[ -x "$HOME/.local/bin/codeql" ]]; then
    CODEQL_BIN="$HOME/.local/bin/codeql"
  elif [[ -x "/home/jaehojeon/.local/bin/codeql" ]]; then
    CODEQL_BIN="/home/jaehojeon/.local/bin/codeql"
  fi
fi

if [[ -z "$CODEQL_BIN" ]]; then
  echo "[error] codeql CLI not found"
  echo "hint: set CODEQL_BIN=/absolute/path/to/codeql or install to ~/.local/bin/codeql"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[error] python3 not found in PATH"
  exit 1
fi

JS_FILE_COUNT=$(find "$TARGET_DIR" -type f \( -name "*.js" -o -name "*.jsx" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.ts" -o -name "*.tsx" \) | wc -l | tr -d ' ')
if [[ "$JS_FILE_COUNT" -eq 0 ]]; then
  echo "[error] no JavaScript/TypeScript source files found under: $TARGET_DIR"
  echo "hint: this query pack is JavaScript-specific (.env/process.env flow)."
  echo "hint: run against a JS/TS project path, for example:"
  echo "      ./run_codeql_scan.sh /path/to/npm-package-or-node-repo"
  exit 2
fi

rm -rf "$DB_DIR"
mkdir -p "$ROOT_DIR/output"

echo "[1/4] Creating CodeQL database from: $TARGET_DIR"
"$CODEQL_BIN" database create "$DB_DIR" \
  --language=javascript \
  --source-root "$TARGET_DIR"

# Some environments fail to create this eagerly; ensure it exists before analyze writes run-info.
mkdir -p "$DB_DIR/results"

echo "[2/4] Installing query pack dependencies"
"$CODEQL_BIN" pack install "$QUERY_PACK_DIR"

echo "[3/4] Analyzing with custom query"
"$CODEQL_BIN" database analyze "$DB_DIR" "$QUERY_FILE" \
  --format=sarif-latest \
  --output "$SARIF_OUT" \
  --threads=0

echo "[4/4] Building triage-friendly tree report"
python3 "$ROOT_DIR/scripts/sarif_to_tree.py" "$SARIF_OUT" "$JSON_OUT" "$MD_OUT"

echo "Done"
echo "- SARIF: $SARIF_OUT"
echo "- Tree JSON: $JSON_OUT"
echo "- Analyst report: $MD_OUT"
