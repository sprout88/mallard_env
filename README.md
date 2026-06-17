# Env Flow Auditor (CodeQL)

This repository provides a CodeQL-based proof of concept for auditing supply-chain style exfiltration behavior, focused on environment variable flows.

Goal:
- Track flow from environment sources such as process.env
- Detect paths that reach exfiltration-relevant sinks (network calls, command execution)
- Generate analyst-friendly outputs beyond raw SARIF

## Why this shape

A single tree is not enough for triage. This PoC produces:
- Alert list: prioritized findings
- Path tree: source -> propagators -> sink
- Signals: suspicious vs possibly benign hints

This helps security analysts separate likely malicious behavior from operational but benign data handling.

## Repository layout

- queries/javascript-security-and-quality/env-to-exfil.ql
	- Custom CodeQL query for environment-variable-to-sink taint flow
- scripts/run_codeql_scan.sh
	- Bash runner for Unix-like environments
- scripts/run_codeql_scan.py
	- Cross-platform runner (recommended on Windows)
- scripts/sarif_to_tree.py
	- Converts SARIF to a compact JSON tree and markdown triage report
- output/
	- Generated artifacts

## Prerequisites

- CodeQL CLI installed and available on PATH
- Python 3
- Target codebase with JavaScript/TypeScript sources

## Run

Windows (Python interface):

```powershell
python scripts/run_codeql_scan.py
```

Windows (scan another path):

```powershell
python scripts/run_codeql_scan.py examples/js-demo
```

Scan the current repository:

```bash
bash scripts/run_codeql_scan.sh
```

Scan another path:

```bash
bash scripts/run_codeql_scan.sh /path/to/target/repo
```

Note:
- The custom query is JavaScript/TypeScript-focused.
- If the target directory has no .js/.ts files, the script exits early with a clear error.

## Outputs

After execution:

- output/env-flow.sarif
	- Raw CodeQL findings
- output/env-flow-tree.json
	- Structured findings for machine triage
- output/env-flow-report.md
	- Human-friendly report with flow paths and signals

## Quick demo target

This repository includes a runnable JavaScript sample target:

- examples/js-demo

Run the scanner against it:

```bash
bash scripts/run_codeql_scan.sh examples/js-demo
```

## How to interpret findings

Focus on:
- Suspicious signals
	- network sink involved
	- command execution sink involved
	- package lifecycle context suspected
- Possibly benign signals
	- internal/local endpoint
	- explicit masking/sanitization hints

High-priority review candidates are paths where:
- source is process.env-derived data
- sink is outbound network or command execution
- code path appears in install/build hooks or dynamic execution contexts

## Current limitations

- Query currently emphasizes process.env as source (can be extended for dotenv parse/populate variants)
- Sink modeling is intentionally focused on common high-risk APIs
- Signal classification is heuristic and designed for triage, not final verdict

## Next hardening steps

- Add dotenv-specific sources:
	- dotenv.config(...).parsed
	- dotenv.parse(...)
- Add more sinks:
	- websocket/send APIs
	- custom HTTP client wrappers
- Add allowlist policy:
	- approved domains
	- approved internal telemetry paths
- Add CI gating with severity threshold
