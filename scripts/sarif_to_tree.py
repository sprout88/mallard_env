#!/usr/bin/env python3
"""Convert CodeQL SARIF output into a triage-oriented tree report.

Usage:
  python3 scripts/sarif_to_tree.py in.sarif out.json out.md
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def severity_from_result(result: dict[str, Any]) -> str:
    level = (result.get("level") or "warning").lower()
    if level == "error":
        return "high"
    if level == "warning":
        return "medium"
    return "low"


def get_rule_name(run: dict[str, Any], rule_id: str) -> str:
    tool = run.get("tool", {})
    driver = tool.get("driver", {})
    rules = driver.get("rules", [])
    for rule in rules:
        if rule.get("id") == rule_id:
            short = rule.get("shortDescription", {})
            return short.get("text") or rule_id
    return rule_id


def location_to_dict(loc: dict[str, Any]) -> dict[str, Any]:
    physical = loc.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})
    msg = loc.get("message", {})
    return {
        "uri": artifact.get("uri", "unknown"),
        "line": region.get("startLine", 1),
        "column": region.get("startColumn", 1),
        "message": msg.get("text", ""),
    }


def extract_path(result: dict[str, Any]) -> list[dict[str, Any]]:
    code_flows = result.get("codeFlows", [])
    if not code_flows:
        return []

    thread_flows = code_flows[0].get("threadFlows", [])
    if not thread_flows:
        return []

    locations = thread_flows[0].get("locations", [])
    path = []
    for entry in locations:
        loc = entry.get("location", {})
        path.append(location_to_dict(loc))
    return path


def classify_signals(path: list[dict[str, Any]]) -> dict[str, list[str]]:
    suspicious = []
    benign = []

    flat = " ".join((step.get("message") or "").lower() for step in path)
    flat += " " + " ".join((step.get("uri") or "").lower() for step in path)

    if any(k in flat for k in ["fetch", "axios", "http", "https", "request"]):
        suspicious.append("network sink involved")
    if any(k in flat for k in ["exec", "execsync", "child_process"]):
        suspicious.append("command execution sink involved")
    if any(k in flat for k in ["postinstall", "preinstall", "prepare"]):
        suspicious.append("package lifecycle context suspected")

    if any(k in flat for k in ["internal", "localhost", "127.0.0.1"]):
        benign.append("possibly internal/local endpoint")
    if any(k in flat for k in ["mask", "redact", "sanitize"]):
        benign.append("some sanitization or masking hint observed")

    return {"suspicious": suspicious, "possibly_benign": benign}


def result_to_finding(run: dict[str, Any], result: dict[str, Any], idx: int) -> dict[str, Any]:
    rule_id = result.get("ruleId", "unknown-rule")
    msg = result.get("message", {}).get("text", "No message")
    locations = result.get("locations", [])
    primary = location_to_dict(locations[0]) if locations else {
        "uri": "unknown",
        "line": 1,
        "column": 1,
        "message": "",
    }

    path = extract_path(result)
    signals = classify_signals(path)

    return {
        "id": f"F-{idx:04d}",
        "rule_id": rule_id,
        "rule_name": get_rule_name(run, rule_id),
        "severity": severity_from_result(result),
        "confidence": "medium",
        "summary": msg,
        "primary_location": primary,
        "path_tree": {
            "source": path[0] if path else None,
            "propagators": path[1:-1] if len(path) > 2 else [],
            "sink": path[-1] if path else None,
        },
        "signals": signals,
    }


def render_markdown(findings: list[dict[str, Any]]) -> str:
    lines = []
    lines.append("# Environment Variable Flow Audit")
    lines.append("")
    lines.append(f"Total findings: {len(findings)}")
    lines.append("")

    for finding in findings:
        loc = finding["primary_location"]
        lines.append(f"## {finding['id']} | {finding['severity'].upper()} | {finding['rule_name']}")
        lines.append(f"- Summary: {finding['summary']}")
        lines.append(f"- Location: {loc['uri']}:{loc['line']}")

        suspicious = finding["signals"]["suspicious"]
        benign = finding["signals"]["possibly_benign"]
        lines.append(f"- Suspicious signals: {', '.join(suspicious) if suspicious else 'none'}")
        lines.append(f"- Possibly benign signals: {', '.join(benign) if benign else 'none'}")
        lines.append("- Flow path:")

        tree = finding["path_tree"]
        source = tree.get("source")
        sink = tree.get("sink")
        props = tree.get("propagators", [])

        if source:
            lines.append(f"  - source: {source['uri']}:{source['line']} {source['message']}")
        for step in props:
            lines.append(f"  - via: {step['uri']}:{step['line']} {step['message']}")
        if sink:
            lines.append(f"  - sink: {sink['uri']}:{sink['line']} {sink['message']}")

        lines.append("")

    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) != 4:
        print("Usage: sarif_to_tree.py <input.sarif> <output.json> <output.md>")
        return 1

    sarif_in = Path(sys.argv[1])
    out_json = Path(sys.argv[2])
    out_md = Path(sys.argv[3])

    data = json.loads(sarif_in.read_text(encoding="utf-8"))

    findings = []
    runs = data.get("runs", [])
    counter = 1
    for run in runs:
        for result in run.get("results", []):
            findings.append(result_to_finding(run, result, counter))
            counter += 1

    payload = {
        "schema_version": "1.0",
        "engine": "codeql",
        "findings": findings,
    }

    out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    out_md.write_text(render_markdown(findings), encoding="utf-8")

    print(f"Wrote {out_json}")
    print(f"Wrote {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
