#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys


def parse_pr_quality_gate(pr_body: str) -> dict:
    import re
    flags = re.MULTILINE | re.IGNORECASE

    def read(pattern: str, field: str, cast):
        m = re.search(pattern, pr_body, flags)
        if not m:
            raise ValueError(f"Field '{field}' not found or invalid in PR body.")
        raw = m.group(1).strip()
        try:
            return cast(raw)
        except Exception as e:
            raise ValueError(
                f"Field '{field}' has invalid value '{raw}': {e}"
            )

    mode = read(r"Security-Gate-Mode:\s*(\w+)", "Security-Gate-Mode", str).lower()
    max_total = read(r"MaxTotalIssueGroups:\s*([0-9]+)", "MaxTotalIssueGroups", int)
    max_high = read(
        r"MaxHighSeverityFindings:\s*([0-9]+)",
        "MaxHighSeverityFindings",
        int,
    )
    max_density = read(
        r"MaxDensityPerKLoCGrouped:\s*([0-9]*\.?[0-9]+)",
        "MaxDensityPerKLoCGrouped",
        float,
    )
    max_secret = read(
        r"MaxSecretFindings:\s*([0-9]+)",
        "MaxSecretFindings",
        int,
    )

    return {
        "mode": mode,
        "max_total_issue_groups": max_total,
        "max_high_severity": max_high,
        "max_density_grouped": max_density,
        "max_secret": max_secret,
    }

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--metrics-file",
        default="security-metrics.json",
        help="Path to aggregated security metrics JSON",
    )
    args = parser.parse_args()

    pr_body = os.environ.get("PR_BODY", "") or ""
    if not pr_body.strip():
        print(
            "PR_BODY environment variable is empty. "
            "Cannot evaluate security quality gate.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        gate_cfg = parse_pr_quality_gate(pr_body)
    except ValueError as e:
        print(f"[QUALITY-GATE] Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.metrics_file, "r", encoding="utf-8") as f:
            metrics = json.load(f)
    except FileNotFoundError:
        print(
            f"[QUALITY-GATE] Metrics file '{args.metrics_file}' not found.",
            file=sys.stderr,
        )
        sys.exit(1)

    total_groups = int(metrics.get("total_issue_groups", 0) or 0)
    severities = metrics.get("severities", {}) or {}
    high_findings = int(severities.get("high", 0) or 0)
    density = metrics.get("density_per_kloc_grouped")
    density = float(density) if density is not None else 0.0
    categories = metrics.get("categories", {}) or {}
    secret_findings = int(categories.get("secret", 0) or 0)

    print("=== Security Quality Gate ===")
    print("Config from PR:")
    print(f"  mode: {gate_cfg['mode']}")
    print(f"  MaxTotalIssueGroups:      {gate_cfg['max_total_issue_groups']}")
    print(f"  MaxHighSeverityFindings:  {gate_cfg['max_high_severity']}")
    print(f"  MaxDensityPerKLoCGrouped: {gate_cfg['max_density_grouped']}")
    print(f"  MaxSecretFindings:        {gate_cfg['max_secret']}")
    print()
    print("Metrics from security-metrics.json:")
    print(f"  total_issue_groups:       {total_groups}")
    print(f"  high_severity_findings:   {high_findings}")
    print(f"  density_per_kloc_grouped: {density:.2f}")
    print(f"  secret_findings:          {secret_findings}")
    print()

    violations = []

    if total_groups > gate_cfg["max_total_issue_groups"]:
        violations.append(
            f"total_issue_groups={total_groups} > MaxTotalIssueGroups={gate_cfg['max_total_issue_groups']}"
        )
    if high_findings > gate_cfg["max_high_severity"]:
        violations.append(
            f"high_severity_findings={high_findings} > MaxHighSeverityFindings={gate_cfg['max_high_severity']}"
        )
    if density > gate_cfg["max_density_grouped"]:
        violations.append(
            f"density_per_kloc_grouped={density:.2f} > MaxDensityPerKLoCGrouped={gate_cfg['max_density_grouped']}"
        )
    if secret_findings > gate_cfg["max_secret"]:
        violations.append(
            f"secret_findings={secret_findings} > MaxSecretFindings={gate_cfg['max_secret']}"
        )

    mode = gate_cfg["mode"]
    if mode not in ("enforce", "warn", "none"):
        print(
            f"[QUALITY-GATE] Unknown mode '{mode}', treating as 'enforce'.",
            file=sys.stderr,
        )
        mode = "enforce"

    if mode == "none":
        print("[QUALITY-GATE] Mode 'none' → skipping enforcement. Result: PASS")
        sys.exit(0)

    if not violations:
        print(f"[QUALITY-GATE] PASSED (mode={mode}). No thresholds exceeded.")
        sys.exit(0)

    print(f"[QUALITY-GATE] Threshold violations ({len(violations)}):")
    for v in violations:
        print(f"  - {v}")

    if mode == "warn":
        print(
            "[QUALITY-GATE] Mode 'warn' → not failing pipeline despite violations."
        )
        sys.exit(0)

    print(
        "[QUALITY-GATE] Mode 'enforce' → failing pipeline due to violations.",
        file=sys.stderr,
    )
    sys.exit(1)


if __name__ == "__main__":
    main()