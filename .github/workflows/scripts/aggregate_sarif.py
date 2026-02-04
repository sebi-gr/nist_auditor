#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
from collections import Counter, defaultdict

# --- Helpers -------------------------------------------------------------

def find_sarif_files(root: Path) -> list[Path]:
    return list(root.rglob("*.sarif"))

def infer_category(rule_id: str | None, tool_name: str, message: str) -> str:
    """Grober Heuristik-Mapper für Kategorien (zum Gruppieren)."""
    s = (rule_id or "").lower()
    t = tool_name.lower()

    if t == "gitleaks":
        return "secret"
    if "sql-injection" in s or "sqli" in s or "formatted-sql-string" in s:
        return "sql-injection"
    if "path-injection" in s or "path-traversal" in s:
        return "path-traversal"
    if "md5" in s:
        return "weak-crypto-md5"
    return "other"

def map_severity(level: str | None) -> str:
    """Mappt SARIF-Level auf eine vereinfachte Severity."""
    if level is None:
        return "medium"
    level = level.lower()
    mapping = {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }
    return mapping.get(level, "medium")

def load_sarif_file(path: Path) -> list[dict]:
    """Liest ein SARIF und normalisiert alle Results in eine Liste einfacher Dicts."""
    with path.open("r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")
            return []

    findings: list[dict] = []
    for run in data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name") or path.stem

        # Rule-Metadata map (für Severity etc.)
        rule_meta = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            rule_meta[rule.get("id")] = rule

        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id")
            rule = rule_meta.get(rule_id) if rule_id else None

            # Level & Severity
            level = res.get("level") or (rule or {}).get("defaultConfiguration", {}).get("level")
            level = level or "warning"
            severity = map_severity(level)

            # Location
            uri = None
            start_line = None
            end_line = None
            locations = res.get("locations") or []
            if locations:
                phys = locations[0].get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri")
                region = phys.get("region", {})
                start_line = region.get("startLine")
                end_line = region.get("endLine")

            message = (res.get("message") or {}).get("text") or ""
            category = infer_category(rule_id, tool_name, message)

            findings.append(
                {
                    "tool": tool_name,
                    "rule_id": rule_id,
                    "severity": severity,
                    "level": level,
                    "file": uri,
                    "start_line": start_line,
                    "end_line": end_line,
                    "message": message,
                    "category": category,
                }
            )

    return findings

def count_loc(repo_root: Path) -> int:
    """Zählt grob die nicht-leeren Codezeilen in typischen Source-Dateien."""
    exts = (
        ".java",
        ".py",
        ".js",
        ".ts",
        ".go",
        ".cs",
        ".rb",
        ".php",
        ".scala",
        ".kt",
        ".c",
        ".cpp",
    )
    total = 0
    for dirpath, dirnames, filenames in os.walk(repo_root):
        parts = dirpath.split(os.sep)
        if any(
            p
            in (
                ".git",
                ".github",
                ".venv",
                "venv",
                "node_modules",
                "dist",
                "build",
                "__pycache__",
            )
            for p in parts
        ):
            continue

        for fname in filenames:
            if fname.endswith(exts):
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            if line.strip():
                                total += 1
                except Exception as e:
                    print(f"[WARN] Failed to read {fpath}: {e}")
    return total

# --- Main aggregation ----------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sarif-dir",
        default="sarif",
        help="Root directory where SARIF artifacts were downloaded",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root (for LoC counting)",
    )
    parser.add_argument(
        "--output",
        default="summary.json",
        help="Where to write the aggregated metrics JSON",
    )
    args = parser.parse_args()

    sarif_root = Path(args.sarif_dir)
    repo_root = Path(args.repo_root)

    sarif_files = find_sarif_files(sarif_root)
    if not sarif_files:
        print(f"[WARN] No SARIF files found under {sarif_root}")
        return

    print("Found SARIF files:")
    for p in sarif_files:
        print(f"  - {p}")

    all_findings: list[dict] = []
    for p in sarif_files:
        file_findings = load_sarif_file(p)
        all_findings.extend(file_findings)

    print(f"\nTotal normalized findings: {len(all_findings)}")

    # Gruppierung: gleiches File + gleiche Zeile + gleiche Kategorie
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for f in all_findings:
        key = (f["file"], f["start_line"], f["category"])
        grouped[key].append(f)

    print(f"Unique issue groups: {len(grouped)}\n")

    # Basismetriken
    tool_counts = Counter(f["tool"] for f in all_findings)
    category_counts = Counter(f["category"] for f in all_findings)
    severity_counts = Counter(f["severity"] for f in all_findings)

    loc = count_loc(repo_root)
    density_raw = (len(all_findings) * 1000.0 / loc) if loc else None
    density_grouped = (len(grouped) * 1000.0 / loc) if loc else None

    print("=== Security Metrics Summary ===")
    print(f"Raw findings: {len(all_findings)}")
    print(f"Unique issue groups: {len(grouped)}")
    print("Findings by tool:")
    for tool, cnt in tool_counts.most_common():
        print(f"  {tool}: {cnt}")
    print("Findings by category:")
    for cat, cnt in category_counts.most_common():
        print(f"  {cat}: {cnt}")
    print("Findings by severity:")
    for sev, cnt in severity_counts.most_common():
        print(f"  {sev}: {cnt}")

    print(f"Lines of code (LoC): {loc}")
    if density_raw is not None:
        print(f"Raw vulnerability density: {density_raw:.2f} findings / KLoC")
        print(f"Grouped vulnerability density: {density_grouped:.2f} groups / KLoC")

    # Detail-Output für weitere Auswertung (z. B. fürs Dashboard)
    metrics = {
        "total_raw_findings": len(all_findings),
        "total_issue_groups": len(grouped),
        "tools": tool_counts,
        "categories": category_counts,
        "severities": severity_counts,
        "loc": loc,
        "density_per_kloc_raw": density_raw,
        "density_per_kloc_grouped": density_grouped,
        "groups": [
            {
                "file": file,
                "start_line": line,
                "category": category,
                "tools": sorted({f["tool"] for f in fs}),
                "severity_max": max(
                    (f["severity"] for f in fs),
                    key=lambda s: ["low", "medium", "high"].index(
                        s if s in ("low", "medium", "high") else "medium"
                    ),
                ),
                "findings": fs,
            }
            for (file, line, category), fs in grouped.items()
        ],
    }

    # Counter-Objekte in normale Dicts umwandeln (JSON-freundlich)
    for key in ("tools", "categories", "severities"):
        metrics[key] = dict(metrics[key])

    out_path = Path(args.output)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nWrote aggregated metrics to {out_path}")


if __name__ == "__main__":
    main()
