# tools/report_step.py
"""
CI-centric RMF report step (no local CLI workflow required).

Expected inputs (fixed paths):
- artifacts/summary.json              (required) : pipeline-produced aggregated JSON (like your example)
  Fallbacks (local/dev): security-metrics.json, summary.json
- rmf_map.yml                         (required) : category->RMF mapping
- .security/decisions.yml             (optional) : human decisions for Manage/Govern

Outputs:
- artifacts/report.json
- artifacts/report.html
- artifacts/pr_summary.md

GitHub Actions usage:
  - name: Build RMF report
    run: python tools/report_step.py
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # pragma: no cover


SEV_ORDER = {"high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
SEV_CANON = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}


def _read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Required JSON file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _read_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Required YAML file not found: {path}")
    if yaml is None:
        raise RuntimeError("PyYAML is not installed. Add `pip install pyyaml` to your workflow.")
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid YAML root (expected dict): {path}")
    return data


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _env(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    return v if v is not None and v.strip() != "" else default


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _severity_norm(s: str) -> str:
    s2 = (s or "").strip().lower()
    if s2 in SEV_ORDER:
        return s2
    # allow inputs like "HIGH"
    s2u = s2.upper()
    return SEV_CANON.get(s2u, "unknown")


def _severity_label(s: str) -> str:
    # for display
    s2 = _severity_norm(s)
    return s2.upper()


def _sev_sort_key(s: str) -> int:
    return SEV_ORDER.get(_severity_norm(s), 0)


def _module_from_file(file_path: str) -> str:
    # deterministic: top-level directory as "module"; if file has no dir -> root
    p = Path(file_path)
    parts = p.parts
    if len(parts) <= 1:
        return "root"
    return parts[0]


def _load_decisions(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists():
        return {}
    data = _read_yaml(path)
    clusters = data.get("clusters", {})
    if not isinstance(clusters, dict):
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for cid, payload in clusters.items():
        if isinstance(cid, str) and isinstance(payload, dict):
            out[cid] = payload
    return out


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    severity: str
    level: str
    file: str
    start_line: int
    end_line: int
    message: str
    category: str


@dataclass
class Cluster:
    cluster_id: str
    module: str
    category: str
    severity: str
    tools: List[str]
    file: str
    start_line: int
    findings: List[Finding]


def _make_cluster_id(module: str, category: str, severity: str) -> str:
    return f"mod:{module}|cat:{category}|sev:{_severity_label(severity)}"


def _extract_clusters(summary: Dict[str, Any]) -> List[Cluster]:
    groups = summary.get("groups", [])
    if not isinstance(groups, list):
        raise ValueError("summary.json: 'groups' must be a list")

    clusters: List[Cluster] = []
    for g in groups:
        if not isinstance(g, dict):
            continue
        file = str(g.get("file", "")).strip()
        start_line = int(g.get("start_line", 0) or 0)
        category = str(g.get("category", "OTHER")).strip() or "OTHER"
        sev = _severity_norm(str(g.get("severity_max", "unknown")))
        tools = g.get("tools", [])
        tools_list = [str(t) for t in tools] if isinstance(tools, list) else []
        module = _module_from_file(file)
        cid = _make_cluster_id(module, category, sev)

        findings_raw = g.get("findings", [])
        findings: List[Finding] = []
        if isinstance(findings_raw, list):
            for f in findings_raw:
                if not isinstance(f, dict):
                    continue
                findings.append(
                    Finding(
                        tool=str(f.get("tool", "")),
                        rule_id=str(f.get("rule_id", "")),
                        severity=_severity_norm(str(f.get("severity", "unknown"))),
                        level=str(f.get("level", "")),
                        file=str(f.get("file", file)),
                        start_line=int(f.get("start_line", start_line) or start_line),
                        end_line=int(f.get("end_line", start_line) or start_line),
                        message=str(f.get("message", "")),
                        category=str(f.get("category", category)) or category,
                    )
                )

        clusters.append(
            Cluster(
                cluster_id=cid,
                module=module,
                category=category,
                severity=sev,
                tools=sorted(set(tools_list)),
                file=file,
                start_line=start_line,
                findings=findings,
            )
        )
    return clusters


def _rmf_category_map(rmf_map: Dict[str, Any], category: str) -> Dict[str, Any]:
    cats = rmf_map.get("categories", {})
    if isinstance(cats, dict) and category in cats and isinstance(cats[category], dict):
        return cats[category]
    # fallback to OTHER
    if isinstance(cats, dict) and "OTHER" in cats and isinstance(cats["OTHER"], dict):
        return cats["OTHER"]
    return {}


def _gate_from_summary(summary: Dict[str, Any]) -> Tuple[str, str]:
    # deterministic fallback if pipeline didn't provide gate status
    severities = summary.get("severities", {})
    high = 0
    if isinstance(severities, dict):
        high = int(severities.get("high", 0) or 0)
    if high > 0:
        return ("fail", "High severity findings present (High>0).")
    return ("pass", "No high severity findings present (High=0).")


def _build_report_json(
    summary: Dict[str, Any],
    rmf_map: Dict[str, Any],
    decisions: Dict[str, Dict[str, Any]],
    provenance: str,
    scan_scope: str,
) -> Dict[str, Any]:
    clusters = _extract_clusters(summary)

    # sort clusters deterministically
    clusters.sort(key=lambda c: (-_sev_sort_key(c.severity), c.module, c.category, c.file, c.start_line))

    gate_status = _env("GATE_STATUS", "").strip().lower()
    gate_rationale = ""
    if gate_status in ("pass", "fail", "warn"):
        gate_rationale = "Gate status provided by pipeline."
    else:
        gate_status, gate_rationale = _gate_from_summary(summary)

    policy_profile = "ai-aware" if provenance in ("ai", "unknown") else "generic"

    # Measure from summary
    loc = int(summary.get("loc", 0) or 0)
    kloc = (loc / 1000.0) if loc > 0 else 0.0
    total_raw = int(summary.get("total_raw_findings", 0) or 0)
    total_grouped = int(summary.get("total_issue_groups", 0) or 0)
    sev_mix = summary.get("severities", {}) if isinstance(summary.get("severities", {}), dict) else {}

    vd_raw = float(summary.get("density_per_kloc_raw", 0.0) or 0.0)
    vd_grouped = float(summary.get("density_per_kloc_grouped", 0.0) or 0.0)

    # Placeholder CS / Risk if not already computed by pipeline
    high = int(sev_mix.get("high", 0) or 0)
    med = int(sev_mix.get("medium", 0) or 0)
    low = int(sev_mix.get("low", 0) or 0)
    info = int(sev_mix.get("info", 0) or 0)

    cs = 100.0 - (high * 20.0 + med * 5.0 + low * 1.0 + info * 0.2)
    cs = max(0.0, min(100.0, cs))

    risk = high * 10.0 + med * 3.0 + low * 1.0 + info * 0.2
    if policy_profile == "ai-aware":
        risk *= 1.2

    # RMF summary counts & missing governance fields
    missing_owner = 0
    missing_ticket = 0
    missing_sla = 0

    clusters_out: List[Dict[str, Any]] = []
    for c in clusters:
        m = _rmf_category_map(rmf_map, c.category)

        # Map
        cia = list(m.get("cia", [])) if isinstance(m.get("cia", []), list) else []
        cwes = list(m.get("cwe", [])) if isinstance(m.get("cwe", []), list) else []
        threat = str(m.get("threat", "Uncategorized"))
        policy_ids = list(m.get("policy", [])) if isinstance(m.get("policy", []), list) else []
        recommend = list(m.get("recommend", [])) if isinstance(m.get("recommend", []), list) else []
        next_steps = list(m.get("next_steps", [])) if isinstance(m.get("next_steps", []), list) else []
        default_sla = int(m.get("default_sla_days", 0) or 0) if str(m.get("default_sla_days", "")).strip() != "" else None

        # Decisions merge
        d = decisions.get(c.cluster_id, {})
        status = str(d.get("status", "none")).strip() or "none"
        owner = str(d.get("owner", "")).strip() or ""
        ticket = str(d.get("ticket", "")).strip() or ""
        sla_days = d.get("sla_days", default_sla)
        exception_ttl_days = d.get("exception_ttl_days", None)
        rationale = str(d.get("rationale", "")).strip() or ""

        if owner == "":
            missing_owner += 1
        if ticket == "":
            missing_ticket += 1
        if sla_days in (None, "", 0):
            missing_sla += 1

        example_locations = [f"{c.file}:{c.start_line}"]
        rules = sorted({f.rule_id for f in c.findings if f.rule_id})

        # compliance status heuristic:
        # - if gate fails and cluster severity high => violated, else unknown/met
        compliance_status = "unknown"
        if c.severity == "high":
            compliance_status = "violated" if gate_status == "fail" else "unknown"
        else:
            compliance_status = "unknown" if gate_status == "fail" else "met"

        clusters_out.append(
            {
                "cluster_id": c.cluster_id,
                "map": {
                    "module": c.module,
                    "category": c.category,
                    "threat": threat,
                    "cia": cia,
                    "cwe": cwes,
                    "affected_files": [c.file],
                    "example_locations": example_locations,
                },
                "measure": {
                    "counts": {
                        "findings_in_cluster": len(c.findings),
                        "severity_max": _severity_label(c.severity),
                    },
                    "severity_mix": {
                        "high": sum(1 for f in c.findings if f.severity == "high"),
                        "medium": sum(1 for f in c.findings if f.severity == "medium"),
                        "low": sum(1 for f in c.findings if f.severity == "low"),
                        "info": sum(1 for f in c.findings if f.severity == "info"),
                    },
                    "tools": c.tools,
                    "rules": rules,
                    "coverage_notes": [f"Scope: {scan_scope}", "Static analysis (SAST) only."],
                    "confidence_notes": [
                        "Static analysis can produce false positives/negatives.",
                        "Business-logic and runtime configuration issues may not be fully captured.",
                    ],
                },
                "manage": {
                    "status": status,
                    "owner": owner,
                    "sla_days": sla_days,
                    "ticket": ticket,
                    "exception_ttl_days": exception_ttl_days,
                    "recommended_actions": recommend,
                    "next_steps": next_steps,
                    "rationale": rationale,
                },
                "govern": {
                    "policy_ids": policy_ids,
                    "compliance_status": compliance_status,
                    "provenance_policy_applied": policy_profile,
                    "decision_audit": {
                        "source": ".security/decisions.yml" if c.cluster_id in decisions else "none",
                    },
                },
            }
        )

    tools_used = []
    t = summary.get("tools", {})
    if isinstance(t, dict):
        tools_used = sorted(t.keys())

    report: Dict[str, Any] = {
        "metadata": {
            "run_id": _env("RUN_ID", ""),
            "timestamp_utc": _now_utc_iso(),
            "repo": _env("REPO_NAME", ""),
            "pr_number": _env("PR_NUMBER", ""),
            "commit_sha": _env("COMMIT_SHA", ""),
            "provenance": provenance,
            "scan_scope": scan_scope,
            "tools_used": tools_used,
            "coverage_notes": [f"Scope: {scan_scope}"],
            "limitations": [
                "This report is based on static analysis outputs and pipeline aggregation.",
                "Passing gates does not imply absence of risk; it indicates policy compliance within scan scope.",
            ],
        },
        "gate": {
            "status": gate_status,
            "rationale": gate_rationale,
            "policy_profile": policy_profile,
        },
        "measure": {
            "loc": loc,
            "kloc": kloc,
            "total_raw_findings": total_raw,
            "total_issue_groups": total_grouped,
            "severity_mix": {
                "high": high,
                "medium": med,
                "low": low,
                "info": info,
            },
            "vd_raw_per_kloc": vd_raw,
            "vd_grouped_per_kloc": vd_grouped,
            "compliance_score": cs,
            "risk_score": risk,
            "reproducibility": {
                "note": "Pin tool versions and run in containerized CI runners to ensure reproducible results.",
            },
        },
        "rmf_summary": {
            "clusters_total": len(clusters_out),
            "missing_fields": {
                "owner": missing_owner,
                "ticket": missing_ticket,
                "sla_days": missing_sla,
            },
        },
        "clusters": clusters_out,
        "recommendations": _deterministic_recommendations(
            gate_status=gate_status,
            missing_owner=missing_owner,
            missing_ticket=missing_ticket,
            missing_sla=missing_sla,
            policy_profile=policy_profile,
        ),
    }
    return report


def _deterministic_recommendations(
    gate_status: str, missing_owner: int, missing_ticket: int, missing_sla: int, policy_profile: str
) -> List[str]:
    rec: List[str] = []
    if gate_status == "fail":
        rec.append("Gate failed: resolve blocking findings before merge or document an approved exception with TTL.")
    if missing_owner > 0:
        rec.append("Assign owners to all finding clusters (Accountability is required for governance).")
    if missing_ticket > 0:
        rec.append("Create tickets for planned fixes to enable tracking and auditability.")
    if missing_sla > 0:
        rec.append("Define SLAs for all clusters (or inherit defaults from rmf_map.yml).")
    if policy_profile == "ai-aware":
        rec.append("AI-aware profile applied: consider tighter thresholds and increased review for injection/secrets/crypto categories.")
    return rec


def _render_html(report: Dict[str, Any]) -> str:
    meta = report.get("metadata", {})
    gate = report.get("gate", {})
    meas = report.get("measure", {})
    rmf = report.get("rmf_summary", {})
    clusters = report.get("clusters", [])

    def esc(s: Any) -> str:
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    gate_status = esc(gate.get("status", "unknown"))
    gate_color = {"pass": "#1f883d", "warn": "#9a6700", "fail": "#cf222e"}.get(gate_status, "#6e7781")

    rows = []
    for c in clusters:
        cid = esc(c.get("cluster_id", ""))
        m = c.get("map", {})
        mg = c.get("manage", {})
        gv = c.get("govern", {})
        ms = c.get("measure", {})

        sev = esc(ms.get("counts", {}).get("severity_max", ""))
        cat = esc(m.get("category", ""))
        mod = esc(m.get("module", ""))
        threat = esc(m.get("threat", ""))
        files = ", ".join(esc(x) for x in m.get("affected_files", []))
        locs = ", ".join(esc(x) for x in m.get("example_locations", []))
        owner = esc(mg.get("owner", ""))
        ticket = esc(mg.get("ticket", ""))
        sla = esc(mg.get("sla_days", ""))
        status = esc(mg.get("status", "none"))

        missing = []
        if owner == "":
            missing.append("owner")
        if ticket == "":
            missing.append("ticket")
        if sla in ("", "None", "0"):
            missing.append("sla")
        missing_txt = ("Missing: " + ", ".join(missing)) if missing else ""

        rec_actions = "".join(f"<li>{esc(a)}</li>" for a in mg.get("recommended_actions", []))
        next_steps = "".join(f"<li>{esc(a)}</li>" for a in mg.get("next_steps", []))
        policies = ", ".join(esc(p) for p in gv.get("policy_ids", []))
        compliance = esc(gv.get("compliance_status", "unknown"))

        # show example findings (messages) succinctly
        examples = []
        for f in (c.get("measure", {}).get("rules", []) or [])[:5]:
            examples.append(f"<li><code>{esc(f)}</code></li>")
        ex_html = "".join(examples) if examples else "<li>(no rule ids)</li>"

        rows.append(
            f"""
<details class="card">
  <summary>
    <span class="sev">{sev}</span>
    <span class="title">{cat} — {mod}</span>
    <span class="right">{gate_status.upper()}</span>
  </summary>
  <div class="body">
    <p><b>Cluster ID:</b> <code>{cid}</code></p>
    <p><b>Location:</b> {locs} — <b>Files:</b> {files}</p>
    <p><b>Threat:</b> {threat} — <b>Policies:</b> {policies} — <b>Compliance:</b> {compliance}</p>

    <h4>Measure</h4>
    <ul>
      <li>Tools: {", ".join(esc(x) for x in ms.get("tools", []))}</li>
      <li>Rules: <ul>{ex_html}</ul></li>
    </ul>

    <h4>Manage</h4>
    <ul>
      <li>Status: <b>{status}</b></li>
      <li>Owner: <b>{owner or "(missing)"}</b></li>
      <li>SLA (days): <b>{sla or "(missing)"}</b></li>
      <li>Ticket: <b>{ticket or "(missing)"}</b></li>
      <li style="color:#9a6700">{esc(missing_txt)}</li>
    </ul>

    <h4>Recommended actions</h4>
    <ul>{rec_actions or "<li>(none)</li>"}</ul>

    <h4>Next steps</h4>
    <ul>{next_steps or "<li>(none)</li>"}</ul>
  </div>
</details>
"""
        )

    recs = "".join(f"<li>{esc(r)}</li>" for r in report.get("recommendations", []))

    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>RMF Security Audit Report</title>
  <style>
    body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; color: #24292f; }}
    .badge {{ display:inline-block; padding: 4px 10px; border-radius: 999px; color: white; font-weight: 600; background: {gate_color}; }}
    .meta {{ color: #57606a; font-size: 14px; }}
    .grid {{ display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-top: 12px; }}
    .kpi {{ border: 1px solid #d0d7de; border-radius: 10px; padding: 12px; }}
    .kpi .v {{ font-size: 18px; font-weight: 700; }}
    .card {{ border: 1px solid #d0d7de; border-radius: 12px; padding: 10px 12px; margin: 10px 0; }}
    summary {{ cursor: pointer; list-style: none; display:flex; gap:12px; align-items:center; }}
    summary::-webkit-details-marker {{ display:none; }}
    .sev {{ width: 70px; font-weight: 700; }}
    .title {{ flex: 1; font-weight: 600; }}
    .right {{ color:#57606a; font-size: 12px; }}
    .body {{ padding: 10px 2px 2px 2px; }}
    code {{ background:#f6f8fa; padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
  <h1>RMF Security Audit Report</h1>
  <div class="meta">
    <div><span class="badge">{esc(gate_status.upper())}</span></div>
    <div>Repo: {esc(meta.get("repo",""))} · PR: {esc(meta.get("pr_number",""))} · SHA: {esc(meta.get("commit_sha",""))}</div>
    <div>Timestamp (UTC): {esc(meta.get("timestamp_utc",""))} · Provenance: {esc(meta.get("provenance","unknown"))} · Profile: {esc(gate.get("policy_profile",""))}</div>
    <div>Scope: {esc(meta.get("scan_scope",""))} · Tools: {", ".join(esc(x) for x in meta.get("tools_used", []))}</div>
  </div>

  <h2>Executive summary</h2>
  <div class="grid">
    <div class="kpi"><div class="meta">LOC</div><div class="v">{esc(meas.get("loc",0))}</div></div>
    <div class="kpi"><div class="meta">Clusters</div><div class="v">{esc(rmf.get("clusters_total",0))}</div></div>
    <div class="kpi"><div class="meta">VD (grouped/KLOC)</div><div class="v">{esc(round(float(meas.get("vd_grouped_per_kloc",0.0) or 0.0), 2))}</div></div>
    <div class="kpi"><div class="meta">Compliance score</div><div class="v">{esc(round(float(meas.get("compliance_score",0.0) or 0.0), 1))}</div></div>
  </div>

  <h2>RMF overview</h2>
  <ul>
    <li>Missing owners: {esc(rmf.get("missing_fields",{{}}).get("owner",0))}</li>
    <li>Missing tickets: {esc(rmf.get("missing_fields",{{}}).get("ticket",0))}</li>
    <li>Missing SLAs: {esc(rmf.get("missing_fields",{{}}).get("sla_days",0))}</li>
  </ul>

  <h2>Recommendations</h2>
  <ul>{recs or "<li>(none)</li>"}</ul>

  <h2>Finding clusters</h2>
  {''.join(rows) if rows else "<p>(no clusters)</p>"}
</body>
</html>
"""
    return html


def _write_outputs(report: Dict[str, Any], artifacts_dir: Path) -> None:
    out_json = artifacts_dir / "report.json"
    out_html = artifacts_dir / "report.html"
    out_md = artifacts_dir / "pr_summary.md"

    # JSON stable formatting
    with out_json.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    html = _render_html(report)
    with out_html.open("w", encoding="utf-8") as f:
        f.write(html)

    gate = report.get("gate", {})
    meas = report.get("measure", {})
    md = (
        f"**Security Audit (RMF)**\n\n"
        f"- Gate: **{gate.get('status','unknown').upper()}** ({gate.get('policy_profile','')})\n"
        f"- Provenance: `{report.get('metadata',{}).get('provenance','unknown')}`\n"
        f"- LOC: {meas.get('loc',0)}\n"
        f"- Clusters: {report.get('rmf_summary',{}).get('clusters_total',0)}\n"
        f"- VD (grouped/KLOC): {round(float(meas.get('vd_grouped_per_kloc',0.0) or 0.0), 2)}\n"
        f"- Compliance score: {round(float(meas.get('compliance_score',0.0) or 0.0), 1)}\n"
        f"- Risk score: {round(float(meas.get('risk_score',0.0) or 0.0), 1)}\n"
    )
    with out_md.open("w", encoding="utf-8") as f:
        f.write(md)


def main() -> int:
    artifacts_dir = Path("artifacts")
    _ensure_dir(artifacts_dir)

    summary_path = artifacts_dir / "summary.json"
    if not summary_path.exists():
        for fallback in (Path("security-metrics.json"), Path("summary.json")):
            if fallback.exists():
                print(
                    f"[report_step] WARN: {summary_path} not found; using {fallback}"
                )
                summary_path = fallback
                break
    rmf_map_path = Path("rmf_map.yml")
    decisions_path = Path(".security") / "decisions.yml"

    provenance = _env("PROVENANCE", "unknown").strip().lower()
    if provenance not in ("ai", "human", "external", "mixed", "unknown"):
        provenance = "unknown"

    scan_scope = _env("SCAN_SCOPE", "diff-only").strip().lower()
    if scan_scope not in ("diff-only", "full"):
        scan_scope = "diff-only"

    summary = _read_json(summary_path)
    rmf_map = _read_yaml(rmf_map_path)
    decisions = _load_decisions(decisions_path)

    report = _build_report_json(
        summary=summary,
        rmf_map=rmf_map,
        decisions=decisions,
        provenance=provenance,
        scan_scope=scan_scope,
    )

    # Populate metadata from env if available (optional)
    report["metadata"]["repo"] = report["metadata"]["repo"] or _env("GITHUB_REPOSITORY", "")
    report["metadata"]["commit_sha"] = report["metadata"]["commit_sha"] or _env("GITHUB_SHA", "")
    report["metadata"]["pr_number"] = report["metadata"]["pr_number"] or _env("PR_NUMBER", "")

    _write_outputs(report, artifacts_dir)
    print(f"Wrote {artifacts_dir/'report.json'} and {artifacts_dir/'report.html'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"[report_step] ERROR: {e}", file=sys.stderr)
        raise
