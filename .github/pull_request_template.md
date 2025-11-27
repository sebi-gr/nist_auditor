### Provenance (required)
Please set one: `ai` / `human` / `external` / `mixed` / `unknown`

Provenance: unknown

---

### Security Quality Gate (required)

Define how this PR should be evaluated against automated security checks  
(Gitleaks, Semgrep, CodeQL, aggregated in the “Security Metrics” job).

Please set Security-Gate-Mode to one of: `enforce` / `warn` / `none`

Security-Gate-Mode: enforce

<!--
The following thresholds are interpreted as "maximum allowed" values
for this pull request. They are compared against the metrics from
security-metrics.json (step 5 in the workflow).

You can tighten or relax them per PR, but the keys themselves
(MaxTotalIssueGroups, MaxHighSeverityFindings, etc.) should stay as-is,
so that CI can parse them reliably.
-->

MaxTotalIssueGroups: 0              <!-- based on metrics.total_issue_groups -->
MaxHighSeverityFindings: 0          <!-- based on metrics.severities["high"] -->
MaxDensityPerKLoCGrouped: 0.50      <!-- based on metrics.density_per_kloc_grouped -->
MaxSecretFindings: 0                <!-- based on "secret" category from Gitleaks -->
