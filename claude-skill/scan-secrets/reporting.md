# Report Generation Instructions

## 1. Validate Triage JSON

Run the validator **first** to catch errors before generating reports:

```bash
cd <omnileak_path> && python3 -m core.ai.triage_validator <json_path> --raw <aggregated_json_path>
```

If validation fails, fix the JSON and re-validate. The validator checks: required fields, correct types, count consistency, risk score formula, and raw ID coverage.

## 2. Excel Report

Convert the triage JSON to Excel:

```bash
cd <omnileak_path> && python3 -m core.ai.triage_reporter <json_path>
```

The `.xlsx` name is auto-derived from the `.json` name. Tabs: Summary, All Findings, True Positives, Duplicates, False Positives, Composite Vulns. If the script fails, report the error but continue.

**All findings including pre-filter auto-FPs must appear in Excel.** The "All Findings" sheet shows every raw Omnileak finding. Auto-FPs appear with `fp_reason` set to `"Auto-filtered: <category>"` (e.g., `"Auto-filtered: lock_file"`). They also appear in the False Positives sheet. No finding should be invisible in the final deliverable.

## Markdown Report

Write `<output_directory>/<repo_name>_secrets-triage-report_<risk_score>.md`:

### Section 1: Executive Summary
Table with: total tool findings, true positives, false positives filtered, AI-only findings, breakdown by severity.

Include the **Risk Score** prominently: `Risk Score: XX/100` with a label:
- 0-20: LOW RISK
- 21-50: MODERATE RISK
- 51-80: HIGH RISK
- 81-100: CRITICAL RISK

### Section 2: Composite Vulnerabilities
Cross-file / code-flow vulnerabilities found only by AI deep analysis. Omit if none.

### Section 3: False Positives Filtered
Summary counts by category (e.g., "28 vendor translations, 22 SDK schemas"). Do NOT list individual FPs.

### Section 4: Remediation Priority
Group by priority with effort estimates: `[quick]`, `[medium]`, `[complex]`.

- **Priority 1 — Rotate Immediately**: production credentials, cloud provider keys, PATs
- **Priority 2 — Rotate Soon**: staging credentials, private keys, auth tokens
- **Priority 3 — Clean Up**: .gitignore updates, git history purge, pre-commit hooks

## Pipeline Improvements Report

Write `<output_directory>/<repo_name>_pipeline-improvements_<risk_score>.md`:

### Section 1: What Went Well
Tool effectiveness, FP rule coverage, severity rubric accuracy.

### Section 2: False Positive Patterns Discovered
New FP patterns not in current rules. Include: pattern, example, proposed rule.

### Section 3: Triage Gaps
Low-confidence findings, ambiguous environments, inconclusive on-disk checks.

### Section 4: Tool Coverage Analysis
Tool overlap, unique catches, blind spots.

### Section 5: Suggested Improvements
Concrete suggestions with: **What**, **Why**, **Priority** (high/medium/low).
