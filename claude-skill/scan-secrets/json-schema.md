# Triage JSON Schema

## File Naming Convention

All output files: `<repo_name>_<base_name>_<risk_score>.<ext>`

Example (repo "my-app", risk score 72):
- `my-app_triage-results_72.json`
- `my-app_triage-results_72.xlsx`
- `my-app_secrets-triage-report_72.md`
- `my-app_pipeline-improvements_72.md`

## JSON Structure

```json
{
  "meta": {
    "repo": "my-app",
    "repo_url": "https://github.com/org/my-app",
    "scan_date": "2026-04-16T10:00:00Z",
    "last_commit": "abc1234",
    "mode": "full_scan",
    "risk_score": 72,
    "total_raw_findings": 150,
    "true_positives": 5,
    "false_positives_filtered": 120,
    "ai_only_findings": 1,
    "deep_analysis_performed": true
  },
  "findings": [],
  "composite_vulnerabilities": []
}
```

**Meta field types:**
- `repo`: string — repository name
- `repo_url`: string — remote origin URL (resolve via `git -C <repo_path> remote get-url origin`; `""` if unavailable)
- `scan_date`: string — ISO 8601 timestamp
- `last_commit`: string — from `<out-dir>/<repo>_latest_commit.txt`
- `mode`: string — `"full_scan"` or `"triage_only"`
- `risk_score`: integer — 0 to 100
- `total_raw_findings`: integer
- `true_positives`: integer
- `false_positives_filtered`: integer
- `ai_only_findings`: integer
- `deep_analysis_performed`: boolean

## Finding Fields

Each finding must have:

| Field | TP value | FP value | DUP value |
|---|---|---|---|
| `id` | sequential int | sequential int | sequential int |
| `omnileak_ids` | list of raw IDs | list of raw IDs | list of raw IDs |
| `classification` | `TRUE_POSITIVE` | `FALSE_POSITIVE` | `DUPLICATE` |
| `severity` | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` | `null` | copied from primary |
| `category` | description | description | copied from primary |
| `secret_value` | value (truncate keys to 60 chars) | value | value |
| `file_path` | path | path | path |
| `line_number` | number | number | number |
| `commit` | hash | hash | hash |
| `on_disk` | `true`/`false`/`"unknown"` | `true`/`false`/`"unknown"` | `true`/`false`/`"unknown"` |
| `confidence` | `high`/`medium`/`low` | `null` | `null` |
| `environment` | `production`/`staging`/`local-dev`/`test`/`vendor`/`unknown` | `null` | `null` |
| `remediation` | `ROTATE_IMMEDIATELY`/`ROTATE_SOON`/`CLEANUP` | `null` | `null` |
| `effort` | `quick`/`medium`/`complex` | `null` | `null` |
| `detected_by` | list of tools or `["AI"]` | list of tools | list of tools |
| `fp_reason` | `null` | explanation string | `null` |
| `duplicate_of` | `null` | `null` | id of primary finding |

## Risk Score Formula

- Each CRITICAL TP: +10 points
- Each HIGH TP: +5 points
- Each MEDIUM TP: +2 points
- Each LOW TP: +1 point
- Multiply subtotal by 1.5 if any composite vulnerabilities exist
- Multiply by 1.3 if any CRITICAL/HIGH TPs are still on disk
- Cap at 100
