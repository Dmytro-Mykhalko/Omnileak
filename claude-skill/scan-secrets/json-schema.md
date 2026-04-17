# Triage JSON Schema

## File Naming Convention

All output files: `<repo_name>_<base_name>_<risk_score>.<ext>`

Example (repo "my-app", risk score 72):
- `my-app_triage-results_72.json`
- `my-app_triage-results_72.xlsx`
- `my-app_secrets-triage-report_72.md`

## How the JSON is produced

**You do not hand-write this file.** Emit a compact `classifications.json` (schema below) and run `python3 -m core.ai.triage_writer` — it assembles the final triage-results JSON, fills defaults from raw data, computes `risk_score`, and stamps `meta.assembled_by`. The validator rejects any triage JSON whose `meta.assembled_by` is not `"triage_writer/v1"`.

## JSON Structure (output of triage_writer)

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
    "duplicates": 25,
    "ai_only_findings": 1,
    "deep_analysis_performed": true,
    "assembled_by": "triage_writer/v1"
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
- `duplicates`: integer
- `ai_only_findings`: integer
- `deep_analysis_performed`: boolean
- `assembled_by`: string — always `"triage_writer/v1"`, stamped by `core.ai.triage_writer`. Required by the validator.

## Compact classifications (input to triage_writer)

The agent writes this small file; `triage_writer` reads it and produces the full triage-results JSON above.

```json
{
  "findings": [
    {
      "omnileak_ids": ["<raw_id_1>", "<raw_id_2>"],
      "classification": "TRUE_POSITIVE",
      "severity": "CRITICAL",
      "category": "AWS Access Key",
      "on_disk": true,
      "confidence": "high",
      "environment": "production",
      "remediation": "ROTATE_IMMEDIATELY",
      "effort": "quick",
      "fp_reason": null,
      "duplicate_of": null
    }
  ],
  "composite_vulnerabilities": []
}
```

Rules:
- **One entry per distinct credential.** If the same secret value appears at multiple paths/commits/tools, group all raw IDs into one entry's `omnileak_ids`.
- **Do NOT include pre-filter auto-FPs here** — `triage_writer` pulls those from `prefiltered.json`.
- **TRUE_POSITIVE** entries: fill all fields (`severity`, `confidence`, `environment`, `remediation`, `effort`).
- **FALSE_POSITIVE** entries: set `severity`/`confidence`/`environment`/`remediation`/`effort` to `null`, fill `fp_reason`.
- **DUPLICATE** entries: list only the duplicate's raw ID in `omnileak_ids`, set `duplicate_of` to the primary's sequential `id` (1-based, matching the order of the primary in your `findings` list).
- Any raw ID not listed here and not in `prefiltered.json`'s auto_fp gets turned into a DUPLICATE with no primary by the writer. The validator fails if coverage is incomplete, so verify every `needs_triage` ID is represented.

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

## Finding Examples

### TRUE_POSITIVE

```json
{
  "id": 1,
  "omnileak_ids": ["a1b2c3d4e5f6", "f7e8d9c0b1a2"],
  "classification": "TRUE_POSITIVE",
  "severity": "CRITICAL",
  "category": "AWS Access Key",
  "secret_value": "AKIAIOSFODNN7EXAMPLE...truncated",
  "file_path": "config/aws.yml",
  "line_number": "12",
  "commit": "abc1234def5678",
  "on_disk": true,
  "confidence": "high",
  "environment": "production",
  "remediation": "ROTATE_IMMEDIATELY",
  "effort": "quick",
  "detected_by": ["gitleaks", "trufflehog"],
  "fp_reason": null,
  "duplicate_of": null
}
```

### FALSE_POSITIVE

```json
{
  "id": 2,
  "omnileak_ids": ["c3d4e5f6a7b8"],
  "classification": "FALSE_POSITIVE",
  "severity": null,
  "category": "Generic Password",
  "secret_value": "password123_placeholder",
  "file_path": "tests/fixtures/mock_config.yml",
  "line_number": "5",
  "commit": "def5678abc1234",
  "on_disk": true,
  "confidence": null,
  "environment": null,
  "remediation": null,
  "effort": null,
  "detected_by": ["detect-secrets"],
  "fp_reason": "Test fixture with placeholder values, not real credentials",
  "duplicate_of": null
}
```

### DUPLICATE

```json
{
  "id": 3,
  "omnileak_ids": ["d4e5f6a7b8c9"],
  "classification": "DUPLICATE",
  "severity": "CRITICAL",
  "category": "AWS Access Key",
  "secret_value": "AKIAIOSFODNN7EXAMPLE...truncated",
  "file_path": "deploy/config.yml",
  "line_number": "8",
  "commit": "111222333aaa",
  "on_disk": false,
  "confidence": null,
  "environment": null,
  "remediation": null,
  "effort": null,
  "detected_by": ["titus"],
  "fp_reason": null,
  "duplicate_of": 1
}
```

## Rules

- `id` **MUST** be a sequential integer starting at 1 (1, 2, 3, ...). No string IDs like "TP-001".
- Every raw Omnileak ID must appear in exactly one finding's `omnileak_ids`. No ID may be omitted or duplicated across findings.
- DUPLICATE findings copy `severity` and `category` from their primary finding.
- Pre-filter auto-FPs are included as regular `FALSE_POSITIVE` findings with `fp_reason` starting with `"Auto-filtered: "` and the category name. They appear in the All Findings sheet of the Excel report.
