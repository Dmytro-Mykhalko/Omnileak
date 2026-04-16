# Manifest Schema

The manifest tracks per-repo progress for iterative multi-repo triage. It lives at `<output_dir>/manifest.json` and is updated after every state change.

## Top-Level Fields

| Field | Type | Description |
|---|---|---|
| `path` | string | Absolute path to this manifest file |
| `created_at` | string | ISO 8601 timestamp |
| `total_repos` | integer | Number of repos in the manifest |
| `total_findings` | integer | Sum of raw findings across all repos |
| `completed` | integer | Repos with status "done" |
| `failed` | integer | Repos with status "failed" |
| `repos` | array | Per-repo entries (sorted by priority descending) |

## Repo Entry Fields

| Field | Type | Description |
|---|---|---|
| `name` | string | Repository name |
| `aggregated_json` | string | Path to Omnileak aggregated_secrets.json |
| `prefiltered_json` | string | Path to prefiltered.json |
| `raw_findings` | integer | Total raw findings from Omnileak |
| `pre_filtered` | integer | Number of auto-FPs from pre-filter |
| `tier` | string | `"skip"` / `"lightweight"` / `"standard"` / `"large"` |
| `priority` | integer | Sort key (higher = processed first) |
| `status` | string | `"pending"` / `"in_progress"` / `"done"` / `"failed"` |
| `started_at` | string/null | ISO 8601 when processing began |
| `completed_at` | string/null | ISO 8601 when processing finished |
| `risk_score` | integer/null | Computed risk score (0-100) |
| `tps` | integer/null | True positive count |
| `fps` | integer/null | False positive count |
| `dups` | integer/null | Duplicate count |
| `duration_s` | integer/null | Processing duration in seconds |
| `triage_json` | string/null | Path to output triage-results JSON |
| `validated` | boolean/null | Whether validator passed |
| `error` | string/null | Error message if failed |

## Status Transitions

```
pending → in_progress → done
                      → failed
```

On `--resume`, repos stuck in `in_progress` for >10 minutes are recovered back to `pending`.

## Tier Assignment

| Tier | Condition (needs_triage count) |
|---|---|
| skip | 0 findings |
| lightweight | 1-20 findings |
| standard | 21-200 findings |
| large | 200+ findings |

## Python API

```python
from core.ai.manifest import create_manifest, load_manifest, update_repo, next_pending, recover_stale

# Create from pre-filter batch results
manifest = create_manifest(prefilter_results, output_dir="./results")

# Resume: load + recover stale
manifest = load_manifest("./results/manifest.json")
recover_stale(manifest["path"], stale_minutes=10)

# Iterate
repo = next_pending(manifest)
update_repo(manifest["path"], repo["name"], status="in_progress",
            started_at=datetime.now(timezone.utc).isoformat())
# ... process repo ...
update_repo(manifest["path"], repo["name"], status="done",
            risk_score=42, tps=5, fps=30, dups=3, validated=True,
            completed_at=datetime.now(timezone.utc).isoformat())
```

## CLI

```bash
python3 -m core.ai.manifest --status <manifest.json>
```
