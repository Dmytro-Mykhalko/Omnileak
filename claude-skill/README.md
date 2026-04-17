# Claude Code Skill — Secrets Detection Pipeline

AI-powered triage layer on top of Omnileak. Classifies scanner findings as true/false positives, performs deep analysis for composite vulnerabilities, and generates structured reports.

## Install

```bash
cd /path/to/Omnileak
./claude-skill/install.sh
```

Copies the skill to `~/.claude/commands/` and sets `OMNILEAK_HOME` in your shell profile.

## Usage

In Claude Code (any directory):

```
/scan-secrets                                          # full scan on cwd
/scan-secrets --repo ~/Projects/my-app                 # full scan on specific repo
/scan-secrets --results ./scanning                     # triage existing Omnileak results
/scan-secrets --results ./scanning --repo ~/src        # triage + deep analysis (reads source)
/scan-secrets --resume ./scanning/manifest.json        # resume interrupted multi-repo triage
/scan-secrets --resume ./manifest.json --retry repo-a  # retry specific failed repos
```

## Architecture

### Single-repo flow

The orchestrator runs everything inline in the current conversation:

```
Omnileak scan → Pre-filter → AI classification → Deep analysis → Validate → Excel + reports
```

### Multi-repo flow

Each repo gets a **fresh sub-agent with clean context** — no accumulated findings from prior repos. The orchestrator stays lightweight (~50K tokens):

```
Orchestrator
  ├── runs Omnileak scan (if not --results)
  ├── runs pre-filter batch on all repos
  ├── creates manifest.json (priority-sorted)
  ├── FOR each repo (sequential, one at a time):
  │     ├── skip-tier (0 findings)? → handle inline
  │     └── spawn sub-agent with agent-prompt.md
  │           └── clean context: rules + schema + this repo only
  │               classify → validate → Excel → markdown → return
  ├── writes pipeline-improvements.md (once, covers all repos)
  └── prints batch summary
```

Sub-agents inherit the model from the parent conversation (Opus/Sonnet/Haiku — whatever you're running).

### Pipeline stages

| Stage | Module | What it does |
|---|---|---|
| Pre-filter | `core/ai/prefilter.py` | Deterministic FP removal (lock files, vendor, minified JS). Enriches remaining findings with TP hints, entropy, sensitivity tags, Docker credential decoding. |
| Manifest | `core/ai/manifest.py` | Tracks per-repo status, tier, priority. Enables resume/retry. |
| AI Classification | Agent (inline or sub-agent) | TP-by-default: examines actual secret values, reads source files, follows closed FP list. |
| Deep Analysis | Agent reads `deep-analysis.md` | Composite vulns, credential reuse, Docker base64, secrets in .sql/.dist/CI files. |
| Validation | `core/ai/triage_validator.py` | Hard gate: schema, counts, sequential IDs, coverage, risk score, file naming. |
| Excel Report | `core/ai/triage_reporter.py` | Summary + All Findings tabs with severity colors and commit hyperlinks. |
| Markdown Report | Agent writes per-repo | Executive summary, risk score, remediation priorities. |

### Pre-filter enrichment

Every finding in `needs_triage` gets these tags:

| Tag | Meaning |
|---|---|
| `tp_hint` | Known credential prefix (AKIA, ghp\_, xoxb\-, sk\_live\_, etc.) — overrides FP rules |
| `entropy` / `high_entropy` | Shannon entropy; flagged if >= 4.0 bits and >= 20 chars |
| `sensitivity` | File-path label: production, staging, infrastructure, certificate, config, test |
| `decoded_docker_creds` | Extracted user:pass from .dockerconfigjson base64 blobs |

### Classification rules

TP-by-default with a closed FP list. Only 8 specific provable conditions can produce an FP. Key principles:

- When in doubt → TP (developers re-check TPs; nobody re-checks FPs)
- Examine actual `secret_value`, never classify by `secret_type` alone
- Certificate/key files (.pem, .key) are always TP
- DUPLICATEs require exact same value — different value = separate finding
- "test" in filename does not mean fake credential

See `scan-secrets/triage-rules.md` for the full ruleset.

## File Structure

```
claude-skill/
├── install.sh                      # Installer script
├── scan-secrets.md                 # Main orchestrator prompt
├── README.md                       # This file
└── scan-secrets/
    ├── triage-rules.md             # TP/FP classification rules, severity matrix
    ├── deep-analysis.md            # Composite vuln checks, credential reuse
    ├── json-schema.md              # Output JSON schema, finding examples
    ├── reporting.md                # Validator, Excel, markdown report instructions
    ├── manifest-schema.md          # Manifest format for resumable multi-repo
    └── agent-prompt.md             # Self-contained prompt for per-repo sub-agents
```

## Output per repo

```
<repo>/
├── <repo>_triage-results_<score>.json    # Full triage JSON (all findings)
├── <repo>_triage-results_<score>.xlsx    # Excel (Summary + All Findings)
└── <repo>_secrets-triage-report_<score>.md  # Markdown summary
```

Multi-repo scans also produce:
```
<output_dir>/
├── manifest.json                   # Progress tracking
└── pipeline-improvements.md        # One report for the entire scan
```

## Updating

After pulling new Omnileak code, re-run the installer:

```bash
cd /path/to/Omnileak && ./claude-skill/install.sh
```
