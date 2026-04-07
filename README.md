# 🔐 Omnileak

A Python-based orchestrator that scans Git repositories for hardcoded secrets using **four industry-standard tools at once**, deduplicates their results, and produces clean reports ready for review.

| Tool | What it does | History scan |
|------|-------------|:------------:|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Regex-based secret detection | ✅ Full git history |
| [Trufflehog](https://github.com/trufflesecurity/trufflehog) | Entropy + regex detection with verified secrets | ✅ Full git history |
| [Detect Secrets](https://github.com/Yelp/detect-secrets) | Yelp's plugin-based scanner | ❌ Current files only* |
| [Titus](https://github.com/praetorian-inc/titus) | High-perf scanner with 487 rules (successor to Noseyparker) | ✅ Full git history |

\* Commit hashes resolved via `git blame`.

**Key features:** zero setup (all tools auto-installed on first run), multi-repo support, parallel execution, smart 3-pass deduplication, clickable commit links in Excel, fault tolerant.

---

## Quick Start

```bash
git clone https://github.com/Dmytro-Mykhalko/Omnileak.git
cd Omnileak
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python main.py --repo /path/to/your-repo --out ./results
```

Tools auto-download to `./bin/` on first run. To install them upfront instead:

```bash
./install_deps.sh
```

---

## CLI Reference

```
python main.py --repo <PATH> --out <PATH> [--tools ...] [--threads N] [--timeout N]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--repo` | **required** | Path to a Git repo **or** a directory containing multiple repos. |
| `--out` | **required** | Output directory for reports. |
| `--tools` | all 4 | Space-separated list: `gitleaks`, `trufflehog`, `detect-secrets`, `titus` |
| `--threads` | `1` | Number of **repos** (projects) to scan in parallel. All 4 tools always run concurrently within each repo regardless of this value. **Recommended: no more than 4** — each repo spawns 4 tool processes, so `--threads 4` = up to 16 concurrent processes. |
| `--timeout` | no limit | Max seconds per tool per repo. |

```bash
# Scan multiple repos, 2 projects at a time
python main.py --repo ~/all-repos --out ./results --threads 2

# Only run Gitleaks and Titus, 30-min timeout
python main.py --repo ~/my-app --out ./results --tools gitleaks titus --timeout 1800
```

---

## Output Structure

### Single-repo scan

```
results/
└── my-app/
    ├── my-app_gitleaks_raw.json           ← unmodified Gitleaks output
    ├── my-app_trufflehog_raw.json         ← unmodified Trufflehog NDJSON
    ├── my-app_detect_secrets_raw.json     ← unmodified Detect Secrets output
    ├── my-app_titus_raw.json              ← unmodified Titus JSON report
    ├── titus.ds/                           ← Titus internal datastore
    ├── my-app_aggregated_secrets.json     ← ✅ deduplicated findings
    └── my-app_secrets_report.xlsx         ← ✅ Excel report (General + per-tool tabs)
```

### Multi-repo scan

```
results/
├── global_aggregated_secrets.json     ← ✅ all repos combined
├── global_secrets_report.xlsx         ← ✅ Excel across all repos
├── repo-alpha/
│   ├── repo-alpha_aggregated_secrets.json
│   ├── repo-alpha_secrets_report.xlsx
│   └── ...raw outputs...
├── repo-beta/
│   └── ...
└── repo-gamma/
    └── ...
```

Each Excel file has a **General** tab (all deduplicated findings) plus one tab per tool. Columns: `id`, `repository`, `file_path`, `line_number`, `secret_type`, `secret_value`, `commit` (clickable link), `found_by`.

---

## 💡 Tips for Effective Scanning

### Organize your workspace

Create a project folder for each engagement. Clone repos into `src/`, point output elsewhere:

```
my-audit/
├── src/                        ← git clone repos here
│   ├── backend-api/
│   ├── frontend-app/
│   └── infra-config/
└── results/                    ← Omnileak writes here
```

```bash
mkdir -p my-audit/src && cd my-audit/src
git clone <repo-url-1>
git clone <repo-url-2>
cd ..
python /path/to/Omnileak/main.py --repo ./src --out ./results
```

### Reviewing the Excel report

1. **Sort by `file_path` A→Z** — groups findings by file, duplicates become obvious.
2. **Add your own columns** for tracking:
   - **Status** — `Vulnerable` / `False Positive` / `Rotated` / `To Investigate`
   - **Severity** — `Critical` / `High` / `Medium` / `Low`
   - **Comments** — your notes
3. **Use the auto-filters** (already enabled on every column) to slice by `secret_type`, `repository`, `found_by`, or your custom columns.
4. **Check per-tool tabs** (Gitleaks, Trufflehog, etc.) to see what each scanner found before deduplication.

### Commit links return 404?

The **commit** column links to the file at that commit (`/blob/<hash>/<file>`). If the file was deleted or renamed, the link will 404. Quick fix — replace `/blob/` with `/commit/` in the URL and remove the file path:

```
Before (404):  https://github.com/org/repo/blob/cb37fba.../docs/some-file.md#L5
After (works): https://github.com/org/repo/commit/cb37fba...
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

No CLI tools needed — tests use mocked data.

---

## FAQ

**Q: Do I need to install the scanner tools manually?**
No. They auto-download to `./bin/` on first run. Or run `./install_deps.sh` to install upfront. Delete `./bin/` to force a re-download.

**Q: What if a tool fails?**
The rest continue. You still get results from whatever succeeded.

**Q: Scan is too slow?**
Use fewer tools (`--tools gitleaks trufflehog`), set a `--timeout`, or increase `--threads` (but stay at 4 or below).

---

## License

MIT
