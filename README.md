# 🔐 Omnileak

A Python-based orchestrator that scans Git repositories for hardcoded secrets using **four industry-standard tools at once**, deduplicates their results, and produces clean reports ready for review.

| Tool | What it does | History scan |
|------|-------------|:------------:|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Regex-based secret detection | ✅ Full git history |
| [Trufflehog](https://github.com/trufflesecurity/trufflehog) | Entropy + regex detection with verified secrets | ✅ Full git history |
| [Detect Secrets](https://github.com/Yelp/detect-secrets) | Yelp's plugin-based scanner | ❌ Current files only* |
| [Titus](https://github.com/praetorian-inc/titus) | High-perf scanner with 487 rules (successor to Noseyparker) | ✅ Full git history |

\* For detect-secrets, commit hashes are resolved via `git blame`.

---

## Features

- **Zero setup** — all 4 CLI tools are **auto-installed** on first run if missing (downloaded to a local `./bin/` folder, no sudo needed)
- **Multi-repo support** — point at one repo or a directory of 100 repos; each gets its own report
- **Parallel execution** — repos scan concurrently (`--threads`), and all 4 tools run in parallel within each repo
- **Smart deduplication** — same secret found by 3 tools = 1 row with `found_by: gitleaks, titus, trufflehog`
- **Whitespace-normalized matching** — different formatting of the same key across tools won't create duplicates
- **Selective tool execution** — run all tools or pick specific ones with `--tools`
- **Fault tolerant** — if a tool crashes or is missing, the rest continue normally
- **Clickable commit links** — the commit column in Excel links directly to the file at that commit on GitHub / GitLab
- **Complete output** — every row in Excel/JSON has `file_path`, `secret_value`, `line_number`, `commit`, `secret_type`, `found_by`

---

## Requirements

- **Python 3.8+**
- **Git** (must be in PATH — used for `git blame` to resolve commit hashes)
- **Internet connection** on first run (to auto-download scanner binaries)
- **macOS** (darwin arm64/amd64) or **Linux** (amd64/arm64)

> You do **not** need to manually install Gitleaks, Trufflehog, Titus, or Detect Secrets. The tool handles this automatically.

---

## Quick Start

```bash
# 1. Clone the project
git clone https://github.com/Dmytro-Mykhalko/Omnileak.git
cd Omnileak

# 2. Create a virtual environment and install Python deps
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Scan a repo (CLI tools auto-install on first run)
python main.py --repo /path/to/your-repo --out ./results
```

On first run you'll see:
```
[installer] gitleaks not found. Attempting auto-install...
[installer] gitleaks installed successfully at ./bin/gitleaks
[installer] trufflehog not found. Attempting auto-install...
[installer] trufflehog installed successfully at ./bin/trufflehog
[installer] titus not found. Attempting auto-install...
[installer] titus installed successfully at ./bin/titus
```

Subsequent runs skip the download — the binaries are cached in `./bin/`.

### Alternative: install tools upfront

If you prefer to install everything before the first scan:

```bash
./install_deps.sh
```

---

## CLI Reference

```
python main.py --repo <PATH> --out <PATH> [--tools ...] [--threads N] [--timeout N]
```

| Flag | Required | Default | Description |
|------|:--------:|---------|-------------|
| `--repo` | **Yes** | — | Path to a single Git repo, **or** a directory containing multiple cloned repos. |
| `--out` | **Yes** | — | Output directory. Created automatically if it doesn't exist. |
| `--tools` | No | all 4 | Space-separated list. Choices: `gitleaks`, `trufflehog`, `detect-secrets`, `titus` |
| `--threads` | No | `4` | Number of repos to scan in parallel. Each repo runs all 4 tools concurrently regardless of this setting. See [Threading model](#threading-model) below. |
| `--timeout` | No | no limit | Max seconds per tool per repo. Omit for unrestricted deep history scans. |

### Threading model

`--threads` controls **repo-level parallelism** — how many repositories are scanned at the same time. Within each repo, all selected tools always run concurrently (one thread per tool).

| `--threads` | Repos in parallel | Tools per repo | Max concurrent processes |
|:-----------:|:-----------------:|:--------------:|:------------------------:|
| 1 | 1 | 4 | 4 |
| 2 | 2 | 4 | 8 |
| **4** (default) | 4 | 4 | 16 |
| 8 | 8 | 4 | 32 |

> ⚠️ **Recommendation:** keep `--threads` at **4 or below** for most machines. Each repo spawns 4 tool processes that scan full git history, which is CPU- and I/O-intensive. Going above 4 can saturate disk I/O and slow things down rather than speed them up.

### Examples

```bash
# Scan a single repo with all tools
python main.py --repo ~/projects/my-app --out ./results

# Scan a directory containing 50 repos (4 repos at a time by default)
python main.py --repo ~/all-repos --out ./results

# Only run Gitleaks and Titus
python main.py --repo ~/projects/my-app --out ./results --tools gitleaks titus

# Set a 30-minute timeout per tool
python main.py --repo ~/projects/huge-monorepo --out ./results --timeout 1800
```

---

## 💡 Tips for Effective Scanning

### 1. Organize your workspace

Create a dedicated project folder for each engagement. Clone all target repos into a `src/` subdirectory, then point Omnileak's `--out` to the project root. This keeps source code and results neatly separated:

```
my-audit/
├── src/                        ← clone repos here
│   ├── backend-api/
│   ├── frontend-app/
│   └── infra-config/
└── results/                    ← Omnileak writes reports here
    ├── global_aggregated_secrets.json
    ├── global_secrets_report.xlsx
    ├── backend-api/
    ├── frontend-app/
    └── infra-config/
```

```bash
mkdir -p my-audit/src && cd my-audit/src
git clone <repo-1-url>
git clone <repo-2-url>
git clone <repo-3-url>
cd ..
python /path/to/Omnileak/main.py --repo ./src --out ./results
```

### 2. Reviewing the Excel report

Once the scan completes, open `secrets_report.xlsx` and try this workflow:

1. **Sort by `file_path` A→Z** — groups findings by file, making it much easier to spot duplicates and understand context.
2. **Add your own columns** next to the report data for tracking:
   - **Status** — e.g. `Vulnerable`, `False Positive`, `Rotated`, `To Investigate`
   - **Severity** — e.g. `Critical`, `High`, `Medium`, `Low`
   - **Comments** — your notes on each finding
3. **Use auto-filters** (already enabled on every column) to quickly slice the data — filter by `secret_type`, `repository`, `found_by`, or your custom Status column.
4. **Check the per-tool tabs** (Gitleaks, Trufflehog, etc.) if you want to see what each tool found individually before deduplication.

### 3. Handling 404 commit links

The **commit** column is a clickable link to the affected file at the exact commit (e.g. `https://github.com/org/repo/blob/<commit>/<file>#L<line>`).

> If a link returns **404** — the file was most likely deleted or renamed after that commit. To view the commit itself, replace `/blob/` with `/commit/` in the URL and remove the file path and line anchor.
>
> For example, change:
> ```
> https://github.com/org/repo/blob/cb37fba.../docs/some-file.md#L5
> ```
> to:
> ```
> https://github.com/org/repo/commit/cb37fba...
> ```

---

## Output Structure

### Single-repo scan

```
results/
└── my-app/
    ├── gitleaks_raw.json           ← unmodified Gitleaks output
    ├── trufflehog_raw.json         ← unmodified Trufflehog NDJSON
    ├── detect_secrets_raw.json     ← unmodified Detect Secrets output
    ├── titus_raw.json              ← unmodified Titus JSON report
    ├── titus.ds/                   ← Titus internal datastore (SQLite)
    ├── aggregated_secrets.json     ← ✅ all findings, deduplicated, normalized
    └── secrets_report.xlsx         ← ✅ Excel report (General + per-tool tabs)
```

### Multi-repo scan

```
results/
├── global_aggregated_secrets.json  ← ✅ global: all repos combined
├── global_secrets_report.xlsx      ← ✅ global: Excel across all repos
├── repo-alpha/
│   ├── gitleaks_raw.json
│   ├── trufflehog_raw.json
│   ├── detect_secrets_raw.json
│   ├── titus_raw.json
│   ├── titus.ds/
│   ├── aggregated_secrets.json     ← per-repo
│   └── secrets_report.xlsx         ← per-repo
├── repo-beta/
│   └── ...
└── repo-gamma/
    └── ...
```

---

## JSON Output Format

Each entry in `aggregated_secrets.json`:

```json
{
    "id": "a1b2c3...sha256",
    "repository": "my-app",
    "file_path": "code/.env.prod",
    "line_number": 22,
    "secret_type": "aws-access-token",
    "secret_value": "AKIAIOSFODNN7EXAMPLE",
    "commit_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "repo_url": "https://github.com/org/my-app",
    "found_by": ["gitleaks", "titus", "trufflehog"]
}
```

| Field | Description |
|-------|-------------|
| `id` | SHA-256 hash of `repo + file + normalized_secret`. Used for deduplication. |
| `repository` | Repo folder name. |
| `file_path` | Relative path from repo root. |
| `line_number` | Line number where the secret appears. |
| `secret_type` | Category from the tool (e.g., `aws-access-token`, `Generic Password`, `np.pem.1`). |
| `secret_value` | The actual secret string extracted from the file. |
| `commit_hash` | Git commit that introduced or last touched the line. Resolved via tool-native data or `git blame`. |
| `repo_url` | HTTPS URL of the git remote (resolved from `origin`). Used to build clickable commit links. |
| `found_by` | Sorted list of tools that detected this secret. |

### Deduplication logic

1. **Pass 1** — group by `id` (repo + file + whitespace-normalized secret). Merge `found_by`, fill empty fields.
2. **Pass 2** — group by repo + secret only (ignoring file path). Catches the same credential reported with different paths by different tools.
3. **Pass 3** — proximity dedup: findings on the same file + line + commit where one secret value contains the other are merged (handles tools extracting different amounts of context).

---

## Excel Output Format

`secrets_report.xlsx` has these tabs:

| Tab | Contents |
|-----|----------|
| **General** | All deduplicated findings. Primary review sheet. |
| **Gitleaks** | Findings where `found_by` includes `gitleaks`. |
| **Trufflehog** | Findings where `found_by` includes `trufflehog`. |
| **Detect-secrets** | Findings where `found_by` includes `detect-secrets`. |
| **Titus** | Findings where `found_by` includes `titus`. |

Excel columns: `id`, `repository`, `file_path`, `line_number`, `secret_type`, `secret_value`, `commit`, `found_by`

- The **commit** column is a clickable hyperlink pointing to the file at that commit on GitHub/GitLab.
- `found_by` is rendered as a comma-separated string (e.g., `gitleaks, titus`) for clean Google Sheets import.
- Auto-filters are enabled on every column in every sheet.

---

## Running Tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/ -v
```

Tests use mock data and mocked subprocesses — **no CLI tools need to be installed**.

| File | Coverage |
|------|----------|
| `tests/test_parsers.py` | All 4 tool parsers: valid data, empty, corrupt, edge cases |
| `tests/test_deduplicator.py` | Merging, whitespace normalization, cross-tool path dedup |
| `tests/test_orchestrator.py` | Pre-flight checks, subprocess errors, timeout handling |
| `tests/test_reporter.py` | JSON + Excel generation, tab structure, `found_by` formatting, commit hyperlinks |

---

## Project Structure

```
Omnileak/
├── main.py                     ← CLI entry point & orchestrator
├── requirements.txt            ← Python dependencies
├── install_deps.sh             ← Optional manual tool installer
├── conftest.py                 ← pytest path config
├── .gitignore
├── LICENSE
├── README.md
├── scanners/
│   ├── __init__.py
│   ├── base.py                 ← BaseScanner ABC + shared utilities
│   ├── gitleaks.py
│   ├── trufflehog.py
│   ├── detect_secrets.py
│   └── titus.py
├── core/
│   ├── __init__.py
│   ├── installer.py            ← Auto-downloads missing CLI tools
│   ├── deduplicator.py         ← 3-pass dedup engine
│   └── reporter.py             ← JSON + Excel report generator
└── tests/
    ├── __init__.py
    ├── test_parsers.py
    ├── test_deduplicator.py
    ├── test_orchestrator.py
    └── test_reporter.py
```

---

## Adding a New Scanner

1. Create `scanners/my_tool.py`, inherit from `BaseScanner`:
   ```python
   from .base import BaseScanner

   class MyToolScanner(BaseScanner):
       def __init__(self, repo_path, output_dir, timeout=None, repo_url=""):
           super().__init__(repo_path, output_dir, timeout, repo_url=repo_url)
           self.tool_name = "MyTool"
           self.cli_command = "mytool"
           self.raw_output = os.path.join(output_dir, "mytool_raw.json")

       def run_scan(self):
           # Run the CLI and save raw output
           ...

       def parse_results(self):
           # Parse raw JSON → list of unified dicts
           ...
   ```

2. Register in `main.py`:
   ```python
   SCANNER_REGISTRY["mytool"] = MyToolScanner
   ```

3. Optionally add an auto-installer in `core/installer.py`.

4. Add tests in `tests/test_parsers.py`.

---

## FAQ

**Q: Do I need to install Gitleaks / Trufflehog / Titus manually?**
No. On the first run, any missing tool is automatically downloaded to `./bin/`. No sudo, no global install.

**Q: What if one of the tools fails mid-scan?**
The orchestrator catches the error, logs it, and continues with the other tools. You still get results from whatever succeeded.

**Q: How does deduplication work across tools?**
Secret values are whitespace-normalized before hashing. If Gitleaks reports `-----BEGIN KEY-----\n    MHc` and Titus reports `-----BEGIN KEY-----\nMHc`, they produce the same hash and merge into one row.

**Q: Can I scan repos that aren't Git repositories?**
Yes — detect-secrets and Titus can scan plain directories. The tool will log a warning and proceed.

**Q: Where are the downloaded binaries stored?**
In `./bin/` inside the project directory. This folder is in `.gitignore` and won't be committed. Delete it to force a fresh download.

**Q: My scan is taking too long — what can I do?**
Try reducing the number of tools (`--tools gitleaks trufflehog`), setting a `--timeout`, or keeping `--threads` at 4 or below. Titus and Trufflehog scanning full git history on large repos can take several minutes each.

---

## License

MIT
