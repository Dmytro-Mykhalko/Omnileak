import os
import sys
import argparse
import logging
import time
from concurrent.futures import ThreadPoolExecutor

# Automatically add the local ./bin directory to the PATH if it exists
_local_bin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")
if os.path.isdir(_local_bin):
    os.environ["PATH"] = _local_bin + os.pathsep + os.environ.get("PATH", "")

from scanners import GitleaksScanner, TrufflehogScanner, DetectSecretsScanner, TitusScanner
from core import Deduplicator, Reporter, ensure_tools

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

SCANNER_REGISTRY = {
    "gitleaks": GitleaksScanner,
    "trufflehog": TrufflehogScanner,
    "detect-secrets": DetectSecretsScanner,
    "titus": TitusScanner,
}


def run_scanner(scanner_instance):
    """Execute a single scanner and return its parsed findings."""
    return scanner_instance.execute()


def discover_repos(path):
    """
    If `path` is a single git repo, return [path].
    If `path` is a directory containing multiple repos, return all of them.
    """
    path = os.path.abspath(path)
    if os.path.isdir(os.path.join(path, ".git")):
        return [path]

    # Otherwise, look for subdirectories that are git repos
    repos = []
    for entry in sorted(os.listdir(path)):
        full = os.path.join(path, entry)
        if os.path.isdir(full) and os.path.isdir(os.path.join(full, ".git")):
            repos.append(full)

    if not repos:
        # Fallback: treat the given path as a single target even if not a git repo
        # (some tools like detect-secrets can still scan flat directories)
        logger.warning(f"No .git directories found under {path}. Treating it as a single scan target.")
        return [path]

    return repos


def scan_single_repo(repo_path, output_dir, tool_names, timeout, threads):
    """Run selected scanners against a single repository and return all findings."""
    repo_name = os.path.basename(repo_path.rstrip("/"))
    repo_out = os.path.join(output_dir, repo_name)
    os.makedirs(repo_out, exist_ok=True)

    scanners = []
    for name in tool_names:
        cls = SCANNER_REGISTRY.get(name)
        if cls:
            scanners.append(cls(repo_path, repo_out, timeout))
        else:
            logger.warning(f"Unknown tool '{name}'. Available: {list(SCANNER_REGISTRY.keys())}")

    all_findings = []
    with ThreadPoolExecutor(max_workers=min(threads, len(scanners) or 1)) as executor:
        results = executor.map(run_scanner, scanners)
        for res in results:
            all_findings.extend(res)

    return all_findings, repo_out


def print_summary(findings, duration):
    """Print a human-readable summary of the scan results."""
    tool_counts = {}
    for f in findings:
        for t in f["found_by"]:
            tool_counts[t] = tool_counts.get(t, 0) + 1

    print("\n" + "=" * 60)
    print("  SCAN SUMMARY")
    print("=" * 60)
    print(f"  Total unique findings : {len(findings)}")
    for tool in sorted(tool_counts):
        print(f"  {tool:20s} : {tool_counts[tool]}")
    print(f"  Total scan time       : {duration:.1f}s")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Omnileak — scan Git repos for hardcoded secrets with multiple tools."
    )
    parser.add_argument(
        "--repo", required=True,
        help="Path to a single repository OR a directory containing multiple repositories.",
    )
    parser.add_argument("--out", required=True, help="Output directory for reports.")
    parser.add_argument("--threads", type=int, default=4, help="Parallel threads (default: 4).")
    parser.add_argument(
        "--timeout", type=int, default=None,
        help="Timeout per tool in seconds (default: no limit).",
    )
    parser.add_argument(
        "--tools", nargs="+", default=list(SCANNER_REGISTRY.keys()),
        help=f"Tools to run (default: all). Choices: {list(SCANNER_REGISTRY.keys())}",
    )
    args = parser.parse_args()

    # Validate paths
    if not os.path.exists(args.repo):
        logger.error(f"Repository path does not exist: {args.repo}")
        sys.exit(1)

    os.makedirs(args.out, exist_ok=True)

    # Auto-install any missing CLI tools before scanning
    ensure_tools(args.tools, _local_bin)

    repos = discover_repos(args.repo)
    logger.info(f"Discovered {len(repos)} repository(ies) to scan.")

    global_start = time.time()
    all_findings = []

    for repo in repos:
        logger.info(f"--- Scanning repository: {repo} ---")
        findings, repo_out = scan_single_repo(repo, args.out, args.tools, args.timeout, args.threads)
        all_findings.extend(findings)

        # Per-repo reports
        dedup = Deduplicator()
        dedup.load(findings)
        repo_deduped = dedup.deduplicate()
        reporter = Reporter(repo_out)
        reporter.generate_json(repo_deduped)
        reporter.generate_excel(repo_deduped)

    # Global aggregated reports (across all repos)
    if len(repos) > 1:
        logger.info("--- Generating global aggregated reports ---")
        global_dedup = Deduplicator()
        global_dedup.load(all_findings)
        global_deduped = global_dedup.deduplicate()
        global_reporter = Reporter(args.out)
        global_reporter.generate_json(global_deduped)
        global_reporter.generate_excel(global_deduped)
    else:
        global_dedup = Deduplicator()
        global_dedup.load(all_findings)
        global_deduped = global_dedup.deduplicate()

    duration = time.time() - global_start
    print_summary(global_deduped, duration)
    logger.info("Done.")


if __name__ == "__main__":
    main()
