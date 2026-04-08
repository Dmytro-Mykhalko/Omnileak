import os
import sys
import argparse
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Automatically add the local ./bin directory to the PATH if it exists
_local_bin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")
if os.path.isdir(_local_bin):
    os.environ["PATH"] = _local_bin + os.pathsep + os.environ.get("PATH", "")

from scanners import GitleaksScanner, TrufflehogScanner, DetectSecretsScanner, TitusScanner, resolve_repo_url
from core import Deduplicator, Reporter, ensure_tools, read_repo_list, clone_repos, save_commit_info

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


def scan_single_repo(repo_path, output_dir, tool_names, timeout):
    """Run selected scanners against a single repository and return all findings.

    Tools within the repo always run concurrently (one thread per tool).
    """
    repo_name = os.path.basename(repo_path.rstrip("/"))
    repo_out = os.path.join(output_dir, repo_name)
    os.makedirs(repo_out, exist_ok=True)

    # Resolve the remote URL once for the whole repo
    repo_url = resolve_repo_url(repo_path)

    scanners = []
    for name in tool_names:
        cls = SCANNER_REGISTRY.get(name)
        if cls:
            scanners.append(cls(repo_path, repo_out, timeout, repo_url=repo_url))
        else:
            logger.warning(f"Unknown tool '{name}'. Available: {list(SCANNER_REGISTRY.keys())}")

    all_findings = []
    with ThreadPoolExecutor(max_workers=len(scanners) or 1) as executor:
        results = executor.map(run_scanner, scanners)
        for res in results:
            all_findings.extend(res)

    return all_findings, repo_out


def process_repo(repo_path, output_dir, tool_names, timeout):
    """Scan a single repo, deduplicate, generate per-repo reports.

    Designed to be called from a thread pool for repo-level parallelism.
    Returns the raw (pre-dedup) findings for global aggregation.
    """
    logger.info(f"--- Scanning repository: {repo_path} ---")

    # Record the latest commit before scanning so we can track history
    repo_name = os.path.basename(repo_path.rstrip("/"))
    repo_out_for_commit = os.path.join(output_dir, repo_name)
    os.makedirs(repo_out_for_commit, exist_ok=True)
    save_commit_info(repo_path, repo_out_for_commit)

    findings, repo_out = scan_single_repo(repo_path, output_dir, tool_names, timeout)

    repo_name = os.path.basename(repo_path.rstrip("/"))
    dedup = Deduplicator()
    dedup.load(findings)
    repo_deduped = dedup.deduplicate()
    reporter = Reporter(repo_out, repo_name=repo_name)
    reporter.generate_json(repo_deduped)
    reporter.generate_excel(repo_deduped)

    return findings


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
        "--repo", default=None,
        help="Path to a single repository OR a directory containing multiple repositories.",
    )
    parser.add_argument("--out", required=True, help="Output directory for reports.")
    parser.add_argument(
        "--clone-urls", default=None,
        help="Path to a .txt file listing repository URLs (one per line). "
             "Repos are cloned via SSH into --clone-dir before scanning.",
    )
    parser.add_argument(
        "--clone-dir", default=None,
        help="Directory to clone repositories into. Required when --clone-urls is used.",
    )
    parser.add_argument(
        "--threads", type=int, default=1,
        help="Number of repos to scan in parallel (default: 1). "
             "Tools within each repo always run in parallel (4 tools = 4 processes) "
             "regardless of this setting. Recommended: no more than 4.",
    )
    parser.add_argument(
        "--timeout", type=int, default=None,
        help="Timeout per tool in seconds (default: no limit).",
    )
    parser.add_argument(
        "--tools", nargs="+", default=list(SCANNER_REGISTRY.keys()),
        help=f"Tools to run (default: all). Choices: {list(SCANNER_REGISTRY.keys())}",
    )
    args = parser.parse_args()

    # At least one source of repos is required
    if not args.repo and not args.clone_urls:
        logger.error("At least one of --repo or --clone-urls is required.")
        sys.exit(1)

    # Validate --repo path when provided
    if args.repo and not os.path.exists(args.repo):
        logger.error(f"Repository path does not exist: {args.repo}")
        sys.exit(1)

    # --clone-dir is required when --clone-urls is used
    if args.clone_urls and not args.clone_dir:
        logger.error("--clone-dir is required when --clone-urls is used.")
        sys.exit(1)

    if args.clone_urls and not os.path.isfile(args.clone_urls):
        logger.error(f"Clone URLs file does not exist: {args.clone_urls}")
        sys.exit(1)

    os.makedirs(args.out, exist_ok=True)

    # Auto-install any missing CLI tools before scanning
    ensure_tools(args.tools, _local_bin)

    repos = []

    # Discover local repos from --repo
    if args.repo:
        repos.extend(discover_repos(args.repo))

    # Clone and add repos from --clone-urls
    if args.clone_urls:
        urls = read_repo_list(args.clone_urls)
        if not urls:
            logger.error(f"No repository URLs found in {args.clone_urls}")
            sys.exit(1)
        logger.info(f"Read {len(urls)} repository URL(s) from {args.clone_urls}")
        cloned = clone_repos(urls, args.clone_dir)
        if not cloned:
            logger.error("No repositories were successfully cloned.")
            if not repos:
                logger.error("No repositories to scan. Aborting.")
                sys.exit(1)
        repos.extend(cloned)

    if not repos:
        logger.error("No repositories to scan. Aborting.")
        sys.exit(1)

    logger.info(f"Discovered {len(repos)} repository(ies) to scan.")

    global_start = time.time()
    all_findings = []

    # Scan repos in parallel (--threads controls concurrency)
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(process_repo, repo, args.out, args.tools, args.timeout): repo
            for repo in repos
        }
        for future in as_completed(futures):
            repo = futures[future]
            try:
                findings = future.result()
                all_findings.extend(findings)
            except Exception:
                logger.exception(f"Failed to process repository: {repo}")

    # Global aggregated reports (across all repos)
    if len(repos) > 1:
        logger.info("--- Generating global aggregated reports ---")
        global_dedup = Deduplicator()
        global_dedup.load(all_findings)
        global_deduped = global_dedup.deduplicate()
        global_reporter = Reporter(args.out, repo_name="global")
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
