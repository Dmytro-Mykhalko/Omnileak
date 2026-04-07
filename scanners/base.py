import abc
import re
import shutil
import subprocess
import logging
import json
import hashlib
import os
import time

logger = logging.getLogger(__name__)


def normalize_secret(value):
    """Collapse all whitespace to produce a canonical form for comparison.
    
    Different tools format the same secret differently:
      Gitleaks:     '-----BEGIN EC PRIVATE KEY-----\\n    MHcCAQEE...'
      Trufflehog:   '-----BEGIN EC PRIVATE KEY-----\\nMHcCAQEE...'
    By stripping ALL whitespace we get the same hash for both.
    """
    return re.sub(r"\s+", "", value)


def resolve_repo_url(repo_path):
    """Resolve the HTTPS browse URL of the git remote (origin).

    Converts SSH URLs (``git@host:org/repo.git``) to
    ``https://host/org/repo`` so that commit links work in browsers.
    Returns an empty string when the remote cannot be determined.

    This is a standalone function so it can be called **once per repo**
    and the result shared across all scanner instances.
    """
    abs_repo = os.path.abspath(repo_path)
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True,
            cwd=abs_repo, timeout=5, check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            url = result.stdout.strip()
            # SSH → HTTPS  (git@github.com:org/repo.git)
            if url.startswith("git@"):
                url = url.replace(":", "/", 1).replace("git@", "https://")
            # Strip trailing .git
            if url.endswith(".git"):
                url = url[:-4]
            return url
    except Exception as e:
        logger.debug(f"Could not resolve remote URL for {abs_repo}: {e}")
    return ""


class BaseScanner(abc.ABC):
    def __init__(self, repo_path, output_dir, timeout=None, repo_url="",
                 commit_from="", commit_to=""):
        self.repo_path = repo_path
        self.output_dir = output_dir
        self.timeout = timeout
        self.tool_name = "Base"
        self.cli_command = None  # Subclasses must set this (e.g., "gitleaks")
        self.scan_duration = None
        self.repo_name = os.path.basename(repo_path.rstrip("/"))
        self.repo_url = repo_url
        self.commit_from = commit_from
        self.commit_to = commit_to
        self._commits_in_range = None  # lazy-loaded by _get_commits_in_range()

    def _prefixed(self, filename):
        """Prepend repo_name_ to filename."""
        if self.repo_name:
            return f"{self.repo_name}_{filename}"
        return filename

    def is_available(self):
        """Check if the CLI tool is available in PATH before attempting to run it."""
        if self.cli_command is None:
            return False
        found = shutil.which(self.cli_command)
        if found:
            logger.info(f"[{self.tool_name}] Found CLI tool at: {found}")
            return True
        else:
            logger.warning(f"[{self.tool_name}] CLI tool '{self.cli_command}' not found in PATH. Skipping.")
            return False

    def generate_id(self, repo, file_path, secret_value):
        """Generate a deterministic ID for deduplication.
        
        The secret_value is whitespace-normalized so that the same
        credential formatted differently by different tools will
        produce the same ID.
        """
        normalized = normalize_secret(secret_value)
        raw = f"{repo}|{file_path}|{normalized}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def run_command(self, cmd, capture_output=True, env=None):
        logger.info(f"[{self.tool_name}] Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=self.timeout,
                env=env,
                check=False,
            )
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"[{self.tool_name}] Timed out after {self.timeout}s.")
            return None
        except FileNotFoundError as e:
            logger.error(f"[{self.tool_name}] CLI tool not found: {e}")
            return None
        except Exception as e:
            logger.error(f"[{self.tool_name}] Error executing command: {e}")
            return None

    def run_command_to_file(self, cmd, output_path):
        """Run a command and redirect stdout directly to a file."""
        logger.info(f"[{self.tool_name}] Running: {' '.join(cmd)} > {output_path}")
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                result = subprocess.run(
                    cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )
            if result.returncode != 0 and result.stderr:
                logger.warning(f"[{self.tool_name}] stderr: {result.stderr.strip()}")
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"[{self.tool_name}] Timed out after {self.timeout}s.")
            return None
        except FileNotFoundError as e:
            logger.error(f"[{self.tool_name}] CLI tool not found: {e}")
            return None
        except Exception as e:
            logger.error(f"[{self.tool_name}] Error executing command: {e}")
            return None

    # ------------------------------------------------------------------
    # Commit-range helpers
    # ------------------------------------------------------------------

    @property
    def has_commit_range(self):
        """True when the user requested a commit-range scan."""
        return bool(self.commit_from or self.commit_to)

    def _git_log_range(self):
        """Return the ``<from>..<to>`` range string for ``git log`` / ``git rev-list``.

        * Both set   → ``FROM..TO``
        * Only from  → ``FROM..HEAD``
        * Only to    → ``TO``  (all history up to *to*, inclusive)
        """
        if self.commit_from and self.commit_to:
            return f"{self.commit_from}..{self.commit_to}"
        if self.commit_from:
            return f"{self.commit_from}..HEAD"
        # only commit_to
        return self.commit_to

    def _get_commits_in_range(self):
        """Return a *set* of full commit hashes within the requested range.

        The result is cached so repeated calls are free.
        """
        if self._commits_in_range is not None:
            return self._commits_in_range

        if not self.has_commit_range:
            self._commits_in_range = set()
            return self._commits_in_range

        rev_range = self._git_log_range()
        abs_repo = os.path.abspath(self.repo_path)
        try:
            result = subprocess.run(
                ["git", "rev-list", rev_range],
                capture_output=True, text=True,
                cwd=abs_repo, timeout=30, check=False,
            )
            if result.returncode == 0:
                self._commits_in_range = set(result.stdout.strip().splitlines())
            else:
                logger.warning(
                    f"[{self.tool_name}] git rev-list failed for range '{rev_range}': "
                    f"{result.stderr.strip()}"
                )
                self._commits_in_range = set()
        except Exception as e:
            logger.warning(f"[{self.tool_name}] Could not resolve commit range: {e}")
            self._commits_in_range = set()

        logger.info(
            f"[{self.tool_name}] Commit range '{rev_range}' contains "
            f"{len(self._commits_in_range)} commit(s)."
        )
        return self._commits_in_range

    def _filter_by_commit_range(self, findings):
        """Drop findings whose commit_hash is outside the requested range."""
        allowed = self._get_commits_in_range()
        if not allowed:
            return findings  # nothing to filter against

        before = len(findings)
        filtered = [f for f in findings if f.get("commit_hash") in allowed]
        dropped = before - len(filtered)
        if dropped:
            logger.info(
                f"[{self.tool_name}] Commit-range filter: kept {len(filtered)}, "
                f"dropped {dropped} outside range."
            )
        return filtered

    # ------------------------------------------------------------------

    def execute(self):
        """Full lifecycle: availability check -> scan -> parse -> filter. Returns list of findings."""
        if not self.is_available():
            return []

        start = time.time()
        success = self.run_scan()
        self.scan_duration = round(time.time() - start, 2)

        if not success:
            logger.error(f"[{self.tool_name}] Scan failed after {self.scan_duration}s.")
            return []

        logger.info(f"[{self.tool_name}] Scan completed in {self.scan_duration}s. Parsing results...")
        findings = self.parse_results()

        if self.has_commit_range:
            findings = self._filter_by_commit_range(findings)

        return findings

    @abc.abstractmethod
    def run_scan(self):
        pass

    @abc.abstractmethod
    def parse_results(self):
        pass
