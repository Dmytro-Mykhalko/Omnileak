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


class BaseScanner(abc.ABC):
    def __init__(self, repo_path, output_dir, timeout=None):
        self.repo_path = repo_path
        self.output_dir = output_dir
        self.timeout = timeout
        self.tool_name = "Base"
        self.cli_command = None  # Subclasses must set this (e.g., "gitleaks")
        self.scan_duration = None
        self.repo_name = os.path.basename(repo_path.rstrip("/"))

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

    def execute(self):
        """Full lifecycle: availability check -> scan -> parse. Returns list of findings."""
        if not self.is_available():
            return []

        start = time.time()
        success = self.run_scan()
        self.scan_duration = round(time.time() - start, 2)

        if not success:
            logger.error(f"[{self.tool_name}] Scan failed after {self.scan_duration}s.")
            return []

        logger.info(f"[{self.tool_name}] Scan completed in {self.scan_duration}s. Parsing results...")
        return self.parse_results()

    @abc.abstractmethod
    def run_scan(self):
        pass

    @abc.abstractmethod
    def parse_results(self):
        pass
