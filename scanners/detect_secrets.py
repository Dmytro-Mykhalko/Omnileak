import os
import json
import logging
import subprocess
from .base import BaseScanner

logger = logging.getLogger(__name__)


class DetectSecretsScanner(BaseScanner):
    def __init__(self, repo_path, output_dir, timeout=None):
        super().__init__(repo_path, output_dir, timeout)
        self.tool_name = "DetectSecrets"
        self.cli_command = "detect-secrets"
        self.raw_output = os.path.join(output_dir, "detect_secrets_raw.json")

    def run_scan(self):
        """detect-secrets must be run from inside the target directory
        with no path argument — passing an absolute path produces empty results."""
        cmd = ["detect-secrets", "scan"]
        abs_repo = os.path.abspath(self.repo_path)
        logger.info(f"[{self.tool_name}] Running: {' '.join(cmd)} (cwd={abs_repo})")
        try:
            with open(self.raw_output, "w", encoding="utf-8") as f:
                result = subprocess.run(
                    cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=self.timeout,
                    cwd=abs_repo,
                    check=False,
                )
            if result.returncode != 0 and result.stderr:
                logger.warning(f"[{self.tool_name}] stderr: {result.stderr.strip()}")
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"[{self.tool_name}] Timed out after {self.timeout}s.")
            return False
        except FileNotFoundError as e:
            logger.error(f"[{self.tool_name}] CLI tool not found: {e}")
            return False
        except Exception as e:
            logger.error(f"[{self.tool_name}] Error executing scan: {e}")
            return False

    def _read_line_from_file(self, file_path, line_number):
        """Read a specific line from a file and return its stripped content."""
        abs_path = os.path.join(os.path.abspath(self.repo_path), file_path)
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    if i == line_number:
                        return line.strip()
        except Exception as e:
            logger.debug(f"[{self.tool_name}] Could not read {abs_path}:{line_number}: {e}")
        return ""

    def _get_commit_for_line(self, file_path, line_number):
        """Use git blame to find the commit that last touched a specific line."""
        abs_repo = os.path.abspath(self.repo_path)
        try:
            result = subprocess.run(
                ["git", "blame", "-L", f"{line_number},{line_number}", "--porcelain", file_path],
                capture_output=True,
                text=True,
                cwd=abs_repo,
                timeout=10,
                check=False,
            )
            if result.returncode == 0 and result.stdout:
                # First line of porcelain output is: <commit_hash> <orig_line> <final_line> [<num_lines>]
                return result.stdout.split()[0]
        except Exception as e:
            logger.debug(f"[{self.tool_name}] git blame failed for {file_path}:{line_number}: {e}")
        return ""

    def parse_results(self):
        if not os.path.exists(self.raw_output):
            logger.warning(f"[{self.tool_name}] Raw output not found at {self.raw_output}.")
            return []

        try:
            with open(self.raw_output, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            logger.error(f"[{self.tool_name}] Failed to parse JSON from {self.raw_output}")
            return []
        except Exception as e:
            logger.error(f"[{self.tool_name}] Error reading raw output: {e}")
            return []

        results = []
        repo = os.path.basename(self.repo_path.rstrip("/"))
        secrets_dict = data.get("results", {})

        for file_path, secrets in secrets_dict.items():
            for item in secrets:
                line_number = item.get("line_number", "")
                hashed_secret = item.get("hashed_secret", "")

                # Extract the real line content instead of the useless hash
                secret_value = ""
                if line_number:
                    secret_value = self._read_line_from_file(file_path, line_number)

                # Fall back to the hash if we couldn't read the file
                if not secret_value:
                    secret_value = hashed_secret

                # Try to get the commit via git blame
                commit_hash = ""
                if line_number:
                    commit_hash = self._get_commit_for_line(file_path, line_number)

                finding = {
                    "id": self.generate_id(repo, file_path, secret_value),
                    "repository": repo,
                    "file_path": file_path,
                    "line_number": line_number,
                    "secret_type": item.get("type", "Unknown"),
                    "secret_value": secret_value,
                    "commit_hash": commit_hash,
                    "found_by": ["detect-secrets"],
                }
                results.append(finding)

        logger.info(f"[{self.tool_name}] Parsed {len(results)} findings.")
        return results
