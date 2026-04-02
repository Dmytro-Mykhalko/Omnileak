import os
import json
import logging
from .base import BaseScanner

logger = logging.getLogger(__name__)


class GitleaksScanner(BaseScanner):
    def __init__(self, repo_path, output_dir, timeout=None):
        super().__init__(repo_path, output_dir, timeout)
        self.tool_name = "Gitleaks"
        self.cli_command = "gitleaks"
        self.raw_output = os.path.join(output_dir, "gitleaks_raw.json")

    def run_scan(self):
        cmd = [
            "gitleaks", "detect",
            "--source", self.repo_path,
            "--report-path", self.raw_output,
            "--report-format", "json",
        ]
        res = self.run_command(cmd)
        if res is None:
            return False
        # gitleaks returns 0 = no leaks, 1 = leaks found, other = error
        if res.returncode not in [0, 1]:
            logger.warning(f"[{self.tool_name}] Exited with code {res.returncode}. stderr: {res.stderr}")
        return True

    def parse_results(self):
        if not os.path.exists(self.raw_output):
            logger.warning(f"[{self.tool_name}] Raw output not found at {self.raw_output}. Likely no findings.")
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

        if not isinstance(data, list):
            logger.error(f"[{self.tool_name}] Unexpected JSON structure (expected list).")
            return []

        results = []
        repo = os.path.basename(self.repo_path.rstrip("/"))
        for item in data:
            file_path = item.get("File", "")
            secret = item.get("Secret", "")
            finding = {
                "id": self.generate_id(repo, file_path, secret),
                "repository": repo,
                "file_path": file_path,
                "line_number": item.get("StartLine", ""),
                "secret_type": item.get("RuleID", "Unknown"),
                "secret_value": secret,
                "commit_hash": item.get("Commit", ""),
                "found_by": ["gitleaks"],
            }
            results.append(finding)

        logger.info(f"[{self.tool_name}] Parsed {len(results)} findings.")
        return results
