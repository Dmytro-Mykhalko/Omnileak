import os
import json
import logging
from .base import BaseScanner

logger = logging.getLogger(__name__)


class TrufflehogScanner(BaseScanner):
    def __init__(self, repo_path, output_dir, timeout=None):
        super().__init__(repo_path, output_dir, timeout)
        self.tool_name = "Trufflehog"
        self.cli_command = "trufflehog"
        self.raw_output = os.path.join(output_dir, self._prefixed("trufflehog_raw.json"))

    def run_scan(self):
        cmd = [
            "trufflehog", "git",
            f"file://{self.repo_path}",
            "--json",
        ]
        res = self.run_command_to_file(cmd, self.raw_output)
        return res is not None

    def parse_results(self):
        if not os.path.exists(self.raw_output):
            logger.warning(f"[{self.tool_name}] Raw output not found at {self.raw_output}.")
            return []

        results = []
        repo = os.path.basename(self.repo_path.rstrip("/"))

        with open(self.raw_output, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    source_meta = item.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
                    file_path = source_meta.get("file", "")
                    commit_hash = source_meta.get("commit", "")
                    secret = item.get("Raw", item.get("Redacted", ""))
                    if not secret:
                        continue

                    finding = {
                        "id": self.generate_id(repo, file_path, secret),
                        "repository": repo,
                        "file_path": file_path,
                        "line_number": source_meta.get("line", ""),
                        "secret_type": item.get("DetectorName", "Unknown"),
                        "secret_value": secret,
                        "commit_hash": commit_hash,
                        "found_by": ["trufflehog"],
                    }
                    results.append(finding)
                except json.JSONDecodeError:
                    logger.debug(f"[{self.tool_name}] Skipping malformed JSON on line {line_num}.")
                    continue
                except Exception as e:
                    logger.debug(f"[{self.tool_name}] Parse error on line {line_num}: {e}")
                    continue

        logger.info(f"[{self.tool_name}] Parsed {len(results)} findings.")
        return results
