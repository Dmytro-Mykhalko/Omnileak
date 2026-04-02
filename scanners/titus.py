import base64
import os
import re
import json
import logging
import sqlite3
import subprocess
from .base import BaseScanner

logger = logging.getLogger(__name__)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _b64decode(value):
    """Decode a base64-encoded string/bytes to UTF-8 text. Returns '' on failure."""
    if not value:
        return ""
    try:
        if isinstance(value, str):
            value = value.encode("utf-8")
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except Exception:
        return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


class TitusScanner(BaseScanner):
    def __init__(self, repo_path, output_dir, timeout=None):
        super().__init__(repo_path, output_dir, timeout)
        self.tool_name = "Titus"
        self.cli_command = "titus"
        self.raw_output = os.path.join(output_dir, "titus_raw.json")
        self.datastore = os.path.join(output_dir, "titus.ds")

    def run_scan(self):
        # Step 1: scan the repo with git history into a datastore
        cmd_scan = [
            "titus", "scan",
            "--git",
            "--output", self.datastore,
            self.repo_path,
        ]
        res_scan = self.run_command(cmd_scan)
        if res_scan is None:
            return False

        # Step 2: export the report as JSON
        cmd_report = [
            "titus", "report",
            "--datastore", self.datastore,
            "--format", "json",
        ]
        res_report = self.run_command_to_file(cmd_report, self.raw_output)
        return res_report is not None

    def _make_path_relative(self, file_path):
        """Strip absolute repo prefix to produce a clean relative path."""
        abs_repo = os.path.abspath(self.repo_path)
        if file_path.startswith(abs_repo):
            file_path = file_path[len(abs_repo):].lstrip("/")
        elif file_path.startswith(self.repo_path):
            file_path = file_path[len(self.repo_path):].lstrip("/")
        return file_path

    def _get_commit_for_line(self, file_path, line_number):
        """Use git blame to find the commit that last touched a specific line."""
        if not file_path or not line_number:
            return ""
        abs_repo = os.path.abspath(self.repo_path)
        try:
            result = subprocess.run(
                ["git", "blame", "-L", f"{line_number},{line_number}",
                 "--porcelain", file_path],
                capture_output=True, text=True,
                cwd=abs_repo, timeout=10, check=False,
            )
            if result.returncode == 0 and result.stdout:
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

        if not isinstance(data, list):
            logger.error(f"[{self.tool_name}] Unexpected JSON structure (expected list).")
            return []

        # Build blob→path maps from both SQLite and human report
        blob_path_map = self._build_blob_path_map_sqlite()
        if not blob_path_map:
            blob_path_map = self._build_blob_path_map_human()

        results = []
        repo = os.path.basename(self.repo_path.rstrip("/"))

        for finding in data:
            rule_id = finding.get("RuleID", "Unknown")
            rule_name = finding.get("RuleName") or rule_id
            matches = finding.get("Matches") or []

            if not matches:
                groups = finding.get("Groups") or []
                if groups:
                    secret = _b64decode(groups[0]).strip()
                    if secret:
                        results.append({
                            "id": self.generate_id(repo, "", secret),
                            "repository": repo,
                            "file_path": "",
                            "line_number": "",
                            "secret_type": rule_name,
                            "secret_value": secret,
                            "commit_hash": "",
                            "found_by": ["titus"],
                        })
                continue

            for m in matches:
                snippet = m.get("Snippet", {})
                secret = _b64decode(snippet.get("Matching", "")).strip()
                if not secret:
                    continue

                match_rule = m.get("RuleName") or rule_name

                location = m.get("Location", {})
                source = location.get("Source", {})
                start = source.get("Start", {})
                line_number = start.get("Line", "")

                blob_id = m.get("BlobID", "")
                file_path = blob_path_map.get(blob_id, "")
                file_path = self._make_path_relative(file_path)

                # Resolve commit hash via git blame
                commit_hash = self._get_commit_for_line(file_path, line_number)

                results.append({
                    "id": self.generate_id(repo, file_path, secret),
                    "repository": repo,
                    "file_path": file_path,
                    "line_number": line_number,
                    "secret_type": match_rule,
                    "secret_value": secret,
                    "commit_hash": commit_hash,
                    "found_by": ["titus"],
                })

        logger.info(f"[{self.tool_name}] Parsed {len(results)} findings.")
        return results

    # ------------------------------------------------------------------
    # Blob → path resolution
    # ------------------------------------------------------------------

    def _build_blob_path_map_sqlite(self):
        """Query the Titus SQLite datastore directly for blob→path mapping."""
        db_path = os.path.join(self.datastore, "datastore.db")
        if not os.path.exists(db_path):
            return {}

        blob_map = {}
        try:
            conn = sqlite3.connect(db_path)
            rows = conn.execute(
                "SELECT blob_id, path FROM provenance WHERE path != ''"
            ).fetchall()
            for blob_id, path in rows:
                if blob_id not in blob_map:
                    blob_map[blob_id] = path
            conn.close()
        except Exception as e:
            logger.debug(f"[{self.tool_name}] SQLite blob map failed: {e}")
            return {}

        logger.info(f"[{self.tool_name}] Resolved {len(blob_map)} blob→path mappings (SQLite).")
        return blob_map

    def _build_blob_path_map_human(self):
        """Fallback: parse `titus report --format human` for File:/Blob: lines."""
        blob_map = {}
        try:
            env = os.environ.copy()
            env["NO_COLOR"] = "1"
            result = subprocess.run(
                ["titus", "report", "--datastore", self.datastore,
                 "--format", "human", "--color", "never"],
                capture_output=True, text=True, timeout=60, check=False,
                env=env,
            )
            if result.returncode != 0:
                return blob_map

            current_file = ""
            for line in result.stdout.splitlines():
                clean = _ANSI_RE.sub("", line).strip()
                if clean.startswith("File:"):
                    current_file = clean.split("File:", 1)[1].strip()
                elif clean.startswith("Blob:"):
                    blob_id = clean.split("Blob:", 1)[1].strip()
                    if blob_id and current_file:
                        blob_map[blob_id] = current_file
        except Exception as e:
            logger.debug(f"[{self.tool_name}] Human report blob map failed: {e}")

        logger.info(f"[{self.tool_name}] Resolved {len(blob_map)} blob→path mappings (human report).")
        return blob_map
