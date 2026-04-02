import re
import hashlib
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


def _normalize(value):
    """Strip all whitespace for comparison purposes."""
    return re.sub(r"\s+", "", value)


def _secret_key(repo, secret_value):
    """A secondary, file-path-agnostic key used to catch the same secret
    reported with different paths by different tools."""
    normalized = _normalize(secret_value)
    raw = f"{repo}|{normalized}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class Deduplicator:
    def __init__(self):
        self.findings = []

    def load(self, results):
        self.findings.extend(results)

    def deduplicate(self):
        total = len(self.findings)
        logger.info(f"Deduplicating {total} findings.")

        # --- Pass 1: Group by the per-file ID (repo + file + secret) ---
        by_id = defaultdict(list)
        for f in self.findings:
            by_id[f["id"]].append(f)

        # Merge findings that share the same ID
        merged_by_id = {}
        for uid, items in by_id.items():
            merged_by_id[uid] = self._merge(items)

        # --- Pass 2: Group by secret-only key (repo + secret, ignoring file) ---
        # This catches the same credential found by different tools
        # that report slightly different file paths.
        by_secret = defaultdict(list)
        for uid, item in merged_by_id.items():
            sk = _secret_key(item["repository"], item["secret_value"])
            by_secret[sk].append(item)

        deduplicated = []
        for sk, items in by_secret.items():
            if len(items) == 1:
                deduplicated.append(items[0])
            else:
                # Keep the entry with the most information (non-empty file_path)
                # and merge found_by from all
                deduplicated.append(self._merge(items))

        logger.info(f"Reduced to {len(deduplicated)} unique findings (from {total} raw).")
        return deduplicated

    @staticmethod
    def _merge(items):
        """Merge a list of findings into one, combining found_by and filling blanks."""
        # Pick the item with the most populated fields as the base
        best = max(items, key=lambda x: (
            bool(x.get("file_path")),
            bool(x.get("commit_hash")),
            bool(x.get("line_number")),
        ))
        base = best.copy()

        found_by = set(base["found_by"])
        for other in items:
            found_by.update(other["found_by"])
            if not base["commit_hash"] and other.get("commit_hash"):
                base["commit_hash"] = other["commit_hash"]
            if not base["line_number"] and other.get("line_number"):
                base["line_number"] = other["line_number"]
            if not base["file_path"] and other.get("file_path"):
                base["file_path"] = other["file_path"]

        base["found_by"] = sorted(found_by)
        return base
