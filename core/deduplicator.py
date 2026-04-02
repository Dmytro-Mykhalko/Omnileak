import re
import hashlib
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

# Regex used by _extract_core to strip a leading variable-assignment prefix
# such as  DATABASE_URL=, S3_CREDENTIALS_KEY=, $password =>, 'key' =>, etc.
_LEADING_ASSIGNMENT_RE = re.compile(
    r"""^['"\s$]*[A-Za-z0-9_>().\-]*(?:=>|=)\s*['"]?""",
)

# Characters that are surrounding "noise" rather than part of the secret itself
_STRIP_CHARS = "'\";$, "


def _normalize(value):
    """Collapse all whitespace *and* escaped newlines for comparison."""
    v = str(value)
    v = v.replace("\\n", "").replace("\n", "")
    return re.sub(r"\s+", "", v)


def _extract_core(value):
    """Strip surrounding context (var assignments, quotes) to isolate the
    raw secret for overlap comparison.

    Examples::

        SECRET=Xk9mPqRsT4vW   -> Xk9mPqRsT4vW
        "$variable = 'val';"   -> val
        AKIAIOSFODNN7EXAMPLE   -> AKIAIOSFODNN7EXAMPLE  (unchanged)
    """
    v = _normalize(value)
    v = _LEADING_ASSIGNMENT_RE.sub("", v)
    v = v.strip(_STRIP_CHARS)
    return v


def _secret_key(repo, secret_value):
    """A secondary, file-path-agnostic key used to catch the same secret
    reported with different paths by different tools."""
    normalized = _normalize(secret_value)
    raw = f"{repo}|{normalized}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _is_overlap(a, b):
    """Return True when finding *a* is a duplicate of finding *b* and should
    be absorbed into *b*.

    Checks three levels (cheapest first):
    1. Exact normalized match.
    2. Normalized *a* is a substring of normalized *b*.
    3. Core-extracted *a* is a substring of normalized *b*.
    """
    na = _normalize(a["secret_value"])
    nb = _normalize(b["secret_value"])

    if na == nb:
        return True
    if na in nb:
        return True
    if _extract_core(a["secret_value"]) in nb:
        return True
    return False


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

        after_pass2 = []
        for sk, items in by_secret.items():
            if len(items) == 1:
                after_pass2.append(items[0])
            else:
                after_pass2.append(self._merge(items))

        # --- Pass 3: Proximity dedup (same file + line + commit) ---
        # Different tools often extract different amounts of context around
        # the same secret on the same line.  Group by location and merge
        # findings whose secret values overlap (one contains the other).
        deduplicated = self._proximity_dedup(after_pass2)

        logger.info(f"Reduced to {len(deduplicated)} unique findings (from {total} raw).")
        return deduplicated

    @classmethod
    def _proximity_dedup(cls, findings):
        """Merge findings that share (repo, file, line, commit) when one
        secret value is contained within the other."""

        # Separate findings into groups by location
        keyed = defaultdict(list)
        for f in findings:
            fp = f.get("file_path", "")
            ln = f.get("line_number", "")
            ch = f.get("commit_hash", "")
            # Only group when we have enough location info
            if fp and ln and ch:
                key = (f["repository"], fp, str(ln), ch)
                keyed[key].append(f)
            else:
                keyed[id(f)].append(f)  # unique key — won't be grouped

        result = []
        for key, group in keyed.items():
            if len(group) < 2:
                result.append(group[0])
                continue
            result.extend(cls._merge_overlapping(group))
        return result

    @classmethod
    def _merge_overlapping(cls, group):
        """Within a location group, absorb findings whose secret value is a
        substring of another finding's value.  Returns the surviving list."""

        # Sort longest normalized secret first — larger values absorb smaller
        items = sorted(
            group,
            key=lambda f: len(_normalize(f["secret_value"])),
            reverse=True,
        )

        absorbed = set()  # indices that have been merged into another

        for i in range(len(items)):
            if i in absorbed:
                continue
            for j in range(i + 1, len(items)):
                if j in absorbed:
                    continue
                # Check both directions (though j is shorter-or-equal)
                if _is_overlap(items[j], items[i]):
                    # j is contained in i — absorb j into i
                    items[i] = cls._merge([items[i], items[j]])
                    absorbed.add(j)
                elif _is_overlap(items[i], items[j]):
                    # i is contained in j — absorb i into j
                    items[j] = cls._merge([items[j], items[i]])
                    absorbed.add(i)
                    break  # i is gone, move on

        return [items[k] for k in range(len(items)) if k not in absorbed]

    @staticmethod
    def _merge(items):
        """Merge a list of findings into one, combining found_by and filling blanks."""
        # Pick the item with the most populated fields as the base;
        # among equal metadata, prefer the longest secret_value.
        best = max(items, key=lambda x: (
            bool(x.get("file_path")),
            bool(x.get("commit_hash")),
            bool(x.get("line_number")),
            len(_normalize(x.get("secret_value", ""))),
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
