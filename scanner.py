"""
scanner.py
=============================================================================
Responsible for TWO things only:
  1. Loading and compiling regex patterns from patterns.json at startup.
  2. Running those patterns against plain-text units and returning matches.

It does NOT know about files, GUI, or CSV output — those are handled by
extractors.py, pii_scanner.py, and report.py respectively.

Public API
----------
  load_patterns(json_path)  → list[PatternGroup]   call once at startup
  scan_units(units, groups) → list[dict]            call per file/folder
  scan_file(filepath)       → list[dict]            convenience wrapper
  scan_folder(folder_path)  → list[dict]            convenience wrapper

Each result dict contains:
  data_type   – e.g. "Social Security Number"
  severity    – "Critical" | "High"
  match       – exact matched string
  location    – human-readable position ("Page 3 | Line 12", "Row 4 | Col B")
  context     – ~60 chars surrounding the match for quick review
  file_name   – filename only (e.g. "records.csv")
  file_path   – full absolute path to the source file
  file_ext    – uppercase extension without dot (e.g. "CSV")
=============================================================================
"""

import re
import os
import json
from pathlib import Path
from typing import TypedDict

from extractors import EXTRACTORS, SUPPORTED_EXTENSIONS


# =============================================================================
# TYPE DEFINITIONS
# =============================================================================

class PatternGroup(TypedDict):
    """
    Represents one compiled data type (e.g. "Email Address").
    Built by load_patterns() from patterns.json.
    """
    label:    str               # display name
    severity: str               # "Critical" or "High"
    patterns: list              # list of compiled re.Pattern objects


# =============================================================================
# SECTION 1 — PATTERN LOADER
# Reads patterns.json, validates each entry, compiles the regex strings,
# and returns a list of PatternGroup dicts ready for scanning.
# =============================================================================

# Maps the string flag names used in patterns.json to Python re constants
_FLAG_MAP: dict[str, int] = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE":  re.MULTILINE,
    "DOTALL":     re.DOTALL,
}


# =============================================================================
# FALSE POSITIVE DETECTION FOR NAMES
# =============================================================================

# Common words that look like names but aren't
_NAME_FALSE_POSITIVES = {
    # Months (often mistaken as names)
    "months": {
        "january", "february", "march", "april", "may", "june",
        "july", "august", "september", "october", "november", "december"
    },
    # Days of week
    "days": {
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"
    },
    # Seasons
    "seasons": {"spring", "summer", "fall", "autumn", "winter"},
    # Directions/Regions
    "directions": {
        "north", "south", "east", "west", "northeast", "northwest", 
        "southeast", "southwest", "central", "western", "eastern", "northern"
    },
    # Address indicators
    "address": {
        "street", "st", "avenue", "ave", "boulevard", "blvd", "drive", "dr",
        "lane", "ln", "road", "rd", "court", "ct", "place", "pl", "way",
        "highway", "hwy", "parkway", "pkwy", "circle", "circ"
    },
    # Job titles (common false positives)
    "titles": {
        "manager", "director", "president", "ceo", "cto", "cfo", "vp",
        "assistant", "associate", "coordinator", "specialist", "analyst",
        "engineer", "technician", "supervisor", "administrator"
    },
    # Company indicators
    "company": {
        "inc", "llc", "corp", "corporation", "company", "ltd", "limited",
        "group", "holdings", "international", "global", "solutions", "systems"
    },
    # Common place names
    "places": {
        "america", "europe", "asia", "africa", "australia", "canada", "china",
        "japan", "germany", "france", "italy", "spain", "mexico", "brazil",
        "california", "texas", "florida", "new york", "london", "paris", "tokyo"
    }
}

# Flatten the set for quick lookup
_ALL_FALSE_POSITIVES = set()
for category in _NAME_FALSE_POSITIVES.values():
    _ALL_FALSE_POSITIVES.update(category)

# Context keywords that indicate something is NOT a name
_NEGATIVE_CONTEXT = [
    "address", "located at", "city", "state", "country", "zip", "postal",
    "mailing", "shipping", "billing", "street", "avenue", "boulevard",
    "company", "corporation", "organization", "department", "team",
    "position", "title", "role", "job", "employee id", "staff"
]

# Context keywords that indicate something IS likely a name
_POSITIVE_CONTEXT = [
    "name", "full name", "first name", "last name", "surname",
    "employee", "customer", "client", "user", "person",
    "mr.", "mrs.", "ms.", "dr.", "prof.", "rev.", "hon."
]


def is_false_positive_name(match_text: str, context: str = "") -> tuple[bool, str]:
    """
    Check if a name match is likely a false positive.
    Returns (is_false_positive, reason)
    """
    match_lower = match_text.lower()
    words = match_lower.split()
    
    # Rule 1: Contains numbers (definitely not a person's name)
    if any(c.isdigit() for c in match_text):
        return True, "contains numbers"
    
    # Rule 2: All words are common false positives
    if len(words) > 0 and all(word in _ALL_FALSE_POSITIVES for word in words):
        return True, "all words are common non-name terms"
    
    # Rule 3: Single word name - too vague unless context helps
    if len(words) == 1:
        # Single common word that's not clearly a name
        if match_lower in _ALL_FALSE_POSITIVES:
            return True, "single common word"
        # Short words (likely abbreviations)
        if len(match_text) <= 2:
            return True, "too short to be a name"
    
    # Rule 4: Looks like an address (ends with street/avenue/etc.)
    if words and words[-1] in _NAME_FALSE_POSITIVES["address"]:
        return True, "looks like an address"
    
    # Rule 5: Contains job titles (unless it has a title prefix like Mr.)
    if any(word in _NAME_FALSE_POSITIVES["titles"] for word in words):
        # Check if there's a title prefix in context
        if not any(title_word in context.lower() for title_word in ["mr.", "mrs.", "ms.", "dr.", "prof."]):
            return True, "contains job title without name prefix"
    
    # Rule 6: Month + Number pattern (e.g., "January 15")
    if len(words) >= 2 and words[0] in _NAME_FALSE_POSITIVES["months"]:
        if words[1].isdigit() or words[1] in ["1st", "2nd", "3rd", "4th", "5th", "th"]:
            return True, "looks like a date"
    
    # Rule 7: Check context for negative indicators
    if context:
        context_lower = context.lower()
        
        # Find where the match appears in context
        match_pos = context_lower.find(match_lower)
        if match_pos != -1:
            # Look at text before the match (within 30 chars)
            start = max(0, match_pos - 30)
            before_text = context_lower[start:match_pos]
            
            # Check for negative context keywords
            for keyword in _NEGATIVE_CONTEXT:
                if keyword in before_text:
                    return True, f"context indicates address/location"
    
    # Rule 8: Check for positive context (increases confidence, not a false positive)
    if context:
        context_lower = context.lower()
        for keyword in _POSITIVE_CONTEXT:
            if keyword in context_lower:
                return False, ""  # Positive context overrides
    
    # Rule 9: Unusual capitalization patterns
    # Real names typically have first letter capitalized
    if match_text.isupper() and len(words) >= 2:
        return True, "all uppercase (likely system data)"
    if match_text.islower() and len(words) >= 2:
        return True, "all lowercase (unlikely proper name)"
    
    # Passed all checks - likely a real name
    return False, ""


def load_patterns(json_path: str | Path) -> list[PatternGroup]:
    """
    Load and compile all PII patterns from a JSON config file.

    Expected JSON structure — an array of objects:
    [
      {
        "label":    "Email Address",
        "severity": "High",
        "flags":    ["IGNORECASE"],
        "patterns": ["regex1", "regex2", ...]
      },
      ...
    ]

    Any object whose key starts with "_" (e.g. "_comment") is treated as a
    comment and skipped automatically.

    Raises:
      FileNotFoundError  – if json_path does not exist
      ValueError         – if a required field is missing or a regex is invalid

    Returns a list of PatternGroup dicts with compiled re.Pattern objects.
    """
    path = Path(json_path)

    if not path.exists():
        raise FileNotFoundError(
            f"patterns.json not found at: {path}\n"
            f"Make sure patterns.json is in the same folder as this script."
        )

    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    if not isinstance(raw, list):
        raise ValueError("patterns.json must contain a JSON array at the top level.")

    groups: list[PatternGroup] = []

    for idx, entry in enumerate(raw):
        # ── Skip comment-only objects ──────────────────────────────────────
        # An entry is a comment if ALL its keys start with "_"
        if all(k.startswith("_") for k in entry.keys()):
            continue

        # ── Validate required fields ───────────────────────────────────────
        for required in ("label", "severity", "patterns"):
            if required not in entry:
                raise ValueError(
                    f"Entry #{idx} in patterns.json is missing required field '{required}'."
                )

        label    = str(entry["label"]).strip()
        severity = str(entry["severity"]).strip()
        raw_flags = entry.get("flags", [])
        raw_patterns = entry["patterns"]

        if not raw_patterns:
            raise ValueError(f"Entry '{label}' has an empty 'patterns' list.")

        # ── Build combined re flag value ───────────────────────────────────
        # e.g. ["IGNORECASE", "MULTILINE"]  →  re.IGNORECASE | re.MULTILINE
        flag_value = 0
        for flag_str in raw_flags:
            flag_upper = flag_str.upper()
            if flag_upper not in _FLAG_MAP:
                raise ValueError(
                    f"Entry '{label}': unknown flag '{flag_str}'. "
                    f"Supported: {list(_FLAG_MAP.keys())}"
                )
            flag_value |= _FLAG_MAP[flag_upper]

        # ── Compile each regex string ──────────────────────────────────────
        compiled = []
        for i, pattern_str in enumerate(raw_patterns):
            try:
                compiled.append(re.compile(pattern_str, flag_value))
            except re.error as exc:
                raise ValueError(
                    f"Entry '{label}', pattern #{i+1} is not valid regex:\n"
                    f"  Pattern : {pattern_str}\n"
                    f"  Error   : {exc}"
                )

        groups.append(PatternGroup(
            label=label,
            severity=severity,
            patterns=compiled,
        ))

    if not groups:
        raise ValueError(
            "patterns.json loaded successfully but contains no usable entries. "
            "Check that at least one entry has label, severity, and patterns fields."
        )

    return groups


# =============================================================================
# SECTION 2 — CORE SCANNING ENGINE
# =============================================================================

def scan_units(
    units:  list[tuple[str, str]],
    groups: list[PatternGroup],
) -> list[dict]:
    """
    Run all pattern groups against a list of (location, text) tuples.

    Deduplication rule:
      Within the same location AND the same data type, the exact same
      matched string is reported only once, even if multiple regex
      variants from the same group all match it.

    Context snippet:
      Up to 60 characters before and after the match are captured to give
      reviewers enough surrounding text to judge whether a match is genuine.

    Args:
      units   – list of (location_label, text) tuples from an extractor
      groups  – compiled pattern groups from load_patterns()

    Returns a list of match dicts (no file metadata — that is added by
    scan_file() which calls this function).
    """
    results = []

    for location, text in units:
        # Skip error/info placeholder entries inserted by extractors
        if location in ("ERROR", "INFO"):
            continue

        for group in groups:
            # seen tracks matched values already recorded for this
            # data type at this exact location, preventing duplicate rows
            seen: set[str] = set()
            
            # Check if this is a Full Name group for special handling
            is_name_group = (group["label"] == "Full Name")

            for pattern in group["patterns"]:
                for m in pattern.finditer(text):
                    value = m.group().strip()

                    # Skip empty or already-seen matches
                    if not value or value in seen:
                        continue
                    
                    # ── FALSE POSITIVE FILTERING FOR NAMES ──
                    if is_name_group:
                        # Extract context around the match
                        start = max(0, m.start() - 60)
                        end = min(len(text), m.end() + 60)
                        context = text[start:end].strip()
                        
                        # Check if this is a false positive
                        is_fp, reason = is_false_positive_name(value, context)
                        if is_fp:
                            # Skip this match entirely
                            continue
                    
                    seen.add(value)

                    # Build a short context snippet centred on the match
                    # Clamp start/end to string bounds
                    start   = max(0, m.start() - 60)
                    end     = min(len(text), m.end() + 60)
                    snippet = text[start:end].strip()
                    if len(snippet) > 140:
                        snippet = snippet[:140] + "…"

                    results.append({
                        "data_type": group["label"],
                        "severity":  group["severity"],
                        "match":     value,
                        "location":  location,
                        "context":   snippet,
                    })

    return results


# =============================================================================
# SECTION 3 — FILE AND FOLDER WRAPPERS
# These convenience functions tie together extractors + scan_units and
# stamp every result with file metadata.
# =============================================================================

def scan_file(
    filepath: str | Path,
    groups:   list[PatternGroup],
) -> list[dict]:
    """
    Extract text from a single file and scan it for PII.

    Steps:
      1. Determine file extension → look up extractor in EXTRACTORS.
      2. Call extractor → get list of (location, text) tuples.
      3. Run scan_units() on those tuples.
      4. Stamp every result dict with file metadata.

    Graceful handling:
      • Unsupported extension  → returns [] silently (no crash)
      • Zero-byte file         → returns [] silently
      • Unreadable / corrupt   → extractor returns an error tuple;
                                  scan_units skips it; returns []

    Returns list of result dicts with keys:
      data_type, severity, match, location, context,
      file_name, file_path, file_ext
    """
    path = Path(filepath)
    ext  = path.suffix.lower()

    # Skip unsupported extensions without raising
    if ext not in EXTRACTORS:
        return []

    # Skip empty files
    if path.stat().st_size == 0:
        return []

    # Extract text units from the file
    try:
        units = EXTRACTORS[ext](path)
    except Exception as exc:
        # Completely unreadable file — return a single diagnostic record
        return [{
            "data_type": "READ ERROR",
            "severity":  "—",
            "match":     str(exc),
            "location":  "—",
            "context":   "—",
            "file_name": path.name,
            "file_path": str(path.resolve()),
            "file_ext":  ext.upper().lstrip("."),
        }]

    # Scan the extracted text
    matches = scan_units(units, groups)

    # Stamp each result with source file metadata
    for m in matches:
        m["file_name"] = path.name
        m["file_path"] = str(path.resolve())   # always store absolute path
        m["file_ext"]  = ext.upper().lstrip(".")

    return matches


def scan_folder(
    folder_path: str | Path,
    groups:      list[PatternGroup],
) -> list[dict]:
    """
    Recursively scan all supported files under folder_path.

    Walk behaviour:
      • Descends into all sub-directories via os.walk.
      • Hidden directories (names starting with ".") are skipped to
        avoid noise from .git, .svn, __pycache__, etc.
      • Files whose extension is not in SUPPORTED_EXTENSIONS are skipped.
      • Zero-byte files are skipped (handled inside scan_file).
      • PermissionError on any file or directory is caught and skipped
        silently so a single locked file doesn't abort the whole scan.

    Returns the combined list of all match dicts from every file scanned.
    """
    all_results: list[dict] = []

    for root, dirs, files in os.walk(folder_path):
        # Prune hidden directories in-place so os.walk doesn't descend into them
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for filename in files:
            ext = Path(filename).suffix.lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue

            full_path = os.path.join(root, filename)
            try:
                all_results.extend(scan_file(full_path, groups))
            except PermissionError:
                # Silently skip files we don't have permission to read
                pass

    return all_results