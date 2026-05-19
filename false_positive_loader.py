"""
false_positive_loader.py
=============================================================================
Loads and caches false positive detection rules from false_positives.json.

Design goal — GENERIC by default
---------------------------------
This module never references any specific category name (months, job_titles,
address_indicators, etc.) in its own code.  All category names, word lists,
role assignments, context keywords, and rule flags come exclusively from the
JSON file.

Adding a new category to false_positives.json requires NO changes here.

How rule behaviour is driven by JSON
-------------------------------------
Categories that need special treatment in the rule engine carry a "roles"
array in the JSON.  Recognised role strings:

  "date_first_word"   – words in this category are used by the date-pattern
                        rule (first token of match is a month-like word).
  "address_last_word" – words in this category are used by the address rule
                        (last token of match is an address suffix).
  "job_title_word"    – words in this category are used by the job-title rule.

Any category with an empty "roles" array is still included in the global
false-positive word set and checked by the bulk membership rules (Rules 2 & 3)
— it just doesn't drive a dedicated structural rule.

Public API
----------
  load_false_positive_rules(path)        → dict          call once at startup
  reload_rules(path)                     → dict          hot-reload from disk
  get_false_positive_words()             → set[str]      all words, all cats
  get_category_words(category)           → set[str]      one named category
  get_role_words(role)                   → set[str]      all words with a role
  get_negative_context()                 → list[str]
  get_positive_context()                 → list[str]
  get_rules_config()                     → dict
  add_custom_false_positive(word, cat)   → bool          in-memory only
  save_custom_words(path, words)         → bool          persists to JSON
=============================================================================
"""

import json
from pathlib import Path
from typing import Dict, Set, List, Optional


# =============================================================================
# MODULE-LEVEL CACHE
# Everything is stored here after load_false_positive_rules() is called.
# =============================================================================

_RULES_CACHE:          Optional[Dict]          = None   # full parsed JSON
_FALSE_POSITIVE_WORDS: Optional[Set[str]]      = None   # union of all categories
_CATEGORY_WORDS:       Optional[Dict[str, Set[str]]] = None  # per-category sets
_ROLE_WORDS:           Optional[Dict[str, Set[str]]] = None  # per-role sets
_NEGATIVE_CONTEXT:     Optional[List[str]]     = None
_POSITIVE_CONTEXT:     Optional[List[str]]     = None


# =============================================================================
# LOAD
# =============================================================================

def load_false_positive_rules(rules_path: str | Path) -> Dict:
    """
    Parse false_positives.json and populate the module cache.

    The function is deliberately free of any hardcoded category names.
    It iterates whatever categories are present in the JSON, reads their
    'words' lists and optional 'roles' arrays, and builds three indexes:

      _FALSE_POSITIVE_WORDS  – flat set of every word across all categories
      _CATEGORY_WORDS        – dict: category_name  → set of words
      _ROLE_WORDS            – dict: role_name       → set of words

    Raises:
        FileNotFoundError  – if the JSON file does not exist
        ValueError         – if the JSON is structurally invalid
    """
    global _RULES_CACHE, _FALSE_POSITIVE_WORDS, _CATEGORY_WORDS
    global _ROLE_WORDS, _NEGATIVE_CONTEXT, _POSITIVE_CONTEXT

    path = Path(rules_path)
    if not path.exists():
        raise FileNotFoundError(
            f"false_positives.json not found at: {path}\n"
            f"Create this file with false positive detection rules."
        )

    with open(path, encoding="utf-8") as f:
        rules = json.load(f)

    if not isinstance(rules, dict):
        raise ValueError("false_positives.json must contain a JSON object at the top level.")

    name_config = rules.get("name_false_positives", {})
    if not name_config:
        raise ValueError("false_positives.json is missing the 'name_false_positives' key.")

    # ── Build word indexes from categories ────────────────────────────────────
    false_positive_words: Set[str]            = set()
    category_words:       Dict[str, Set[str]] = {}
    role_words:           Dict[str, Set[str]] = {}

    for category_name, category_data in name_config.get("categories", {}).items():
        # Normalise all words to lowercase for case-insensitive matching
        words: Set[str] = {w.lower() for w in category_data.get("words", [])}

        category_words[category_name] = words
        false_positive_words.update(words)

        # Index words by every role declared for this category
        for role in category_data.get("roles", []):
            role_words.setdefault(role, set()).update(words)

    # ── Load context keyword lists ────────────────────────────────────────────
    context_keywords = name_config.get("context_keywords", {})
    negative_context: List[str] = context_keywords.get("negative", {}).get("words", [])
    positive_context: List[str] = context_keywords.get("positive", {}).get("words", [])

    # ── Populate cache ────────────────────────────────────────────────────────
    _RULES_CACHE          = rules
    _FALSE_POSITIVE_WORDS = false_positive_words
    _CATEGORY_WORDS       = category_words
    _ROLE_WORDS           = role_words
    _NEGATIVE_CONTEXT     = negative_context
    _POSITIVE_CONTEXT     = positive_context

    return rules


def reload_rules(rules_path: str | Path) -> Dict:
    """Reload rules from disk — useful for hot-reload without restarting."""
    return load_false_positive_rules(rules_path)


# =============================================================================
# ACCESSORS
# All accessors guard against being called before load_false_positive_rules().
# =============================================================================

def _require_loaded(name: str):
    """Raise a clear error if the cache has not been populated yet."""
    if _RULES_CACHE is None:
        raise RuntimeError(
            f"Cannot call {name}() before load_false_positive_rules() has been called."
        )


def get_false_positive_words() -> Set[str]:
    """
    Return the union of every word across all categories as a flat set.
    Used for bulk membership tests (Rules 2 and 3).
    """
    _require_loaded("get_false_positive_words")
    return _FALSE_POSITIVE_WORDS  # type: ignore[return-value]


def get_category_words(category: str) -> Set[str]:
    """
    Return the word set for one named category.
    Returns an empty set if the category does not exist — never raises.

    Example:
        get_category_words("months")  →  {"january", "february", ...}
    """
    _require_loaded("get_category_words")
    return _CATEGORY_WORDS.get(category, set())  # type: ignore[union-attr]


def get_role_words(role: str) -> Set[str]:
    """
    Return all words that carry a specific role tag.
    Returns an empty set if no category carries that role.

    This is the preferred accessor for rule-engine code because it decouples
    rules from specific category names entirely.

    Example:
        get_role_words("date_first_word")   →  {"january", "february", ...}
        get_role_words("address_last_word") →  {"street", "avenue", ...}
        get_role_words("job_title_word")    →  {"manager", "director", ...}

    Adding a new category with role "date_first_word" in the JSON
    automatically extends the set returned here — no code change needed.
    """
    _require_loaded("get_role_words")
    return _ROLE_WORDS.get(role, set())  # type: ignore[union-attr]


def get_all_categories() -> List[str]:
    """Return the list of all category names currently loaded."""
    _require_loaded("get_all_categories")
    return list(_CATEGORY_WORDS.keys())  # type: ignore[union-attr]


def get_all_roles() -> List[str]:
    """Return the list of all role names currently loaded."""
    _require_loaded("get_all_roles")
    return list(_ROLE_WORDS.keys())  # type: ignore[union-attr]


def get_negative_context() -> List[str]:
    """Return the list of negative context keywords."""
    _require_loaded("get_negative_context")
    return _NEGATIVE_CONTEXT  # type: ignore[return-value]


def get_positive_context() -> List[str]:
    """Return the list of positive context keywords."""
    _require_loaded("get_positive_context")
    return _POSITIVE_CONTEXT  # type: ignore[return-value]


def get_rules_config() -> Dict:
    """
    Return the rules configuration dict (toggle flags and thresholds).

    Example keys: enable_number_check, min_name_length, max_name_word_count,
                  context_window_size, enable_repeated_word_filter, ...
    """
    _require_loaded("get_rules_config")
    return _RULES_CACHE.get("name_false_positives", {}).get("rules", {})  # type: ignore[union-attr]


# =============================================================================
# RUNTIME MUTATION (in-memory only unless save_custom_words is called)
# =============================================================================

def add_custom_false_positive(word: str, category: str = "custom") -> bool:
    """
    Add a word to the in-memory false positive set at runtime.

    Changes are NOT persisted to disk.  Call save_custom_words() separately
    if persistence is required.

    Args:
        word:     The word to suppress (stored lowercase).
        category: Which category bucket to place it in.
                  Falls back to 'custom' if the given category does not exist.

    Returns True on success, False if the cache has not been loaded yet.
    """
    if _CATEGORY_WORDS is None or _FALSE_POSITIVE_WORDS is None:
        return False

    target = category if category in _CATEGORY_WORDS else "custom"

    # Ensure the custom category exists even if missing from JSON
    if target not in _CATEGORY_WORDS:
        _CATEGORY_WORDS[target] = set()

    normalised = word.lower()
    _CATEGORY_WORDS[target].add(normalised)
    _FALSE_POSITIVE_WORDS.add(normalised)
    return True


def save_custom_words(rules_path: str | Path, custom_words: List[str]) -> bool:
    """
    Append custom words to the 'custom' category in false_positives.json
    and immediately reload the in-memory cache.

    Duplicate words are silently ignored.

    Args:
        rules_path:   Path to false_positives.json.
        custom_words: Words to persist.

    Returns True on success, False on any I/O or JSON error.
    """
    path = Path(rules_path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)

        categories = (
            rules
            .setdefault("name_false_positives", {})
            .setdefault("categories", {})
        )
        custom_category = categories.setdefault("custom", {"words": [], "description": "Custom false positives", "roles": []})
        if "words" not in custom_category:
            custom_category["words"] = []

        existing = {w.lower() for w in custom_category["words"]}
        new_words = [w for w in custom_words if w.lower() not in existing]
        custom_category["words"].extend(new_words)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=2, ensure_ascii=False)

        reload_rules(rules_path)
        return True

    except Exception as exc:
        print(f"[false_positive_loader] Error saving custom words: {exc}")
        return False