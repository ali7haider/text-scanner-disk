"""
false_positive_loader.py
Loads and manages false positive detection rules from false_positives.json.
"""

import json
from pathlib import Path
from typing import Dict, Set, List, Optional

# Global cache for loaded rules
_RULES_CACHE: Optional[Dict] = None
_FALSE_POSITIVE_WORDS: Optional[Set[str]] = None
_NEGATIVE_CONTEXT: Optional[List[str]] = None
_POSITIVE_CONTEXT: Optional[List[str]] = None
_CATEGORY_WORDS: Optional[Dict[str, Set[str]]] = None


def load_false_positive_rules(rules_path: str | Path) -> Dict:
    """
    Load false positive rules from JSON file.
    
    Args:
        rules_path: Path to false_positives.json
        
    Returns:
        Dictionary containing all rules
        
    Raises:
        FileNotFoundError: If rules file doesn't exist
        ValueError: If JSON is invalid
    """
    global _RULES_CACHE, _FALSE_POSITIVE_WORDS, _NEGATIVE_CONTEXT, _POSITIVE_CONTEXT, _CATEGORY_WORDS
    
    path = Path(rules_path)
    
    if not path.exists():
        raise FileNotFoundError(
            f"false_positives.json not found at: {path}\n"
            f"Create this file with false positive detection rules."
        )
    
    with open(path, encoding="utf-8") as f:
        rules = json.load(f)
    
    # Build flattened set of all false positive words
    false_positive_words = set()
    category_words = {}
    
    name_config = rules.get("name_false_positives", {})
    categories = name_config.get("categories", {})
    
    for category_name, category_data in categories.items():
        words = set(category_data.get("words", []))
        category_words[category_name] = words
        false_positive_words.update(words)
    
    # Load context keywords
    context_keywords = name_config.get("context_keywords", {})
    negative_context = context_keywords.get("negative", {}).get("words", [])
    positive_context = context_keywords.get("positive", {}).get("words", [])
    
    # Cache everything
    _RULES_CACHE = rules
    _FALSE_POSITIVE_WORDS = false_positive_words
    _NEGATIVE_CONTEXT = negative_context
    _POSITIVE_CONTEXT = positive_context
    _CATEGORY_WORDS = category_words
    
    return rules


def get_false_positive_words() -> Set[str]:
    """Get all false positive words as a flattened set."""
    if _FALSE_POSITIVE_WORDS is None:
        raise RuntimeError("Must call load_false_positive_rules() first")
    return _FALSE_POSITIVE_WORDS


def get_category_words(category: str) -> Set[str]:
    """Get words for a specific category (e.g., 'months', 'address_indicators')."""
    if _CATEGORY_WORDS is None:
        raise RuntimeError("Must call load_false_positive_rules() first")
    return _CATEGORY_WORDS.get(category, set())


def get_negative_context() -> List[str]:
    """Get list of negative context keywords."""
    if _NEGATIVE_CONTEXT is None:
        raise RuntimeError("Must call load_false_positive_rules() first")
    return _NEGATIVE_CONTEXT


def get_positive_context() -> List[str]:
    """Get list of positive context keywords."""
    if _POSITIVE_CONTEXT is None:
        raise RuntimeError("Must call load_false_positive_rules() first")
    return _POSITIVE_CONTEXT


def get_rules_config() -> Dict:
    """Get the rules configuration (enabled checks, thresholds, etc.)."""
    if _RULES_CACHE is None:
        raise RuntimeError("Must call load_false_positive_rules() first")
    return _RULES_CACHE.get("name_false_positives", {}).get("rules", {})


def add_custom_false_positive(word: str, category: str = "custom") -> bool:
    """
    Add a custom false positive word to the in-memory rules.
    Note: This does NOT persist to disk.
    
    Args:
        word: The word to add as false positive
        category: Which category to add it to ('custom' by default)
        
    Returns:
        True if added successfully
    """
    if _CATEGORY_WORDS is None:
        return False
    
    if category not in _CATEGORY_WORDS:
        category = "custom"
    
    _CATEGORY_WORDS[category].add(word.lower())
    _FALSE_POSITIVE_WORDS.add(word.lower())
    return True


def reload_rules(rules_path: str | Path) -> Dict:
    """Reload rules from disk (useful for dynamic updates)."""
    return load_false_positive_rules(rules_path)


# Optional: Function to save custom words to disk
def save_custom_words(rules_path: str | Path, custom_words: List[str]) -> bool:
    """
    Save custom words to the JSON file.
    
    Args:
        rules_path: Path to false_positives.json
        custom_words: List of custom words to add
        
    Returns:
        True if saved successfully
    """
    path = Path(rules_path)
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            rules = json.load(f)
        
        # Add custom words
        custom_category = rules.get("name_false_positives", {}).get("categories", {}).get("custom", {})
        if "words" not in custom_category:
            custom_category["words"] = []
        
        # Add new words without duplicates
        existing = set(custom_category["words"])
        new_words = [w for w in custom_words if w.lower() not in existing]
        custom_category["words"].extend(new_words)
        
        # Save back
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(rules, f, indent=2)
        
        # Reload rules
        reload_rules(rules_path)
        return True
        
    except Exception as e:
        print(f"Error saving custom words: {e}")
        return False