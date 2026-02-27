"""Entropy utility functions used for lexical URL analysis."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy for a string.

    Args:
        value: Input text to evaluate.

    Returns:
        Shannon entropy in bits per symbol.
    """
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy