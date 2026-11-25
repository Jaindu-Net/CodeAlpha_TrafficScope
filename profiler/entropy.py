"""Byte-level Shannon entropy calculation and payload classification."""

from __future__ import annotations

import numpy as np


def shannon_entropy(data: bytes) -> float:
    """Compute byte-level Shannon entropy in bits per byte (range 0.0 to 8.0)."""
    if not data:
        return 0.0

    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    nonzero = counts[counts > 0]
    probs = nonzero / len(data)
    entropy = float(-np.sum(probs * np.log2(probs)))
    return max(0.0, entropy)


def classify_entropy(entropy_value: float) -> str:
    """Categorize Shannon entropy into plaintext, compressed/mixed, or encrypted."""
    if entropy_value < 3.5:
        return "plaintext"
    if entropy_value <= 6.0:
        return "compressed/mixed"
    return "likely encrypted"
