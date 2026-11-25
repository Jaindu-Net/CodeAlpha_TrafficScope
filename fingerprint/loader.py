"""Loader and scorer for the passive OS fingerprint JSON database."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "db" / "fingerprints.json"


@dataclass(frozen=True, slots=True)
class FingerprintEntry:
    """Single OS/device signature in the local fingerprint database."""

    os: str
    ttl_range: tuple[int, int]
    window_size: int | None
    tcp_options_order: tuple[str, ...]
    confidence: int


@dataclass(frozen=True, slots=True)
class FingerprintMatch:
    """Scored match result produced by FingerprintDB.match()."""

    os: str
    score: int
    entry_confidence: int


def _validate_ttl_range(ttl_range: Any, idx: int) -> tuple[int, int]:
    """Validate a [min_ttl, max_ttl] pair within 0..255."""
    valid_ints = (
        isinstance(ttl_range, list)
        and len(ttl_range) == 2
        and all(isinstance(v, int) and 0 <= v <= 255 for v in ttl_range)
    )
    if not valid_ints or ttl_range[0] > ttl_range[1]:
        raise ValueError(f"Fingerprint entry #{idx} 'ttl_range' must be [min, max] in 0..255.")
    return (ttl_range[0], ttl_range[1])


def _validate_entry(raw: Any, idx: int) -> FingerprintEntry:
    """Validate and convert a raw JSON dictionary into a FingerprintEntry."""
    if not isinstance(raw, dict):
        raise ValueError(f"Fingerprint entry #{idx} must be a JSON object.")

    required = {"os", "ttl_range", "window_size", "tcp_options_order", "confidence"}
    missing = required - set(raw.keys())
    if missing:
        raise ValueError(f"Fingerprint entry #{idx} missing keys: {sorted(missing)}")

    os_name = raw["os"]
    if not isinstance(os_name, str) or not os_name.strip():
        raise ValueError(f"Fingerprint entry #{idx} 'os' must be a non-empty string.")

    ttl_pair = _validate_ttl_range(raw["ttl_range"], idx)
    window_size = raw["window_size"]
    if window_size is not None and (not isinstance(window_size, int) or window_size < 0):
        raise ValueError(f"Fingerprint entry #{idx} 'window_size' must be int >= 0 or null.")

    opts = raw["tcp_options_order"]
    if not isinstance(opts, list) or not all(isinstance(o, str) for o in opts):
        raise ValueError(f"Fingerprint entry #{idx} 'tcp_options_order' must be list[str].")

    confidence = raw["confidence"]
    if not isinstance(confidence, int) or not (1 <= confidence <= 100):
        raise ValueError(f"Fingerprint entry #{idx} 'confidence' must be int in 1..100.")

    return FingerprintEntry(
        os=os_name.strip(),
        ttl_range=ttl_pair,
        window_size=window_size,
        tcp_options_order=tuple(opts),
        confidence=confidence,
    )


def _score_entry(
    entry: FingerprintEntry,
    ttl: int,
    window: int,
    obs_opts: tuple[str, ...],
    obs_no_nop: tuple[str, ...],
) -> int:
    """Compute structural match score (0-100) for one fingerprint DB entry."""
    if not (entry.ttl_range[0] <= ttl <= entry.ttl_range[1]):
        return 0

    score = 40
    if entry.window_size is None:
        score += 15
    elif entry.window_size == window:
        score += 30

    if entry.tcp_options_order == obs_opts:
        score += 30
    elif obs_no_nop and tuple(o for o in entry.tcp_options_order if o != "NOP") == obs_no_nop:
        score += 15
    return score


class FingerprintDB:
    """Loads passive TCP/IP OS signatures and scores candidate packet headers."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        """Load and validate the JSON fingerprint database."""
        self.db_path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
        self.entries: tuple[FingerprintEntry, ...] = self._load(self.db_path)

    @staticmethod
    def _load(path: Path) -> tuple[FingerprintEntry, ...]:
        if not path.is_file():
            raise FileNotFoundError(f"Fingerprint DB not found: {path}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed fingerprint DB JSON '{path}': {exc}") from exc

        if not isinstance(payload, list):
            raise ValueError(f"Fingerprint DB '{path}' must be a JSON array.")

        return tuple(_validate_entry(item, idx) for idx, item in enumerate(payload))

    def match(
        self,
        ttl: int,
        window: int,
        options_order: list[str] | tuple[str, ...],
        *,
        min_score: int = 40,
        limit: int = 3,
    ) -> list[FingerprintMatch]:
        """Score observed SYN header features and return top matches descending."""
        obs_opts = tuple(options_order)
        obs_no_nop = tuple(opt for opt in obs_opts if opt != "NOP")
        matches: list[FingerprintMatch] = []

        for entry in self.entries:
            score = _score_entry(entry, ttl, window, obs_opts, obs_no_nop)
            if score >= min_score:
                matches.append(
                    FingerprintMatch(
                        os=entry.os,
                        score=score,
                        entry_confidence=entry.confidence,
                    )
                )

        matches.sort(key=lambda m: (m.score, m.entry_confidence), reverse=True)
        return matches[:limit]
