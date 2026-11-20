"""Deterministic random stream for the world generator.

The generator never uses Python's :mod:`random`. Every list it builds draws
from its own :class:`SeedStream`, a SHA-256 counter-mode stream keyed by the
world seed and a label (``"people"``, ``"sms"``, ``"photos"`` ...). Adding
photos therefore never changes the contacts: the two lists read independent
streams.

The byte stream is ``sha256(DOMAIN || seed || 0x00 || label || 0x00 ||
counter_be64)`` for ``counter = 0, 1, 2, ...``; each block yields four 64-bit
words. The output depends only on the seed bytes and the label, so it is
identical on every platform and Python version.
"""

from __future__ import annotations

import bisect
import hashlib
import math
import secrets
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Sequence

T = TypeVar("T")

_DOMAIN = b"sandroid-world-stream-v1\x00"
_TWO_64 = float(1 << 64)
#: Minimum seed length in hex digits (128 bits).
MIN_SEED_HEX = 32


def new_seed() -> str:
    """Return a fresh random seed in the ``"hex:<64 hex>"`` form."""
    return "hex:" + secrets.token_hex(32)


def parse_seed(seed: str) -> bytes:
    """Decode a ``"hex:<32+ hex>"`` seed string.

    Args:
        seed: The seed as written in a world spec.

    Returns:
        The seed bytes.

    Raises:
        ValueError: The seed is not ``hex:`` followed by at least
            :data:`MIN_SEED_HEX` hex digits (an even number).
    """
    if not isinstance(seed, str) or not seed.startswith("hex:"):
        raise ValueError(f"world seed must be 'auto' or 'hex:<hex>', got {seed!r}")
    digits = seed[4:]
    if len(digits) < MIN_SEED_HEX or len(digits) % 2:
        raise ValueError(
            f"world seed needs an even number of at least {MIN_SEED_HEX} hex digits"
        )
    try:
        return bytes.fromhex(digits)
    except ValueError as exc:
        raise ValueError(f"world seed is not hex: {seed!r}") from exc


class SeedStream:
    """SHA-256 counter-mode random stream.

    Args:
        seed: Seed bytes (see :func:`parse_seed`).
        label: Stream label; different labels give independent streams.
    """

    __slots__ = ("_buf", "_counter", "_prefix", "label", "seed")

    def __init__(self, seed: bytes, label: str) -> None:
        self.seed = seed
        self.label = label
        self._prefix = _DOMAIN + seed + b"\x00" + label.encode("utf-8") + b"\x00"
        self._counter = 0
        self._buf: list[int] = []

    def u64(self) -> int:
        """Return the next 64-bit unsigned integer."""
        if not self._buf:
            block = hashlib.sha256(
                self._prefix + self._counter.to_bytes(8, "big")
            ).digest()
            self._counter += 1
            self._buf = [
                int.from_bytes(block[i : i + 8], "big") for i in (24, 16, 8, 0)
            ]
        return self._buf.pop()

    def random(self) -> float:
        """Return a float in ``[0, 1)``."""
        return self.u64() / _TWO_64

    def below(self, n: int) -> int:
        """Return an integer in ``[0, n)`` without modulo bias."""
        if n <= 0:
            raise ValueError("below() needs n > 0")
        limit = (1 << 64) - ((1 << 64) % n)
        while True:
            value = self.u64()
            if value < limit:
                return value % n

    def randint(self, low: int, high: int) -> int:
        """Return an integer in ``[low, high]`` (both inclusive)."""
        return low + self.below(high - low + 1)

    def uniform(self, low: float, high: float) -> float:
        """Return a float in ``[low, high)``."""
        return low + (high - low) * self.random()

    def chance(self, p: float) -> bool:
        """Return True with probability ``p``."""
        return self.random() < p

    def choice(self, items: Sequence[T]) -> T:
        """Return one element of a non-empty sequence."""
        return items[self.below(len(items))]

    def digits(self, n: int, *, first_nonzero: bool = False) -> str:
        """Return ``n`` random decimal digits."""
        out = [str(self.below(10)) for _ in range(n)]
        if first_nonzero and out:
            out[0] = str(1 + self.below(9))
        return "".join(out)

    def weighted(self, items: Sequence[T], weights: Sequence[float]) -> T:
        """Return one element, drawn with the given non-negative weights."""
        return items[self.weighted_index(Cumulative(weights))]

    def weighted_index(self, cumulative: Cumulative) -> int:
        """Return an index drawn from a precomputed :class:`Cumulative`."""
        return cumulative.pick(self.random())

    def shuffled(self, items: Sequence[T]) -> list[T]:
        """Return a Fisher-Yates shuffled copy."""
        out = list(items)
        for i in range(len(out) - 1, 0, -1):
            j = self.below(i + 1)
            out[i], out[j] = out[j], out[i]
        return out

    def gauss(self, mu: float = 0.0, sigma: float = 1.0) -> float:
        """Return a normally distributed float (Box-Muller)."""
        u1 = max(self.random(), 1e-300)
        u2 = self.random()
        return mu + sigma * math.sqrt(-2.0 * math.log(u1)) * math.cos(2 * math.pi * u2)

    def lognormal(self, median: float, sigma: float) -> float:
        """Return a log-normally distributed float with the given median."""
        return median * math.exp(self.gauss(0.0, sigma))


class Cumulative:
    """Precomputed cumulative weights for repeated weighted draws.

    Args:
        weights: Non-negative weights; at least one must be positive.
    """

    __slots__ = ("_cum", "total")

    def __init__(self, weights: Sequence[float]) -> None:
        total = 0.0
        cum: list[float] = []
        for w in weights:
            total += max(float(w), 0.0)
            cum.append(total)
        if total <= 0:
            raise ValueError("weighted draw needs a positive weight")
        self._cum = cum
        self.total = total

    def pick(self, u: float) -> int:
        """Map a uniform ``u`` in ``[0, 1)`` to an index."""
        idx = bisect.bisect_right(self._cum, u * self.total)
        return min(idx, len(self._cum) - 1)
