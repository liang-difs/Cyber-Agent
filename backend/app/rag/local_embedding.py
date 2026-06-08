"""Deterministic local embedding fallback for offline RAG indexing."""

from __future__ import annotations

import hashlib
import math
import re

TOKEN_RE = re.compile(r"[a-z0-9]+")
EMBEDDING_DIMENSION = 384


def embed_texts(texts: list[str], dimension: int = EMBEDDING_DIMENSION) -> list[list[float]]:
    """Embed texts with a stable hashing fallback."""
    return [_embed_text(text, dimension=dimension) for text in texts]


def _embed_text(text: str, dimension: int = EMBEDDING_DIMENSION) -> list[float]:
    vector = [0.0] * dimension
    for token in TOKEN_RE.findall(text.lower()):
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        index = int.from_bytes(digest[:4], "little") % dimension
        sign = 1.0 if digest[4] & 1 else -1.0
        vector[index] += sign

    norm = math.sqrt(sum(value * value for value in vector))
    if norm:
        vector = [value / norm for value in vector]
    return vector
