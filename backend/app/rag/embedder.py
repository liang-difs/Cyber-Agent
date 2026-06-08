"""BGE-M3 Embedding Service with degradation protection."""

from __future__ import annotations

import logging
import os
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# Set HF mirror before any huggingface imports so the endpoint is picked up.
os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")

_MODEL_LOAD_TIMEOUT = 15  # seconds

# Keep a module-level symbol so tests can patch it, but avoid importing the
# heavy dependency until an embedding model is actually needed.
SentenceTransformer = None  # type: ignore[assignment,misc]


def _get_sentence_transformer():
    global SentenceTransformer
    if SentenceTransformer is not None:
        return SentenceTransformer

    try:
        from sentence_transformers import SentenceTransformer as _SentenceTransformer
    except ImportError:
        return None

    SentenceTransformer = _SentenceTransformer
    return SentenceTransformer


class EmbeddingService:
    """BGE-M3 embedding with graceful degradation."""

    def __init__(self, model_name: str = "BAAI/bge-m3"):
        self._model = None
        self._is_available = False
        try:
            sentence_transformer_cls = _get_sentence_transformer()
            if sentence_transformer_cls is None:
                raise ImportError("sentence_transformers not installed")
            # Load model in a thread with timeout to avoid blocking when
            # huggingface.co is unreachable (retries cause 30+ second hangs).
            result = [None]
            error = [None]

            def _load():
                try:
                    result[0] = sentence_transformer_cls(model_name)
                except Exception as e:
                    error[0] = e

            t = threading.Thread(target=_load, daemon=True)
            t.start()
            t.join(timeout=_MODEL_LOAD_TIMEOUT)

            if t.is_alive():
                logger.warning(
                    "Embedding model load timed out after %ds — RAG will degrade to BM25",
                    _MODEL_LOAD_TIMEOUT,
                )
            elif error[0]:
                raise error[0]
            elif result[0] is not None:
                self._model = result[0]
                self._is_available = True
                logger.info("Embedding model loaded: %s", model_name)
        except Exception as e:
            logger.warning("Embedding model unavailable: %s — RAG will degrade to BM25", e)

    @property
    def is_available(self) -> bool:
        return self._is_available

    def encode(self, texts: list[str]) -> Optional[list[list[float]]]:
        """Encode texts to vectors. Returns None if model unavailable."""
        if not self._is_available or self._model is None:
            return None
        try:
            embeddings = self._model.encode(texts, normalize_embeddings=True)
            return embeddings.tolist()
        except Exception as e:
            logger.error("Embedding encode failed: %s", e)
            return None
