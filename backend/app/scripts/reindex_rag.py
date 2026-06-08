"""Reindex Stage 2 public RAG sources into the shared collection."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from app.rag.stage2_importer import (
    DEFAULT_STAGE2_ATTACK_RULE_SOURCE_TYPES,
    DEFAULT_COLLECTION_NAME,
    DEFAULT_NORMALIZED_DOCS,
    DEFAULT_STAGE2_FINGERPRINT_SOURCE_TYPES,
    DEFAULT_STAGE2_THREAT_INTEL_SOURCE_TYPES,
    DEFAULT_STAGE2_SOURCE_TYPES,
    import_stage2_public,
)


STAGE2_PROFILES: dict[str, tuple[str, ...]] = {
    "attack_rules": DEFAULT_STAGE2_ATTACK_RULE_SOURCE_TYPES,
    "threat_intel": DEFAULT_STAGE2_THREAT_INTEL_SOURCE_TYPES,
    "fingerprints": DEFAULT_STAGE2_FINGERPRINT_SOURCE_TYPES,
    "all_public": DEFAULT_STAGE2_ATTACK_RULE_SOURCE_TYPES + DEFAULT_STAGE2_THREAT_INTEL_SOURCE_TYPES + DEFAULT_STAGE2_FINGERPRINT_SOURCE_TYPES,
}


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reindex Stage 2 public RAG sources.")
    parser.add_argument("--collection", default=DEFAULT_COLLECTION_NAME)
    parser.add_argument("--profile", choices=sorted(STAGE2_PROFILES), default="attack_rules")
    parser.add_argument("--source-types", nargs="*", default=list(DEFAULT_STAGE2_SOURCE_TYPES))
    parser.add_argument("--categories", nargs="*", default=None)
    parser.add_argument("--input", default=str(DEFAULT_NORMALIZED_DOCS))
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    source_types = args.source_types if args.source_types != list(DEFAULT_STAGE2_SOURCE_TYPES) else list(STAGE2_PROFILES[args.profile])
    summary = import_stage2_public(
        collection_name=args.collection,
        source_types=source_types,
        categories=args.categories,
        path=Path(args.input),
        limit=args.limit,
        dry_run=args.dry_run,
        batch_size=args.batch_size,
    )
    print(
        "Stage 2 public import complete: "
        f"seen={summary['seen']} selected={summary['selected']} indexed={summary['indexed']} "
        f"skipped_existing={summary['skipped_existing']} collection={args.collection}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
