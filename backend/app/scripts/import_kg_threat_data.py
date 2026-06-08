"""Import threat intelligence data into the Knowledge Graph.

导入 MITRE ATT&CK 和 CVE 数据到知识图谱。
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def import_mitre_attack(graph, attack_path: str) -> dict[str, int]:
    """Import MITRE ATT&CK data into the knowledge graph."""
    from app.knowledge_graph.entity import Entity, EntityType
    from app.knowledge_graph.relation import Relation, RelationType

    with open(attack_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])
    stats = {"techniques": 0, "malware": 0, "threat_actors": 0, "tools": 0, "tactics": 0, "relations": 0}

    # Build ID → name map for relationship resolution
    id_map: dict[str, str] = {}

    for obj in objects:
        obj_type = obj.get("type")
        obj_id = obj.get("id", "")
        name = obj.get("name", "")
        description = (obj.get("description") or "")[:500]

        if not name:
            continue

        # Extract ATT&CK ID from external references
        attack_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id", "")
                break

        entity = None

        if obj_type == "attack-pattern":
            entity = Entity(
                id=f"technique-{attack_id or obj_id}",
                name=name,
                entity_type=EntityType.TECHNIQUE,
                properties={
                    "attack_id": attack_id,
                    "description": description,
                    "platforms": obj.get("x_mitre_platforms", []),
                    "kill_chain_phases": [
                        p.get("phase_name", "")
                        for p in obj.get("kill_chain_phases", [])
                    ],
                },
                source="mitre_attack",
                confidence=0.95,
                tags=["mitre", "attack", "technique"],
            )
            stats["techniques"] += 1

        elif obj_type == "malware":
            entity = Entity(
                id=f"malware-{attack_id or obj_id}",
                name=name,
                entity_type=EntityType.MALWARE,
                properties={
                    "attack_id": attack_id,
                    "description": description,
                    "platforms": obj.get("x_mitre_platforms", []),
                    "is_family": obj.get("x_mitre_is_family", False),
                },
                source="mitre_attack",
                confidence=0.9,
                tags=["mitre", "malware"],
            )
            stats["malware"] += 1

        elif obj_type == "intrusion-set":
            entity = Entity(
                id=f"threat_actor-{attack_id or obj_id}",
                name=name,
                entity_type=EntityType.THREAT_ACTOR,
                properties={
                    "attack_id": attack_id,
                    "description": description,
                    "aliases": obj.get("aliases", []),
                },
                source="mitre_attack",
                confidence=0.9,
                tags=["mitre", "threat_actor"],
            )
            stats["threat_actors"] += 1

        elif obj_type == "tool":
            entity = Entity(
                id=f"tool-{attack_id or obj_id}",
                name=name,
                entity_type=EntityType.TOOL,
                properties={
                    "attack_id": attack_id,
                    "description": description,
                    "platforms": obj.get("x_mitre_platforms", []),
                },
                source="mitre_attack",
                confidence=0.9,
                tags=["mitre", "tool"],
            )
            stats["tools"] += 1

        elif obj_type == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname", "")
            entity = Entity(
                id=f"tactic-{shortname or attack_id}",
                name=name,
                entity_type=EntityType.TACTIC,
                properties={
                    "attack_id": attack_id,
                    "shortname": shortname,
                    "description": description,
                },
                source="mitre_attack",
                confidence=0.95,
                tags=["mitre", "tactic"],
            )
            stats["tactics"] += 1

        if entity:
            graph.add_entity(entity)
            id_map[obj_id] = entity.id

    # Import relationships
    for obj in objects:
        if obj.get("type") != "relationship":
            continue

        source_ref = obj.get("source_ref", "")
        target_ref = obj.get("target_ref", "")
        rel_type = obj.get("relationship_type", "")

        source_entity_id = id_map.get(source_ref)
        target_entity_id = id_map.get(target_ref)

        if not source_entity_id or not target_entity_id:
            continue

        # Map STIX relationship types to our RelationType
        relation_map = {
            "uses": RelationType.USES,
            "mitigates": RelationType.MITIGATES,
            "indicates": RelationType.RELATED_TO,
            "attributed-to": RelationType.ATTRIBUTED_TO,
            "targets": RelationType.AFFECTS,
            "delivers": RelationType.DELIVERS,
            "drops": RelationType.DROPS,
        }

        rt = relation_map.get(rel_type)
        if not rt:
            continue

        relation = Relation(
            id=f"rel-{obj.get('id', '')}",
            source_id=source_entity_id,
            target_id=target_entity_id,
            relation_type=rt,
            confidence=0.9,
            properties={"stix_relationship": rel_type},
        )

        try:
            graph.add_relation(relation)
            stats["relations"] += 1
        except (ValueError, KeyError):
            pass

    return stats


def import_cve_entities(graph, cve_jsonl_path: str, max_items: int = 5000) -> dict[str, int]:
    """Import CVE records as entities in the knowledge graph."""
    from app.knowledge_graph.entity import Entity, EntityType

    stats = {"cves": 0, "errors": 0}

    with open(cve_jsonl_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= max_items:
                break
            try:
                record = json.loads(line)
                cve_id = record.get("cve_id", "")
                if not cve_id:
                    continue

                entity = Entity(
                    id=cve_id,
                    name=cve_id,
                    entity_type=EntityType.CVE,
                    properties={
                        "cvss_score": record.get("cvss_score"),
                        "severity": record.get("severity", ""),
                        "published": record.get("published", ""),
                        "description": (record.get("description") or "")[:300],
                    },
                    source="nvd",
                    confidence=0.95,
                    tags=["cve", "nvd"],
                )
                graph.add_entity(entity)
                stats["cves"] += 1

            except (json.JSONDecodeError, Exception):
                stats["errors"] += 1

    return stats


def main():
    from app.knowledge_graph.graph import get_knowledge_graph

    graph = get_knowledge_graph()
    corpus_dir = Path("corpus")

    # 1. Import MITRE ATT&CK
    attack_path = corpus_dir / "attack" / "mitre_attack.json"
    if attack_path.exists():
        logger.info("Importing MITRE ATT&CK from %s", attack_path)
        stats = import_mitre_attack(graph, str(attack_path))
        logger.info("ATT&CK import: %s", stats)
    else:
        logger.warning("MITRE ATT&CK file not found: %s", attack_path)

    # 2. Import CVE entities (from high severity corpus)
    for cve_file in ["nvd_critical.jsonl", "nvd_high.jsonl"]:
        cve_path = corpus_dir / "nvd_full" / cve_file
        if cve_path.exists():
            logger.info("Importing CVEs from %s", cve_path)
            stats = import_cve_entities(graph, str(cve_path), max_items=5000)
            logger.info("CVE import from %s: %s", cve_file, stats)

    # 3. Print final stats
    final_stats = graph.get_stats()
    logger.info("Knowledge graph final stats: %s", final_stats)


if __name__ == "__main__":
    main()
