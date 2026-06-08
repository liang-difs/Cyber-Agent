"""Tests for knowledge graph module.

Covers: KnowledgeGraph, EntityExtractor.
"""

import pytest
from app.knowledge_graph.graph import KnowledgeGraph
from app.knowledge_graph.extractor import EntityExtractor
from app.knowledge_graph.entity import Entity, EntityType
from app.knowledge_graph.relation import Relation, RelationType


class TestKnowledgeGraph:
    def test_init_creates_graph(self):
        kg = KnowledgeGraph()
        assert kg is not None

    def test_add_entity(self):
        kg = KnowledgeGraph()
        entity = Entity(
            id="test-1",
            name="CVE-2024-1234",
            entity_type=EntityType.CVE,
            confidence=0.9,
            source="test",
        )
        result_id = kg.add_entity(entity)
        assert result_id == "test-1"
        retrieved = kg.get_entity("test-1")
        assert retrieved is not None
        assert retrieved.name == "CVE-2024-1234"

    def test_add_relation(self):
        kg = KnowledgeGraph()
        e1 = Entity(id="ip-1", name="192.168.1.1", entity_type=EntityType.IP, confidence=0.8, source="test")
        e2 = Entity(id="cve-1", name="CVE-2024-1234", entity_type=EntityType.CVE, confidence=0.9, source="test")
        kg.add_entity(e1)
        kg.add_entity(e2)
        rel = Relation(
            id="rel-1",
            source_id="ip-1",
            target_id="cve-1",
            relation_type=RelationType.EXPLOITS,
            confidence=0.7,
        )
        rel_id = kg.add_relation(rel)
        assert rel_id == "rel-1"

    def test_search_entities_by_name(self):
        kg = KnowledgeGraph()
        entity = Entity(id="test-2", name="Emotet", entity_type=EntityType.MALWARE, confidence=0.9, source="test")
        kg.add_entity(entity)
        results = kg.search_entities("Emotet")
        assert len(results) >= 1
        assert any(e.name == "Emotet" for e in results)

    def test_find_entities_by_type(self):
        kg = KnowledgeGraph()
        e1 = Entity(id="ip-1", name="10.0.0.1", entity_type=EntityType.IP, confidence=0.8, source="test")
        e2 = Entity(id="cve-1", name="CVE-2024-0001", entity_type=EntityType.CVE, confidence=0.9, source="test")
        kg.add_entity(e1)
        kg.add_entity(e2)
        results = kg.find_entities_by_type(EntityType.IP)
        assert len(results) >= 1
        assert all(e.entity_type == EntityType.IP for e in results)

    def test_get_neighbors(self):
        kg = KnowledgeGraph()
        e1 = Entity(id="a", name="A", entity_type=EntityType.IP, confidence=0.8, source="test")
        e2 = Entity(id="b", name="B", entity_type=EntityType.DOMAIN, confidence=0.8, source="test")
        e3 = Entity(id="c", name="C", entity_type=EntityType.MALWARE, confidence=0.8, source="test")
        kg.add_entity(e1)
        kg.add_entity(e2)
        kg.add_entity(e3)
        kg.add_relation(Relation(id="r1", source_id="a", target_id="b", relation_type=RelationType.COMMUNICATES_WITH, confidence=0.7))
        kg.add_relation(Relation(id="r2", source_id="b", target_id="c", relation_type=RelationType.USES, confidence=0.7))
        neighbors = kg.get_neighbors("a", depth=1)
        assert isinstance(neighbors, dict)

    def test_find_path(self):
        kg = KnowledgeGraph()
        e1 = Entity(id="x", name="X", entity_type=EntityType.IP, confidence=0.8, source="test")
        e2 = Entity(id="y", name="Y", entity_type=EntityType.DOMAIN, confidence=0.8, source="test")
        kg.add_entity(e1)
        kg.add_entity(e2)
        kg.add_relation(Relation(id="r1", source_id="x", target_id="y", relation_type=RelationType.COMMUNICATES_WITH, confidence=0.7))
        path = kg.find_path("x", "y")
        assert path is not None

    def test_export_to_dict(self):
        kg = KnowledgeGraph()
        entity = Entity(id="test-3", name="Test", entity_type=EntityType.IP, confidence=0.8, source="test")
        kg.add_entity(entity)
        data = kg.export_to_dict()
        assert "entities" in data
        assert "relations" in data
        assert len(data["entities"]) >= 1

    def test_get_stats(self):
        kg = KnowledgeGraph()
        e1 = Entity(id="s1", name="A", entity_type=EntityType.IP, confidence=0.8, source="test")
        e2 = Entity(id="s2", name="B", entity_type=EntityType.CVE, confidence=0.9, source="test")
        kg.add_entity(e1)
        kg.add_entity(e2)
        stats = kg.get_stats()
        assert "total_entities" in stats
        assert stats["total_entities"] >= 2

    def test_delete_entity(self):
        kg = KnowledgeGraph()
        entity = Entity(id="del-1", name="ToDelete", entity_type=EntityType.IP, confidence=0.8, source="test")
        kg.add_entity(entity)
        assert kg.get_entity("del-1") is not None
        result = kg.delete_entity("del-1")
        assert result is True
        assert kg.get_entity("del-1") is None

    def test_find_entity_by_name(self):
        kg = KnowledgeGraph()
        entity = Entity(id="fbn-1", name="FindMe", entity_type=EntityType.MALWARE, confidence=0.8, source="test")
        kg.add_entity(entity)
        found = kg.find_entity_by_name("FindMe")
        assert found is not None
        assert found.name == "FindMe"

    def test_get_entity_relations(self):
        kg = KnowledgeGraph()
        e1 = Entity(id="er-1", name="E1", entity_type=EntityType.IP, confidence=0.8, source="test")
        e2 = Entity(id="er-2", name="E2", entity_type=EntityType.DOMAIN, confidence=0.8, source="test")
        kg.add_entity(e1)
        kg.add_entity(e2)
        kg.add_relation(Relation(id="err-1", source_id="er-1", target_id="er-2", relation_type=RelationType.COMMUNICATES_WITH, confidence=0.7))
        rels = kg.get_entity_relations("er-1")
        assert len(rels) >= 1


class TestEntityExtractor:
    def test_extract_entities_cve(self):
        extractor = EntityExtractor()
        text = "Vulnerability CVE-2024-1234 was found in the system."
        entities = extractor.extract_entities(text)
        cves = [e for e in entities if e.entity_type == EntityType.CVE]
        assert len(cves) >= 1
        assert "CVE-2024-1234" in cves[0].name

    def test_extract_entities_ip(self):
        extractor = EntityExtractor()
        # Use public IP since private IPs may be filtered
        text = "Suspicious traffic from 203.0.113.50 detected."
        entities = extractor.extract_entities(text)
        ips = [e for e in entities if e.entity_type == EntityType.IP]
        assert len(ips) >= 1

    def test_extract_entities_hash(self):
        extractor = EntityExtractor()
        text = "Malicious file hash: d41d8cd98f00b204e9800998ecf8427e"
        entities = extractor.extract_entities(text)
        hashes = [e for e in entities if e.entity_type == EntityType.HASH]
        assert len(hashes) >= 1

    def test_extract_entities_domain(self):
        extractor = EntityExtractor()
        text = "C2 server evil-domain.example.com contacted."
        entities = extractor.extract_entities(text)
        domains = [e for e in entities if e.entity_type == EntityType.DOMAIN]
        assert len(domains) >= 1

    def test_extract_entities_empty_text(self):
        extractor = EntityExtractor()
        entities = extractor.extract_entities("")
        assert entities == []

    def test_extract_entities_no_entities(self):
        extractor = EntityExtractor()
        entities = extractor.extract_entities("This is a normal sentence with no IOCs.")
        assert isinstance(entities, list)

    def test_extract_from_log(self):
        extractor = EntityExtractor()
        log_entry = {"message": "Connection from 10.0.0.1 to evil.com", "level": "warning"}
        entities = extractor.extract_from_log(log_entry)
        assert isinstance(entities, list)

    def test_extract_from_ioc(self):
        extractor = EntityExtractor()
        ioc_data = {"value": "192.168.1.1", "type": "ip"}
        entities = extractor.extract_from_ioc(ioc_data)
        assert isinstance(entities, list)
