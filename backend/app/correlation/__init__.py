"""
Correlation layer public API.

Primary entry points:
    extract_entities()          – extract entities from a NormalizedEvent
    enrich_normalized_payload() – merge extraction result into a stream payload dict

All other symbols are importable directly from their modules.
"""
from app.correlation.extractor import EntityExtractor, extract_entities
from app.correlation.enrichment import enrich_normalized_payload, collect_entity_keys
from app.correlation.schemas import ExtractionResult, EntitySet, CorrelationMetadata

__all__ = [
    "EntityExtractor",
    "extract_entities",
    "enrich_normalized_payload",
    "collect_entity_keys",
    "ExtractionResult",
    "EntitySet",
    "CorrelationMetadata",
]
