# ADR-020: Existing Case Sysmon Collection ingestion

## Status

Approved by the user on 2026-10-14 for local implementation and verification.

## Decision

- A Python `CollectionValidator` implements the existing Host demo's strict
  three-file contract for `process-create.xml`, `file-create.xml`, and
  `collection-metadata.json`.
- Validation reads bounded regular files once into immutable byte snapshots.
  Those exact bytes, rather than reopened source paths, are passed to the
  Artifact Store. Source links, layout changes, and changes during validation
  are rejected.
- The existing Sysmon normalizer remains the XML parser and field-validation
  boundary. Collection validation adds the Host contract's role, positive
  record/process identifiers, non-zero GUID, metadata identity, and paired
  event correlation checks. The normalizer's 1 MiB XML limit remains in force.
- `CollectionIngestionService` targets an existing Open Case and inserts all
  missing Artifact rows under one SQLite write transaction. Process Create and
  File Create XML use `ArtifactKind.SYSMON`; metadata uses
  `ArtifactKind.OTHER`.
- A reuse candidate must belong to the same Case and have the same kind and
  SHA-256. Its canonical content is verified before reuse, and Sysmon content
  must normalize to the requested role. The lowest existing Artifact display
  ID is selected deterministically.
- A complete retry reuses all three Artifact rows. A partial match creates only
  missing rows, so already attached Sysmon XML does not create duplicate
  Timeline observations.
- Newly published bytes are tracked by ownership identity. If the SQLite
  transaction fails, rows and counters roll back, then only operation-owned
  content with no committed Artifact reference is deleted. Cleanup failure is
  reported as `ARTIFACT_CLEANUP_FAILED`.
- This feature works with both SQLite v1 and v2 and adds no schema or migration.
  Collection metadata does not create manual evidence provenance.

## Consequences

An existing Case can contain analyst-supplied Manual Evidence and an automated
Sysmon Collection without conflating their trust or provenance semantics.
Timeline and Markdown Report behavior remains unchanged because they continue
to consume the two generic Sysmon Artifacts. Collection-level history, queries,
and Execution Run identity are intentionally unavailable until a later model is
approved.
