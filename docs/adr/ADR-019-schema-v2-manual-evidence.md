# ADR-019: SQLite v2 and manual evidence provenance

## Status

Approved by the user on 2026-10-14 for local implementation and verification.

## Decision

- SQLite schema v2 adds an optional one-to-one `artifact_provenance` row for an
  existing Artifact. The `artifacts` table and `Artifact` domain object do not
  change.
- New Projects use SQLite v2. Existing valid v1 and v2 Projects remain readable
  by the M0-M2 services. Manual Evidence registration requires v2.
- A v1 Project is upgraded only by an explicit `project migrate --to 2`
  operation. Opening a Project never migrates it.
- Migration runs in one SQLite write transaction. A failure rolls back both the
  new table and migration-history row and verifies that the original v1
  contract is still valid.
- A separate backup is required before migrating irreplaceable research data.
  The Workbench does not create or manage that backup automatically.
- Manual Evidence content uses the existing Artifact Store and
  `ArtifactKind.EVIDENCE`. Its Artifact row and provenance row commit in the
  same SQLite transaction. The bytes are never interpreted as a verified
  observation merely because they were registered.
- The 4 MiB and extension allowlist apply only to Manual Evidence registration;
  the general Artifact Store remains unbounded by default.
- Case Bundle v1 remains byte-for-byte contract compatible. It exports the
  generic Evidence Artifact and content but omits manual provenance, so that
  metadata does not survive a Bundle v1 round trip.

## Consequences

The platform can display analyst-supplied origin metadata without changing the
existing Artifact identity or Bundle v1 manifest. Both database versions need
version-aware validation. Callers must surface a migration-required error for
v1 manual registration, and users must treat Bundle v1 provenance loss as an
explicit limitation.
