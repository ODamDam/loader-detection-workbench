# Existing Case Sysmon Collection Ingestion Contract

## Public API

Python:

```python
result = CollectionIngestionService(project_root).import_collection(
    "CASE-0001", collection_directory
)
```

CLI, run from the Project workspace:

```text
workbench case collection import CASE-0001 COLLECTION_DIRECTORY
```

The selected Case must exist and be Open. The result reports only status,
Case display ID, three Artifact display IDs, and created/reused counts. It does
not print source paths, collection run IDs, process GUIDs, commands, or XML.

Statuses are:

- `imported`: three new logical Artifact rows were created.
- `imported-with-reuse`: at least one matching row was reused and at least one
  missing row was created.
- `already-present`: all three roles reused existing rows; no counter or
  Timeline change occurred.

## Input contract

The directory must not traverse a symlink or Windows reparse point and must
contain exactly these three non-empty regular files, each no larger than 4 MiB:

- `process-create.xml`
- `file-create.xml`
- `collection-metadata.json`

Each XML file is additionally limited to 1 MiB by the existing Sysmon parser.
The JSON document must be UTF-8, reject duplicate property names, and have
exactly these top-level properties:

```text
collector, version, run_id, collection_started_at,
collection_completed_at, events
```

`collector` is `sysmon-demo`, `version` is integer `1`, `run_id` is 32
lowercase hexadecimal characters, and timestamps use exact
`YYYY-MM-DDTHH:MM:SSZ` form with completion not before start. `events` contains
exactly two ordered objects with only `event_id`, `record_id`, `file`, and
`sha256`: Event ID 1 / `process-create.xml`, followed by Event ID 11 /
`file-create.xml`.

SHA-256 values must match the validated XML bytes. Each XML document must be
one supported namespaced Sysmon event. Event ID and EventRecordID must match its
metadata entry. Both events must have the same non-zero ProcessGuid and positive
ProcessId, and the Event ID 1 record ID must be lower than the Event ID 11
record ID. DTD/entity input is rejected by the existing normalizer.

## Storage and retry contract

The validator returns the exact bytes that passed all checks. Ingestion publishes
only those snapshots. It never reopens the Collection source for storage.

The role mapping is fixed:

| Role | Artifact kind |
|---|---|
| Process Create XML | `sysmon` |
| File Create XML | `sysmon` |
| Collection metadata | `other` |

Reuse is scoped to the same Case, kind, and SHA-256. Canonical stored content is
verified before reuse; XML is normalized again to verify its role. A different
Case gets separate logical Artifact rows while the content-addressed Store may
deduplicate physical bytes. Metadata never creates an `artifact_provenance` row.

All missing rows and Artifact counter changes share one SQLite transaction.
After rollback, only newly published, still-unreferenced content is eligible for
compensating deletion. A cleanup failure is explicit and may require an
operator to inspect the unreferenced content with `project validate --full`.

## Stable failures

- `CASE_NOT_FOUND`, `CASE_CLOSED`
- `INVALID_SYSMON_COLLECTION_LAYOUT`
- `INVALID_SYSMON_COLLECTION_FILE`
- `INVALID_SYSMON_COLLECTION_METADATA`
- `SYSMON_COLLECTION_XML_SIZE_EXCEEDED`
- `SYSMON_COLLECTION_HASH_MISMATCH`
- `SYSMON_COLLECTION_EVENT_MISMATCH`
- `SYSMON_COLLECTION_CORRELATION_INVALID`
- `SYSMON_COLLECTION_INPUT_CHANGED`
- Existing Sysmon parser, Artifact integrity/store/persistence, and cleanup
  error codes where those lower-level contracts fail

## Compatibility and exclusions

SQLite v1 and v2 are both supported with no migration. Existing Host and Repeat
PowerShell scripts are unchanged. Existing Manual Evidence provenance, Case
Bundle v1, Timeline, and Markdown Report formats are unchanged.

This operation validates structure and integrity; it does not establish that
events are malicious or independently attest how they were collected. It does
not create an Execution Run or persistent Collection record. Collection history,
VirtualBox control, Guest execution/retrieval, UI, AI, and Bundle v2 are out of
scope.
