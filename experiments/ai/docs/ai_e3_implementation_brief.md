# AI-E3 Implementation Brief v0.1 — Professor Review Candidate

**Status:** Professor Review Candidate. This brief describes a future
implementation. No Graph Builder, adapter or public interface is approved by
this document alone.

## 1. Decision classes and authority

The brief uses the same decision labels as the companion
[AI-E3 Data & Graph Contract v0.1](ai_e3_data_graph_contract.md):

- **AI-E0 Approved Contract** — inherited research decisions.
- **AI-E3 Proposed Contract** — candidate implementation behavior.
- **Professor Decision Required** — unresolved research decisions that block
  dependent implementation.

The approved [Behavior Graph Ontology v0.1](https://www.notion.so/3d0c4ac09ebd81339243fa256bce6a6a)
and the AI-E0 approved research draft
[Minimum Event Schema v0.1](https://www.notion.so/3d0c4ac09ebd8180af64d66f71bff6ea)
remain source research contracts. The latter is not yet a Workbench M1 public
Evidence/Event contract. This proposal neither promotes it nor changes product
core interfaces.

## 2. Objective — AI-E3 Proposed Contract

Build a deterministic, immutable, typed temporal graph from the Workbench's
existing normalized Sysmon Event ID 1 and 11 objects. Preserve source Artifact
and EventRecordID provenance, record evidence-quality limits, and never invent
an unobserved relation.

The first vertical slice supports:

- PROCESS and FILE nodes;
- CREATE edges from Event ID 11;
- provenance for Event ID 1 process observations and Event ID 11 edges;
- Case-scoped identity;
- separate Collection Coverage and Graph Completeness quality;
- versioned, byte-stable JSON serialization.

It does not create SPAWN edges because the current normalized Event ID 1 type
does not contain an approved parent-process identity.

## 3. Reconciliation with current Workbench types

### 3.1 Current normalized fields

| Workbench type | Existing fields used by AI-E3 |
| --- | --- |
| `ProcessCreateEvent` | `timestamp`, `event_id`, `process_guid`, `process_id`, `image`, `source_artifact_id`, `source_record_id` |
| `FileCreateEvent` | `timestamp`, `event_id`, `process_guid`, `process_id`, `image`, `target_filename`, `source_artifact_id`, `source_record_id` |

`command_line` and `creation_utc_time` remain available normalized evidence but
are not required graph identity fields. The first serialization must not expose
command lines merely for diagnostics. Any future graph attribute use requires a
separate privacy and research review.

Both existing event types are immutable, validate their expected Event ID,
validate ProcessGuid and require UTC timestamps. Their provenance is an
Artifact identity plus a decimal-string EventRecordID.

### 3.2 Current Timeline behavior

`CaseTimelineQuery` reads the Case's Sysmon Artifacts and deliberately
propagates any normalization failure rather than returning a partial Timeline.
It orders normalized observations by:

```text
(timestamp UTC, event_id, artifact display ID, EventRecordID string)
```

The proposed adapter consumes that read-only result. It does not query private
telemetry locations, mutate a Case, alter an Artifact or call the raw XML
normalizer directly.

## 4. Proposed component boundaries

### 4.1 Immutable graph domain

Define immutable values for:

- node type and edge type enums using the approved vocabulary;
- PROCESS and FILE identity;
- EvidenceReference;
- `GraphNode`, `NodeObservation` and `GraphEdge` records;
- Collection Coverage and Graph Completeness status;
- limitation code and non-sensitive description;
- graph envelope and schema version.

The initial constructors accept only fields supported by the companion data
contract. They reject empty identity, non-UTC time, malformed provenance and
unsupported types.

### 4.2 Graph Builder

The pure builder receives a Case identity, an explicit collection-quality
input and an iterable of already normalized events. It performs the following
steps:

1. Validate the complete input boundary before emitting a result.
2. Sort observations by the existing Timeline contract.
3. Reserve each EvidenceReference and reject any duplicate.
4. Establish PROCESS nodes by canonical ProcessGuid while checking PID
   consistency.
5. Record Event ID 1 as a provenance-bearing `NodeObservation` without an edge;
   retain its exact PID and Image metadata.
6. Establish FILE nodes by exact TargetFilename for Event ID 11.
7. Add one CREATE edge per Event ID 11, retaining its exact actor PID and Image
   metadata; do not deduplicate repeated relations.
8. Account for every input event and calculate Graph Completeness.
9. Attach Collection Coverage without promoting it based on conversion
   success.
10. Return an immutable graph or one fail-closed error.

The builder does not read files, databases or XML and does not make ML or
maliciousness decisions.

### 4.3 Read-only Case Adapter

The adapter invokes the existing `CaseTimelineQuery` for one explicit Case and
passes the returned immutable observations to the builder.

Because the current Case and Timeline models do not prove telemetry coverage,
the adapter supplies:

```text
Collection Coverage: uncertain
Limitation: collection_coverage_unverified
```

The limitation explains that collection configuration, filters, loss and the
full execution behavior are not established. A Graph Completeness value of
`complete` means only that every supplied supported normalized event was
converted. It must not change Collection Coverage.

No product DB/schema, public CLI, parser or Artifact interface change is part
of this adapter proposal.

### 4.4 Deterministic serializer

The serializer accepts only a validated graph envelope. It applies the
versioned JSON schema, canonical list and field order, UTC timestamp format,
UTF-8 encoding and fixed final-newline policy defined during implementation
review.

It must not include generation time, random identifiers, absolute paths or
environment-dependent values. Two serializations of the same graph must be
byte-identical.

## 5. Exception and partial-failure behavior

### 5.1 Fail-closed errors — AI-E3 Proposed Contract

The first implementation stops without returning a successful graph for:

- invalid or unsupported normalized input;
- missing, corrupt or duplicate EvidenceReference;
- conflicting PID for one ProcessGuid;
- missing actor or target identity;
- non-UTC or invalid time;
- unaccounted input;
- serialization failure.

The adapter also propagates current Timeline normalization failures. It must not
replace a failed Case read with an empty or partial graph.

### 5.2 Diagnostic boundary

Errors identify the stage and a stable error code. Diagnostics must not contain
raw XML, command lines, private TargetFilename values, ProcessGuid values,
absolute host paths or full serialized graph data. Existing source evidence and
partial runtime artifacts are read only and are not deleted or overwritten.

### 5.3 Image inconsistency — Professor Decision Required

The shared fact name is `process_image_inconsistent`: different exact Image
strings were observed for one ProcessGuid. It is only input-quality
information. It conveys no process-tampering, maliciousness, file-equivalence
or file-difference conclusion.

The recommended candidate behavior is to retain the exact evidence-associated
Image observations, keep one ProcessGuid-based node, mark the limitation and
continue. The alternative is to fail closed. Implementation of this branch is
deferred until the professor selects a policy. Neither option may normalize
the strings or silently overwrite one with another.

## 6. Proposed validation matrix

All tests use synthetic normalized events or the repository's existing
harmless Sysmon fixtures. No VM, malware, private telemetry, network service or
external dataset is required.

| Test | Required assertion |
| --- | --- |
| Event ID 1 construction | One PROCESS node observation with provenance; no SPAWN edge. |
| Event ID 11 construction | PROCESS and exact-string FILE nodes plus one CREATE edge. |
| ProcessGuid identity | Same GUID and PID correlate; PID alone never correlates. |
| PID reuse safety | Different ProcessGuid values with the same PID remain distinct. |
| Conflicting PID | Same ProcessGuid with different PID fails closed. |
| Repeated file creation | Different EvidenceReferences produce separate CREATE edges. |
| Duplicate evidence | Repeated ArtifactId/EventRecordID pair fails, even for identical input. |
| Unmatched File Create | Event ID 11 may establish its PROCESS actor from its own validated fields; no process-start or SPAWN observation is fabricated. |
| Missing parent evidence | No SPAWN edge and an explicit supported-scope limitation. |
| File identity | Exact TargetFilename comparison; no case or path normalization. |
| Image variation | Assert the professor-approved behavior and the non-interpretive limitation semantics. |
| Provenance failure | Missing or corrupt Artifact/EventRecordID fails closed. |
| Unsupported input | No partial successful graph. |
| Timeline ordering | UTC, Event ID, Artifact display ID, then lexicographic EventRecordID. |
| Quality axes | Collection Coverage stays uncertain while a fully converted input may have complete Graph Completeness. |
| Stable output | Repeated serialization is byte-identical. |
| Sensitive diagnostics | Errors omit XML, command lines, identities and private paths. |

Regression validation for a later implementation includes existing Workbench
pytest, Ruff, `mypy src`, AI-E2 tests and its frozen result checks. AI-E2 data,
split, features, model settings and recorded metrics remain unchanged.

## 7. Acceptance criteria for a later implementation

A future implementation is complete only when:

- the professor-approved decisions are reflected in the data contract;
- every supported event is represented with valid provenance;
- duplicate or conflicting evidence fails closed;
- the adapter leaves Collection Coverage uncertain when coverage is unknown;
- Graph Completeness accounts for every supplied event independently of
  Collection Coverage;
- no SPAWN or other unsupported relation is generated;
- repeated serialization is byte-identical;
- the proposed validation matrix and existing regressions pass;
- final diff and security review show no raw evidence, private paths, secrets,
  runtime graphs or unrelated product changes.

## 8. Professor Decision Required

1. **Image inconsistency handling:** limitation with continued conversion, or a
   fail-closed error. The fact remains non-interpretive in both cases.
2. **Future SPAWN support:** required normalized parent-process fields,
   identity validation and missing-parent behavior.
3. **Static and dynamic evidence combination:** entity linking, provenance,
   conflict resolution and temporal semantics.
4. **GNN evaluation scope:** task definition, labels, dataset partitions,
   baselines, leakage controls and evaluation protocol.

No implementation depending on these decisions should precede professor and
user approval.

## 9. Excluded implementation scope

- Graph Builder code in this documentation checkpoint
- New Sysmon Event IDs or raw XML reparsing
- Workbench CLI, parser, DB/schema or dependency changes
- VM lifecycle work, guest execution, malware execution or network changes
- Static PE processing or static/dynamic evidence fusion
- GNN libraries, training, inference or result claims
- ATT&CK mapping, rule adoption or maliciousness labels
- AI-E2 model, feature, split or result changes
- Commit or push without separate approval
