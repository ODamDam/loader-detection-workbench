# AI-E3 Data & Graph Contract v0.1 — Professor Review Candidate

**Status:** Professor Review Candidate. This document does not amend the
approved AI-E0 research contracts or create a Workbench public contract.

## 1. Decision classes

This document uses the following labels so that inherited research decisions
are not confused with new implementation proposals.

- **AI-E0 Approved Contract** — a decision already approved in the AI-E0
  research track.
- **AI-E3 Proposed Contract** — a concrete contract proposed for the first
  graph prototype. It is not approved until professor review is complete.
- **Professor Decision Required** — an open research decision. Implementation
  that depends on it must remain deferred.

The source documents are:

- Behavior Graph Ontology v0.1,
  an approved AI-E0 closing artifact.
- Minimum Event Schema v0.1,
  an AI-E0 approved research draft. It is not yet the official Workbench M1
  Evidence/Event contract.

The repository's current immutable `ProcessCreateEvent` and
`FileCreateEvent` types and `CaseTimelineQuery` behavior are implementation
constraints, not retroactive changes to either AI-E0 document.

## 2. Inherited research contract

### 2.1 Graph and ontology boundary — AI-E0 Approved Contract

The behavior graph is a directed, typed, temporal heterogeneous graph. The
approved Core node vocabulary is:

- `PROCESS`
- `FILE`
- `MODULE`
- `REGISTRY`
- `NETWORK_ENDPOINT`
- `DOMAIN`

The approved Core edge vocabulary is:

- `SPAWN`
- `CREATE`
- `MODIFY`
- `DELETE`
- `LOAD`
- `CONNECT`
- `QUERY`
- `TERMINATE`

The first AI-E3 prototype does not redefine this vocabulary. Supporting only a
subset does not remove the other approved terms.

The approved layer boundary remains:

```text
Raw Telemetry
→ Normalized Event
→ Behavior Graph
→ Capability / Hypothesis
→ ATT&CK Candidate
→ ML/GNN Prediction
```

Observed facts, analytical hypotheses, ATT&CK mappings, verdicts and model
predictions must not be combined into one graph layer. `INJECT` is not a raw
graph edge.

### 2.2 Event and provenance principles — AI-E0 Approved Contract

- A normalized event represents an observation, not a maliciousness verdict.
- Relations should use the `Actor → Action → Target` form when the evidence
  supports all three parts.
- PID alone is not a process identity because Windows can reuse PIDs.
- `ProcessGuid` is the preferred Case-scoped process correlation key for
  Sysmon-derived evidence.
- Every normalized event must remain traceable to its original evidence.
- The approved collection-quality vocabulary is `complete`, `partial` and
  `uncertain`.
- Missing telemetry must not silently become an observed absence or a negative
  label.

## 3. Initial supported subset — AI-E3 Proposed Contract

The prototype consumes existing Workbench normalized events. It does not parse
raw XML and does not broaden the normalizer.

| Normalized input | Node types | Edge | Result |
| --- | --- | --- | --- |
| Sysmon Event ID 1 `ProcessCreateEvent` | `PROCESS` | none | Establish or corroborate a process observation. |
| Sysmon Event ID 11 `FileCreateEvent` | `PROCESS`, `FILE` | `CREATE` | Preserve one observed process-to-file relation. |

The current Event ID 1 model has no validated parent-process identity.
Therefore it cannot substantiate a `SPAWN` edge. The graph builder must not
reparse raw XML to obtain fields outside the approved normalized-event input.

No File, Module, Registry, Network Endpoint, Domain or process relationship may
be fabricated to fill a vocabulary slot. Unsupported normalized event types
must fail closed rather than disappear from an apparently successful graph.

## 4. Identity contract — AI-E3 Proposed Contract

All identities are scoped to one Workbench Case. The graph must not correlate
entities across Cases merely because their source strings match.

### 4.1 PROCESS identity

- Logical key: `(case identity, canonical UUID value of ProcessGuid)`.
- The textual GUID representation may be converted to the standard lowercase,
  hyphenated UUID representation for deterministic serialization.
- PID is metadata and a consistency check; it is never the node identity.
- If observations with the same ProcessGuid contain different PIDs, graph
  construction fails with `CONFLICTING_PROCESS_PID`.
- Image is observed metadata and is not part of PROCESS identity.

### 4.2 FILE identity

- Logical key: `(case identity, exact TargetFilename string)`.
- The observed string is preserved exactly, including case, separators and
  spelling.
- No Windows path normalization, case folding, separator conversion, alias
  resolution, environment expansion or file-system lookup is performed.

Consequently, two spellings that Windows might resolve to the same file can
produce two FILE nodes, and an identical string can refer to different file
states over time. These are explicit v0.1 limitations, not facts the graph may
resolve without evidence.

### 4.3 EvidenceReference identity

Each observed relation carries an immutable reference containing:

| Field | Source | Requirement |
| --- | --- | --- |
| `artifact_id` | `source_artifact_id` | Required Workbench Artifact identity. |
| `event_record_id` | `source_record_id` | Required non-empty decimal string. |

The pair `(artifact_id, event_record_id)` is the EvidenceReference identity
within a graph. If the same pair appears more than once, construction fails
with `DUPLICATE_EVIDENCE_REFERENCE`, even when the repeated event is otherwise
identical. Duplicate evidence is not silently deduplicated.

Different EvidenceReferences may describe the same PROCESS, FILE or relation.
Those observations remain separate edges.

## 5. Proposed immutable graph records

The following logical records describe the candidate contract. Python class
names and module placement remain implementation details until implementation
approval.

### 5.1 GraphNode

| Field | Type | Meaning |
| --- | --- | --- |
| `node_id` | string | Deterministic Case-scoped serialization identity. |
| `node_type` | enum | `PROCESS` or `FILE` in the initial subset. |
| `identity` | typed value | Canonical ProcessGuid or exact TargetFilename. |
| `attributes` | typed object | Observed display metadata only. |

### 5.2 NodeObservation

| Field | Type | Meaning |
| --- | --- | --- |
| `node_id` | string | Observed PROCESS node identity. |
| `observed_at_utc` | UTC timestamp | Event ID 1 observation time. |
| `source_event_id` | integer | `1` in the initial subset. |
| `process_id` | integer | Observed PID metadata and consistency input. |
| `image` | string | Exact observed Image metadata. |
| `evidence` | EvidenceReference | Original Artifact and EventRecordID. |
| `sequence` | integer | Deterministic position after canonical ordering. |

### 5.3 GraphEdge

| Field | Type | Meaning |
| --- | --- | --- |
| `edge_type` | enum | `CREATE` in the initial subset. |
| `source_node_id` | string | PROCESS node identity. |
| `target_node_id` | string | FILE node identity. |
| `observed_at_utc` | UTC timestamp | Event observation time. |
| `source_event_id` | integer | `11` for the initial CREATE mapping. |
| `attributes` | typed object | Exact observed actor PID and Image metadata. |
| `evidence` | EvidenceReference | Original Artifact and EventRecordID. |
| `sequence` | integer | Deterministic position after canonical ordering. |

Every Event ID 11 observation produces one edge. Repeated CREATE observations
with different EvidenceReferences are preserved even if all actor, target and
timestamp values are otherwise equal.

An Event ID 1 observation creates or corroborates a PROCESS node and produces a
NodeObservation, but does not produce a relation edge in the initial subset.
Its EvidenceReference must still be validated and reserved, so it participates
in duplicate-evidence detection. Event ID 11 preserves its observed actor PID
and Image on the CREATE edge. This lets image-quality checks retain exact input
strings without treating Image as process identity.

Duplicate-evidence validation counts normalized input events, not the number of
internal references to one accepted event while an immutable graph is being
assembled. A serialized EvidenceReference must remain internally consistent
wherever the schema refers to it.

## 6. Ordering and deterministic serialization — AI-E3 Proposed Contract

Input from `CaseTimelineQuery` follows this ascending key:

1. UTC `timestamp`
2. numeric `event_id`
3. `source_artifact_id.display_id`
4. `source_record_id` using lexicographic string comparison

The EventRecordID order deliberately remains lexicographic to preserve the
existing Case Timeline contract. For example, `"10"` sorts before `"2"`.
AI-E3 must not silently replace it with numeric ordering.

Canonical graph serialization must:

- use a fixed schema version;
- emit UTF-8 JSON with one documented whitespace and newline policy;
- sort nodes by `(node_type, node_id)`;
- sort observations and edges by the Timeline key above and assign `sequence`
  from that order;
- use fixed field ordering and deterministic representations for enums,
  timestamps and identifiers;
- omit execution time, UUID generation, absolute local paths and other
  nondeterministic runtime data.

Repeated serialization of the same validated input and Case identity must be
byte-identical.

## 7. Quality contract

### 7.1 Collection Coverage

**Collection Coverage** describes how much of the behavior that occurred
during execution was captured and made available as evidence. Its status uses
the approved `complete`, `partial` or `uncertain` vocabulary.

The current Case Adapter cannot establish the configured telemetry channels,
collection interval, loss, filters or all behavior that occurred. It must
therefore set Collection Coverage to `uncertain` and include a limitation such
as `collection_coverage_unverified` with a factual explanation.

Graph conversion success does not promote Collection Coverage to `complete`.
Absence of an event in an uncertain collection is not evidence that the
behavior did not occur.

### 7.2 Graph Completeness

**Graph Completeness** describes how completely the provided normalized events
were converted according to this graph contract. It does not describe the
underlying execution or collection.

Graph Completeness may be `complete` only relative to the supplied, validated,
supported normalized-event set: every input is accepted, every required entity
and observation is represented, and all provenance is retained. It must be
`partial` when a separately approved future mode intentionally preserves a
graph while declaring skipped input. The initial implementation has no such
mode and fails closed instead. It is `uncertain` when the adapter cannot prove
the input boundary or conversion accounting.

These two quality axes are independent. A graph can have complete conversion
of its supplied events while Collection Coverage remains uncertain.

### 7.3 `process_image_inconsistent`

`process_image_inconsistent` means only that different exact Image strings
were observed for the same ProcessGuid. It is quality information about input
consistency.

It does not assert or imply:

- process tampering or another malicious behavior;
- that the strings identify the same file;
- that the strings identify different files;
- a malware verdict, capability, ATT&CK mapping or model label.

Windows paths are commonly case-insensitive while preserving case, and
different textual forms can arise without changing process identity. The v0.1
contract does not normalize or resolve those forms. The final handling policy
for this quality fact remains a Professor Decision Required item.

## 8. Fail-closed conditions — AI-E3 Proposed Contract

Graph construction must return no successful graph when any of the following
occurs:

- an input is not one of the approved normalized event types;
- a required value or UTC timestamp is missing or invalid;
- Artifact or EventRecordID provenance is missing or corrupt;
- an EvidenceReference is repeated;
- one ProcessGuid has conflicting PIDs;
- an edge refers to a node that cannot be established;
- conversion accounting cannot prove that every input was handled;
- deterministic ordering or serialization cannot be completed.

The Case Timeline already propagates normalization failures instead of
returning a partial timeline. AI-E3 must preserve that behavior and must not
convert a failure into a partial success. Errors and limitations must avoid raw
XML, command lines, private paths or other sensitive telemetry.

## 9. Candidate serialized envelope — AI-E3 Proposed Contract

The deterministic JSON envelope is proposed to contain:

```text
schema_version
case_reference
supported_scope
quality
  collection_coverage
  graph_completeness
limitations
nodes
node_observations
edges
```

`case_reference` must use an existing stable Case identity. `node_observations`
preserves Event ID 1 evidence without inventing a relation. The precise JSON
field types, identifier encoding and limitation object schema must be frozen in
the implementation review before code is written.

## 10. Professor Decision Required

1. **Image inconsistency handling:** decide whether
   `process_image_inconsistent` permits a successful graph with preserved exact
   observations and an explicit limitation, or causes fail-closed graph
   construction. Its non-interpretive meaning in section 7.3 remains fixed in
   either case.
2. **Future SPAWN support:** approve an input contract that carries validated
   parent and child process identity before enabling `SPAWN`. Current Event ID
   1/11 models are insufficient.
3. **Static and dynamic evidence combination:** define identity, provenance,
   conflict and temporal rules before static attributes are attached to this
   dynamic behavior graph.
4. **GNN evaluation scope:** define the task, labels, partitions, baselines and
   evaluation protocol separately from graph construction. This graph contract
   does not approve GNN training or inference.

## 11. Explicit exclusions

- Raw XML reparsing or new Sysmon Event IDs
- Parent-process inference and SPAWN fabrication
- Windows path canonicalization or file-system resolution
- Static PE extraction or static/dynamic evidence fusion
- Maliciousness labels, capability claims or ATT&CK mapping
- GNN training, model inference or AI Provider integration
- Workbench DB/schema, parser or public CLI changes
- Changes to AI-E2 features, split, model or results
