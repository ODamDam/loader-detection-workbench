# Minimal static PE analysis contract

## Scope and command

```text
workbench case static analyze CASE-NNNN ART-NNNNNN
```

The command reads an Artifact already attached to the selected Case through the
verified Artifact Store. It never executes the content. The source read is capped
at 64 MiB. A `static` JSON Artifact is registered in the same Case and contains
the source display ID, SHA-256, size, analyzer name/version/time, parse status,
basic PE/COFF fields, architecture, and section metadata.

No database schema is added. The source/result relationship is an immutable field
inside the result Artifact. Existing content-addressed storage and row identity
rules apply, so equal result bytes may share stored content while retaining
distinct Artifact records.

## Result states

- `ok`: the PE signature, COFF header, supported PE32/PE32+ optional-header magic,
  and bounded section table were parsed.
- `not_pe`: the source does not begin with the DOS `MZ` signature.
- `malformed_pe`: the source begins with `MZ` but required headers, offsets, or
  section raw-data bounds are invalid.

Unknown machine values are retained as a hexadecimal header value and reported
with architecture `unknown`.

## Result schema v2 (2026-11-11, W3)

New results use `schema_version: 2` and analyzer `workbench-pe` version `2`.
Version 1 results remain readable; their v2 fields keep empty defaults.

- `file_entropy` and per-section `entropy`, `raw_pointer`, `executable`,
  `writable`.
- `pe` extras from `pefile` (bytes only): `imports` (DLL → names or
  `ordinal#N`; capped at 256 DLLs / 4096 functions), `imphash`, `exports`
  (count, first 256 names), `compile_timestamp`, `entry_point`, `image_base`,
  `subsystem`, `is_dll`, `overlay_size`, and `signature`
  (`absent` or `present_unverified`; Authenticode is not verified).
  A pefile failure is recorded as `parser_warning` and does not fail the result.
- `strings`: ASCII and UTF-16LE strings of at least 6 characters (first 2000
  unique values, each truncated to 200 characters) and `indicators`
  (url, ipv4, registry, windows_path, executable_name, script_keyword).
  Strings and indicators are also extracted for non-PE sources.
- `flags`: deterministic analyst leads such as `high_entropy_section`,
  `writable_executable_section`, `packer_section_name`, `few_imports`,
  `notable_imports`, `overlay`, `no_authenticode_signature`. A flag is a lead
  for review, never a maliciousness verdict.

The UI shows imports, flags and indicators but not `windows_path` values or
the raw string list, consistent with the platform UI path-disclosure rule; the
CLI summary and the JSON result Artifact keep the full bounded data.

## Safety and presentation

Only verified source bytes are inspected. The result records no host absolute
path and does not include source bytes. The local UI displays the result and a
link to its source Artifact, while continuing to omit stored paths and binary
download or preview routes.
