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

The MVP collector intentionally excludes imports, strings, entropy, signatures,
and executable behavior. Unknown machine values are retained as a hexadecimal
header value and reported with architecture `unknown`.

## Safety and presentation

Only verified source bytes are inspected. The result records no host absolute
path and does not include source bytes. The local UI displays the result and a
link to its source Artifact, while continuing to omit stored paths and binary
download or preview routes.
