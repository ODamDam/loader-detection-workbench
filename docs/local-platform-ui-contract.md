# Local Flask platform UI contract

## Scope

The UI opens one Project selected by the local CLI operator. It lists Cases,
shows attached Artifacts and available Manual Evidence provenance, registers a
manual file in an Open v2 Case, and shows the safe subset of Event ID 1/11
Timeline fields. It is a presentation adapter over existing Application Services.

It does not provide Project selection in the browser, evidence download or raw
preview, Markdown report preview, Collection import, VM controls, graph or rule
editing, AI features, authentication, or remote access.

## Start command

```text
workbench ui serve [ROOT] [--port PORT]
```

`ROOT` defaults to the current directory and must already be a valid v1 or v2
Project. `PORT` defaults to 8080 and must be 1 through 65535. The Project is
validated before Waitress binds to `127.0.0.1`. There is no `--host` option.

## HTTP surface

| Method | Path | Contract |
|---|---|---|
| GET | `/` | Redirect to `/cases` |
| GET | `/health` | Return only `{"status":"ready"}` |
| GET | `/cases` | List Cases or show an empty state |
| GET | `/cases/<case-id>` | Case and path-safe Artifact/provenance detail |
| GET | `/cases/<case-id>/evidence/new` | Registration form or state notice |
| POST | `/cases/<case-id>/evidence` | Register through `ManualEvidenceService`, then 303 redirect |
| GET | `/cases/<case-id>/timeline` | Event ID 1/11 safe Timeline projection |

The Artifact view includes display ID, kind, neutral classification, SHA-256,
size, and creation time. Provenance, when present, adds original filename,
analyst-supplied source, description, and evidence type. An Evidence Artifact
without provenance remains valid. An Other Artifact is never inferred to be
Collection metadata.

The Timeline includes timestamp, Event ID and name, PID, source Artifact display
ID, and EventRecordID. Image, command line, target filename, ProcessGuid, raw XML,
and stored content paths are deliberately omitted.

## Upload and compatibility

- Only Open Cases can accept a file.
- The UI uses a generated temporary directory and generated staging filename.
  The untrusted browser filename is passed only as `original_filename` metadata.
- The HTTP request cap is 5 MiB. The Service's exact Manual Evidence limit remains
  4 MiB, with its existing allowlist and metadata limits.
- Temporary data is removed after success and all handled or unhandled failures.
- Repeated equal bytes create the same distinct rows and shared content as the
  existing Service and CLI contract.
- v1 Case, Artifact, and Timeline reads work. Registration reports
  `PROJECT_MIGRATION_REQUIRED`; no automatic migration occurs.

## Browser security

The server accepts only the configured loopback Host and exact Origin for state
changing requests. All POST requests require a CSRF token. Jinja autoescaping is
kept enabled. Responses deny framing, MIME sniffing, referrer forwarding,
cross-origin resources, objects, external form actions, and caching. Debug mode,
the reloader, proxy headers, download routes, and raw evidence rendering are not
enabled.

The UI has no authentication. Loopback binding is therefore a security boundary,
not a convenience default. Operators must not expose it with port forwarding,
reverse proxies, or alternate bind configuration.

## Error behavior

Missing Cases return 404, invalid input returns 400, Closed Case and migration
requirements return 409, oversized HTTP requests return 413, and invalid stored
Timeline data returns 422. Internal errors return a generic 500 response. Pages
show stable safe codes and never return filesystem or SQLite exception detail.
