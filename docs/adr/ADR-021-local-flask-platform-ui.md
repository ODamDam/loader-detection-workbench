# ADR-021: Loopback-only Flask platform UI

## Status

Approved by the user on 2026-10-14 for local implementation and verification.

## Decision

- The basic platform UI uses server-rendered Flask templates, Flask-WTF CSRF
  protection, local CSS, and Waitress. It has no CDN or frontend build step.
- `workbench ui serve [ROOT] --port PORT` selects exactly one Project before the
  server starts. Browsers cannot choose or submit a workspace path.
- Waitress binds only to IPv4 loopback `127.0.0.1`. Debug mode, the Flask
  development server, the reloader, proxy trust, and a configurable bind host
  are not exposed.
- Routes call the existing Project, Case, Artifact, Manual Evidence, and
  Timeline Application Services. They do not query SQLite, invoke the CLI as a
  subprocess, or duplicate normalization and storage policy.
- Manual upload bytes are staged under an OS temporary directory with a
  generated name. The browser filename is metadata only. The existing Manual
  Evidence Service remains authoritative for the 4 MiB limit, extension allowlist,
  provenance validation, transaction, deduplication, and failure compensation.
- The browser boundary additionally enforces a bounded multipart request,
  CSRF, exact Origin, trusted Host, Jinja escaping, security headers, and
  cleanup of the temporary directory on every outcome.
- Pages expose display IDs and safe metadata only. Artifact and Project internal
  IDs, content paths, workspace paths, evidence bytes, commands, executable
  paths, target paths, and Process GUIDs are not rendered.
- SQLite v1 remains readable. Manual Evidence registration remains v2-only and
  reports that an explicit migration is required. The UI never migrates a Project.
- `ArtifactKind.OTHER` is displayed only as an Other Artifact because the current
  schema does not establish Collection provenance.

## Consequences

The UI is a local single-user presentation layer over the existing core. It is
not authenticated and must remain loopback-only. Repeated upload preserves the
existing Manual Evidence behavior: distinct Artifact/provenance rows may share
canonical content. There is no evidence download, raw preview, Markdown report
preview, VM action, AI action, or new database schema in this decision.
