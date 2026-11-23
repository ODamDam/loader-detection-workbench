# Local Web UI demo runbook

This runbook prepares and presents a sanitized 2–3 minute demonstration. It uses
only a header-only synthetic PE fixture and the repository's public Sysmon XML.
It does not execute the fixture, start a VM, or contact an external service.

## Prepare once before recording

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Prepare-UiDemo.ps1
```

The default output is `.demo\ui-readiness`. The script refuses to overwrite an
existing output. To rebuild, preserve or remove the old demo manually and choose
a fresh destination:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Prepare-UiDemo.ps1 `
  -OutputRoot .demo\ui-readiness-2
```

The prepared Project contains:

- `CASE-0001`: sample Artifact, Static PE Result, two Sysmon Artifacts, metadata,
  two normalized Observations, and a pre-generated Markdown report;
- `CASE-0002`: an empty Case for the empty-state demonstration;
- `inputs\analyst-note.txt`: sanitized file to upload during the recording.

Manual Evidence is deliberately not pre-registered so the upload can be shown
live. The Project and inputs are ignored by Git and separate from user Projects.

## Start the local UI

```powershell
uv run workbench ui serve ".demo\ui-readiness\project" --port 8080
```

Open `http://127.0.0.1:8080/cases`. Keep the terminal open. Stop the server with
Ctrl+C after recording.

The pre-generated full Markdown report is located at:

```text
.demo\ui-readiness\project\reports\CASE-0001.md
```

## 2–3 minute click path

| Time | Click path | Show |
|---|---|---|
| 0:00–0:20 | Cases → `CASE-0001` | Case management and Artifact/Evidence/Observation counts |
| 0:20–0:50 | `ART-000002` | Static PE Result, source Artifact link, SHA-256, x64, PE32+, `.text` |
| 0:50–1:15 | Back → `ART-000003`, then `ART-000004` | Sysmon Event ID 1/11, EventRecordID 42/43, source Artifact relationship |
| 1:15–1:35 | Case details → **View Sysmon timeline** | Both observations ordered by timestamp |
| 1:35–1:55 | **Preview report** | Safe report overview and the existing full Markdown generation command |
| 1:55–2:30 | Case details → **Add manual evidence** | Upload `inputs\analyst-note.txt`; origin `demo analyst`; type `analyst_note`; description `sanitized demo evidence` |
| 2:30–2:50 | Redirected Case details → new Evidence Artifact | Updated counts, success notice, SHA-256, filename, provenance, and description |

Optional: open `CASE-0002` briefly to show the explicit empty state. Do not expose
the browser through port forwarding or change the loopback-only binding.
