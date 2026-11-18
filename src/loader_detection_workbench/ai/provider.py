"""Replaceable analysis provider boundary and the built-in offline provider.

``OfflineTemplateProvider`` is not a language model. It applies a few fixed
templates to the digest so that the whole pipeline (digest, validation,
storage, review, report) works without any API key or network (ADR-004).
Its output goes through exactly the same validation and review as any other
provider's output.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from loader_detection_workbench.ai.domain import (
    ProviderOutput,
    ProviderSuggestion,
    SuggestionKind,
)

SCRIPT_HOSTS = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
    }
)


class AnalysisProvider(Protocol):
    """Turns one evidence digest into suggestions. Must not keep state."""

    name: str
    model: str
    # True when ``analyze`` would send the digest off this machine.
    requires_network: bool

    def analyze(self, digest: Mapping[str, Any]) -> ProviderOutput: ...


def _plural(count: int, noun: str, plural: str | None = None) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {plural or noun + 's'}"


class OfflineTemplateProvider:
    name = "offline-template"
    model = "template-v1"
    requires_network = False

    def analyze(self, digest: Mapping[str, Any]) -> ProviderOutput:
        stage = digest.get("stage")
        if stage == "collection":
            return ProviderOutput(tuple(self._collection(digest)[:16]))
        if stage == "synthesis":
            return ProviderOutput(tuple(self._synthesis(digest)[:16]))
        return self._legacy(digest)

    # -- ADR-031 stages -------------------------------------------------------

    @staticmethod
    def _collection(digest: Mapping[str, Any]) -> list[ProviderSuggestion]:
        """Hypothesis candidates, evidence links and next steps from the digest."""
        static = list(digest.get("static", []))
        sysmon = dict(digest.get("sysmon", {}))
        processes = list(sysmon.get("processes", []))
        artifacts = [dict(item) for item in digest.get("artifacts", [])]
        samples = [str(a["id"]) for a in artifacts if a.get("kind") == "sample"]
        sysmon_ids = [str(a["id"]) for a in artifacts if a.get("kind") == "sysmon"]
        out: list[ProviderSuggestion] = []

        for process in processes:
            name = str(process.get("image_name", "")).lower()
            parent = process.get("parent_index")
            source = process.get("source_artifact")
            activity = dict(process.get("activity", {}))
            if not source:
                continue
            if name in SCRIPT_HOSTS and parent is not None:
                parent_name = processes[parent].get("image_name")
                out.append(
                    ProviderSuggestion(
                        SuggestionKind.HYPOTHESIS_CANDIDATE,
                        f"{parent_name} started {process.get('image_name')}; a loader "
                        "may hand later stages to a script host or system utility.",
                        title=f"{parent_name} spawns {process.get('image_name')}",
                        evidence_artifact_ids=(str(source),),
                        expected_benign="Installers and administrative scripts also "
                        "start these utilities.",
                    )
                )
            if int(process.get("files_written", 0) or 0) and ".exe" in process.get(
                "file_extensions", []
            ):
                out.append(
                    ProviderSuggestion(
                        SuggestionKind.HYPOTHESIS_CANDIDATE,
                        f"{process.get('image_name')} wrote an executable file; the "
                        "sample may stage or copy itself to another location.",
                        title=f"{process.get('image_name')} drops an executable",
                        evidence_artifact_ids=(str(source),),
                        expected_benign="Installers and updaters write executables.",
                    )
                )
            if activity.get("registry"):
                out.append(
                    ProviderSuggestion(
                        SuggestionKind.HYPOTHESIS_CANDIDATE,
                        f"{process.get('image_name')} changed registry keys or "
                        "values; persistence may be involved.",
                        title=f"{process.get('image_name')} registry modification",
                        evidence_artifact_ids=(str(source),),
                        expected_benign="First-run configuration writes registry "
                        "values as well.",
                    )
                )
        for result in static:
            leads = [str(lead) for lead in result.get("leads", [])]
            notable = [lead for lead in leads if lead.startswith("notable_imports")]
            if notable:
                out.append(
                    ProviderSuggestion(
                        SuggestionKind.HYPOTHESIS_CANDIDATE,
                        "The import table names APIs used for dynamic loading or "
                        f"process creation ({notable[0]}).",
                        title="Imports for loading or starting later stages",
                        evidence_artifact_ids=(str(result["artifact"]),),
                        expected_benign="Runtimes and installers import the same APIs.",
                    )
                )
            if sysmon_ids:
                out.append(
                    ProviderSuggestion(
                        SuggestionKind.EVIDENCE_LINK,
                        f"Static result {result['artifact']} and the Sysmon events "
                        f"in {sysmon_ids[0]} describe the same sample; behavior seen "
                        "at run time can be checked against the imported APIs.",
                        evidence_artifact_ids=(str(result["artifact"]), sysmon_ids[0]),
                    )
                )

        anchor = samples[:1] or [str(a["id"]) for a in artifacts[:1]]
        if anchor and not static:
            out.append(
                ProviderSuggestion(
                    SuggestionKind.NEXT_STEP,
                    f"No static result exists for {anchor[0]}; a static PE analysis "
                    "would show imports, sections and packing leads.",
                    evidence_artifact_ids=(anchor[0],),
                )
            )
        if anchor and not sysmon_ids:
            out.append(
                ProviderSuggestion(
                    SuggestionKind.NEXT_STEP,
                    f"No Sysmon telemetry is attached for {anchor[0]}; an approved "
                    "VM execution would show its run-time behavior.",
                    evidence_artifact_ids=(anchor[0],),
                )
            )
        if sysmon_ids and any(not p.get("captured") for p in processes):
            out.append(
                ProviderSuggestion(
                    SuggestionKind.NEXT_STEP,
                    "Some processes appear only as a parent or actor; a longer "
                    "run or a wider capture window would complete the tree.",
                    evidence_artifact_ids=(sysmon_ids[0],),
                )
            )
        if anchor and not dict(digest.get("recorded", {})).get("validation_runs"):
            out.append(
                ProviderSuggestion(
                    SuggestionKind.NEXT_STEP,
                    "No validation run is recorded; a rule tested against benign "
                    "comparison data would show whether a candidate is specific.",
                    evidence_artifact_ids=(anchor[0],),
                )
            )
        return out

    @staticmethod
    def _synthesis(digest: Mapping[str, Any]) -> list[ProviderSuggestion]:
        """Key hypotheses with their support, and an ordered mechanism outline."""
        findings = [dict(item) for item in digest.get("findings", [])]
        by_id = {str(item["id"]): item for item in findings}
        out: list[ProviderSuggestion] = []
        for item in findings:
            if item.get("kind") != "hypothesis" or item.get("verdict") != "supported":
                continue
            support = sorted(
                {
                    str(ref)
                    for link in findings
                    if link.get("kind") == "link" and item["id"] in link["findings"]
                    for ref in link["findings"]
                    if ref != item["id"] and ref in by_id
                }
            )
            out.append(
                ProviderSuggestion(
                    SuggestionKind.KEY_HYPOTHESIS,
                    f"Confirmed hypothesis {item['id']} is supported by "
                    + (", ".join(support) if support else "no linked evidence yet")
                    + ".",
                    title=str(item.get("title") or item["id"])[:200],
                    evidence_artifact_ids=(str(item["id"]), *support),
                )
            )
        evidence = [item for item in findings if item.get("kind") == "evidence"]
        if evidence:
            # IDs only: analyst text is not echoed back into an opinion.
            cited = [str(item["id"]) for item in evidence[:16]]
            out.append(
                ProviderSuggestion(
                    SuggestionKind.MECHANISM,
                    "Outline in the order the confirmed evidence was recorded "
                    "(template, not an interpretation): " + " -> ".join(cited) + ".",
                    evidence_artifact_ids=tuple(cited),
                )
            )
        return out

    # -- ADR-026 ----------------------------------------------------------------

    def _legacy(self, digest: Mapping[str, Any]) -> ProviderOutput:
        static = list(digest.get("static", []))
        sysmon = dict(digest.get("sysmon", {}))
        processes = list(sysmon.get("processes", []))
        suggestions: list[ProviderSuggestion] = []

        parts: list[str] = []
        for result in static:
            if result.get("is_pe"):
                parts.append(
                    f"Static result {result['artifact']} describes a "
                    f"{result.get('architecture')} PE importing "
                    f"{_plural(len(result.get('imports', [])), 'DLL')} and "
                    + _plural(int(result.get("import_function_count", 0)), "function")
                    + "; analysis leads: "
                    + (", ".join(result.get("leads", [])) or "none")
                    + "."
                )
            else:
                parts.append(
                    f"Static result {result['artifact']} is not a parsed PE "
                    f"(status {result.get('status')})."
                )
        if sysmon.get("record_total"):
            counts = ", ".join(
                f"Event ID {key}: {value}"
                for key, value in dict(sysmon.get("event_id_counts", {})).items()
            )
            parts.append(
                "Sysmon telemetry holds "
                + _plural(int(sysmon["record_total"]), "record")
                + " across "
                + _plural(int(sysmon.get("process_total", 0)), "process", "processes")
                + f" ({counts})."
            )
        if not parts:
            parts.append(
                "No static result or Sysmon telemetry is attached to this Case."
            )
        suggestions.append(ProviderSuggestion(SuggestionKind.SUMMARY, " ".join(parts)))

        for process in processes:
            name = str(process.get("image_name", "")).lower()
            parent = process.get("parent_index")
            source = process.get("source_artifact")
            if name in SCRIPT_HOSTS and parent is not None and source:
                parent_name = processes[parent].get("image_name")
                suggestions.append(
                    ProviderSuggestion(
                        SuggestionKind.HYPOTHESIS,
                        f"Process {parent_name} started the script host or system "
                        f"utility {process.get('image_name')}. Check whether the "
                        "child command line and its timing are specific to this "
                        "sample.",
                        title=f"{parent_name} spawns {process.get('image_name')}",
                        evidence_artifact_ids=(str(source),),
                        expected_benign="Administrative scripts and installers also "
                        "start these utilities; compare the parent and arguments.",
                    )
                )
            activity = dict(process.get("activity", {}))
            if source and (activity.get("dns") or activity.get("network")):
                suggestions.append(
                    ProviderSuggestion(
                        SuggestionKind.HYPOTHESIS,
                        f"Process {process.get('image_name')} produced name "
                        "resolution or network connection events. Check the "
                        "destination and how soon after start it happened.",
                        title=f"{process.get('image_name')} network activity",
                        evidence_artifact_ids=(str(source),),
                        expected_benign="Update checks and telemetry of benign "
                        "software also resolve names shortly after start.",
                    )
                )
            if source and activity.get("registry"):
                suggestions.append(
                    ProviderSuggestion(
                        SuggestionKind.HYPOTHESIS,
                        f"Process {process.get('image_name')} created or changed "
                        "registry keys or values. Check whether a persistence "
                        "location is involved.",
                        title=f"{process.get('image_name')} registry modification",
                        evidence_artifact_ids=(str(source),),
                        expected_benign="Installers and first-run configuration "
                        "write registry values as well.",
                    )
                )
        for result in static:
            leads = [str(lead) for lead in result.get("leads", [])]
            notable = [lead for lead in leads if lead.startswith("notable_imports")]
            if notable:
                suggestions.append(
                    ProviderSuggestion(
                        SuggestionKind.HYPOTHESIS,
                        "The import table contains APIs often used for dynamic "
                        f"loading or memory allocation ({notable[0]}). Check whether "
                        "they are used to load a later stage.",
                        title="Imports used for dynamic code loading",
                        evidence_artifact_ids=(str(result["artifact"]),),
                        expected_benign="Plugin hosts, runtimes and packers of "
                        "benign software import the same APIs.",
                    )
                )

        if not static:
            suggestions.append(
                ProviderSuggestion(
                    SuggestionKind.REVIEW_ITEM,
                    "No static analysis result is attached. Run "
                    "'workbench case static analyze' on the sample Artifact.",
                )
            )
        if not sysmon.get("record_total"):
            suggestions.append(
                ProviderSuggestion(
                    SuggestionKind.REVIEW_ITEM,
                    "No Sysmon telemetry is attached, so no dynamic behavior was "
                    "considered.",
                )
            )
        if any(not process.get("captured") for process in processes):
            suggestions.append(
                ProviderSuggestion(
                    SuggestionKind.REVIEW_ITEM,
                    "Some processes appear only as a parent or actor; their "
                    "creation was not captured, so the process tree is incomplete.",
                )
            )
        if not dict(digest.get("recorded", {})).get("validation_runs"):
            suggestions.append(
                ProviderSuggestion(
                    SuggestionKind.REVIEW_ITEM,
                    "No validation run is recorded for this Case yet. A hypothesis "
                    "needs a rule and a benign comparison before it is supported.",
                )
            )
        return ProviderOutput(tuple(suggestions[:16]))


def default_providers() -> dict[str, AnalysisProvider]:
    provider = OfflineTemplateProvider()
    return {provider.name: provider}
