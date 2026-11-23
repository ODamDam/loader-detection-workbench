"""Server-side layout of small layered graphs rendered as inline SVG.

No script or third-party library is involved: nodes are placed in fixed-width
columns and edges are cubic curves between column sides. Templates draw the
result with SVG presentation attributes and CSS classes only, which satisfies
the UI Content-Security-Policy (no inline style, no script).
"""

from __future__ import annotations

from dataclasses import dataclass

from loader_detection_workbench.report.analysis import CaseAnalysis
from loader_detection_workbench.sysmon.relations import ProcessRelations

NODE_WIDTH = 190
NODE_HEIGHT = 44
COLUMN_GAP = 70
ROW_GAP = 14
HEADER_HEIGHT = 34
MARGIN = 10
MAX_LABEL = 24


@dataclass(frozen=True, slots=True)
class NodeSpec:
    key: str
    label: str
    sublabel: str
    kind: str
    href: str | None = None
    title: str | None = None


@dataclass(frozen=True, slots=True)
class Node:
    label: str
    sublabel: str
    kind: str
    href: str | None
    title: str
    x: int
    y: int
    width: int = NODE_WIDTH
    height: int = NODE_HEIGHT

    @property
    def text_x(self) -> int:
        return self.x + 10

    @property
    def label_y(self) -> int:
        return self.y + 18

    @property
    def sublabel_y(self) -> int:
        return self.y + 35


@dataclass(frozen=True, slots=True)
class Edge:
    path: str
    kind: str


@dataclass(frozen=True, slots=True)
class Column:
    title: str
    x: int


@dataclass(frozen=True, slots=True)
class Graph:
    width: int
    height: int
    columns: tuple[Column, ...]
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]

    @property
    def is_empty(self) -> bool:
        return not self.nodes


def clip(value: str, limit: int = MAX_LABEL) -> str:
    text = " ".join(value.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def layered_graph(
    columns: list[tuple[str, list[NodeSpec]]],
    edges: list[tuple[str, str, str]],
) -> Graph:
    placed: dict[str, Node] = {}
    headers: list[Column] = []
    tallest = 0
    for index, (title, specs) in enumerate(columns):
        x = MARGIN + index * (NODE_WIDTH + COLUMN_GAP)
        headers.append(Column(title, x))
        tallest = max(tallest, len(specs))
        for row, spec in enumerate(specs):
            placed[spec.key] = Node(
                clip(spec.label),
                clip(spec.sublabel, 30),
                spec.kind,
                spec.href,
                spec.title or f"{spec.label} — {spec.sublabel}",
                x,
                HEADER_HEIGHT + row * (NODE_HEIGHT + ROW_GAP),
            )
    drawn: list[Edge] = []
    for source_key, target_key, kind in edges:
        source, target = placed.get(source_key), placed.get(target_key)
        if source is None or target is None:
            continue
        x1, y1 = source.x + source.width, source.y + source.height // 2
        x2, y2 = target.x, target.y + target.height // 2
        bend = COLUMN_GAP // 2
        drawn.append(
            Edge(f"M {x1} {y1} C {x1 + bend} {y1}, {x2 - bend} {y2}, {x2} {y2}", kind)
        )
    width = 2 * MARGIN + max(len(columns), 1) * (NODE_WIDTH + COLUMN_GAP) - COLUMN_GAP
    height = HEADER_HEIGHT + max(tallest, 1) * (NODE_HEIGHT + ROW_GAP) + MARGIN
    return Graph(width, height, tuple(headers), tuple(placed.values()), tuple(drawn))


def evidence_graph(
    analysis: CaseAnalysis,
    *,
    artifact_href: dict[str, str],
    rule_href: dict[str, str],
    run_href: dict[str, str],
) -> Graph:
    """Evidence → Hypothesis → Rule → Validation for one Case."""
    static_sources = {
        result.artifact.artifact_id.display_id: result.source_artifact_id
        for result in analysis.static_results
    }
    collected = {
        run.sysmon_artifact_id: run.display_id
        for run in analysis.execution_runs
        if run.sysmon_artifact_id is not None
    }
    artifacts: list[NodeSpec] = []
    for artifact in analysis.artifacts:
        display_id = artifact.artifact_id.display_id
        detail = artifact.kind.value
        if display_id in static_sources:
            detail = f"static of {static_sources[display_id]}"
        elif display_id in collected:
            detail = f"sysmon from {collected[display_id]}"
        artifacts.append(
            NodeSpec(
                f"a:{display_id}",
                display_id,
                detail,
                "artifact",
                artifact_href.get(display_id),
            )
        )
    hypotheses = [
        NodeSpec(
            f"h:{item.display_id}",
            item.display_id,
            item.status.value,
            f"hypothesis hypothesis-{item.status.value}",
            None,
            f"{item.display_id} — {item.title}",
        )
        for item in analysis.hypotheses
    ]
    rules = [
        NodeSpec(
            f"r:{rule.display_id}",
            rule.display_id,
            f"{rule.format.value} · v{rule.latest.version} {rule.latest.status.value}",
            "rule",
            rule_href.get(rule.display_id),
            f"{rule.display_id} — {rule.name}",
        )
        for rule in analysis.rules
    ]
    runs: list[NodeSpec] = []
    edges: list[tuple[str, str, str]] = []
    for run in analysis.validation_runs:
        result = analysis.case_result(run)
        outcome = "not a member" if result is None else result.outcome.value
        css = "none" if result is None else result.outcome.value.lower()
        runs.append(
            NodeSpec(
                f"v:{run.display_id}",
                run.display_id,
                f"{run.kind.value} · v{run.rule_version} · {outcome}",
                f"run outcome-{css}",
                run_href.get(run.display_id),
            )
        )
        edges.append((f"r:{run.rule_display_id}", f"v:{run.display_id}", "validated"))
    for hypothesis in analysis.hypotheses:
        for artifact_id in hypothesis.evidence_artifact_ids:
            edges.append((f"a:{artifact_id}", f"h:{hypothesis.display_id}", "supports"))
        for rule_id in hypothesis.rule_display_ids:
            edges.append((f"h:{hypothesis.display_id}", f"r:{rule_id}", "implements"))
    return layered_graph(
        [
            ("Evidence (Artifacts)", artifacts),
            ("Hypotheses", hypotheses),
            ("Rules", rules),
            ("Validation runs", runs),
        ],
        edges,
    )


def process_graph(relations: ProcessRelations) -> Graph:
    """Process tree by depth; files written by a process sit one column deeper."""
    columns: dict[int, list[NodeSpec]] = {}
    edges: list[tuple[str, str, str]] = []
    for index, process in enumerate(relations.processes):
        depth = relations.depth(process)
        key = f"p:{index}"
        activity = ", ".join(
            f"{name} {count}" for name, count in sorted(process.activity.items())
        )
        pid = "PID ?" if process.pid is None else f"PID {process.pid}"
        sublabel = pid if not activity else f"{pid} · {activity}"
        if not process.captured:
            sublabel = f"{pid} · not captured"
        if process.same_as is not None:
            sublabel = f"{sublabel} · same file as {process.same_as}"
        columns.setdefault(depth, []).append(
            NodeSpec(
                key,
                process.image_name,
                sublabel,
                "process" if process.captured else "process process-external",
                None,
                f"{process.image_name} — {sublabel}"
                + (f" — {process.source}" if process.source else ""),
            )
        )
        if process.parent_key is not None:
            for parent_index, parent in enumerate(relations.processes):
                if parent.key == process.parent_key:
                    edges.append((f"p:{parent_index}", key, "spawned"))
                    break
        for file_index, written in enumerate(process.files):
            file_key = f"f:{index}:{file_index}"
            columns.setdefault(depth + 1, []).append(
                NodeSpec(
                    file_key,
                    written.name,
                    f"file · {written.source or 'unknown record'}",
                    "file",
                )
            )
            edges.append((key, file_key, "wrote"))
        hidden = process.file_total - len(process.files)
        if hidden > 0:
            more_key = f"f:{index}:more"
            columns.setdefault(depth + 1, []).append(
                NodeSpec(more_key, f"+{hidden} more files", "not drawn", "file")
            )
            edges.append((key, more_key, "wrote"))
    ordered = [
        ("Root processes" if depth == 0 else f"Depth {depth}", columns[depth])
        for depth in sorted(columns)
    ]
    return layered_graph(ordered, edges)
