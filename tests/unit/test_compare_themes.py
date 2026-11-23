"""Theme-based opinion matching for provider comparison (ADR-027, ADR-031)."""

from __future__ import annotations

from loader_detection_workbench.ai.compare import Opinion, _group, themes
from loader_detection_workbench.ai.domain import SuggestionKind

K = SuggestionKind


def _op(
    provider: str,
    kind: SuggestionKind,
    text: str,
    title: str | None = None,
    cites: tuple[str, ...] = ("ART-000007", "ART-000059"),
) -> Opinion:
    return Opinion("AIA-0001", provider, "m", 1, kind, title, text, cites)


def test_themes_read_behavior_words() -> None:
    assert themes("Outbound network communication via WinINet and Winsock") == {
        "network"
    }
    assert themes("Sample drops and spawns secondary executable payload") == {
        "execution"
    }
    assert themes("Screen capture capability via GDI and GDIPlus imports") == {"screen"}
    assert themes("may try to establish persistence via registry") == {"registry"}
    assert themes("A neutral sentence about counts") == frozenset()


def test_differently_worded_hypotheses_group_by_theme() -> None:
    hyp = K.HYPOTHESIS_CANDIDATE
    groups = _group(
        [
            _op("openai", hyp, "x", "Networking APIs; likely outbound network use"),
            _op("deepseek", hyp, "x", "Network capability may be present"),
            _op(
                "gemini",
                hyp,
                "x",
                "Outbound network communication via WinINet and Winsock",
                cites=("ART-000007",),
            ),
            _op("gemini", hyp, "x", "Sample drops and spawns a secondary executable"),
        ]
    )
    assert [sorted(o.provider for o in g.opinions) for g in groups] == [
        ["deepseek", "gemini", "openai"],
        ["gemini"],
    ]


def test_no_shared_citation_or_same_provider_never_groups() -> None:
    groups = _group(
        [
            _op(
                "openai", K.NEXT_STEP, "Inspect registry writes", cites=("ART-000001",)
            ),
            _op(
                "gemini", K.NEXT_STEP, "Inspect registry writes", cites=("ART-000059",)
            ),
            _op(
                "openai",
                K.NEXT_STEP,
                "Inspect registry keys again",
                cites=("ART-000001",),
            ),
        ]
    )
    assert [len(g.opinions) for g in groups] == [1, 1, 1]


def test_groups_do_not_chain_through_mixed_opinions() -> None:
    # registry ~ registry+network ~ network: the ends must not end up together.
    groups = _group(
        [
            _op("openai", K.NEXT_STEP, "Enumerate the registry keys"),
            _op(
                "deepseek", K.NEXT_STEP, "Check registry writes and DNS network queries"
            ),
            _op("gemini", K.NEXT_STEP, "Capture network traffic and DNS queries"),
        ]
    )
    assert [sorted(o.provider for o in g.opinions) for g in groups] == [
        ["deepseek", "openai"],
        ["gemini"],
    ]


def test_without_themes_wording_still_decides() -> None:
    same = _group(
        [
            _op("a", K.NEXT_STEP, "Compare the counts with a clean baseline run"),
            _op("b", K.NEXT_STEP, "Compare the counts with a clean baseline"),
        ]
    )
    different = _group(
        [
            _op("a", K.NEXT_STEP, "Compare the counts with a clean baseline run"),
            _op("b", K.NEXT_STEP, "Review section entropy values"),
        ]
    )
    assert len(same) == 1 and len(different) == 2
