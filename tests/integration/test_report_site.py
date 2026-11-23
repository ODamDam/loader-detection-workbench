"""Static report site (M4) and report de-identification."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from analysis_fixture import UNTRUSTED, build_workspace

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.cli import main
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.report.document import (
    Bullets,
    Code,
    Document,
    Links,
    Paragraph,
    item,
    trusted,
    untrusted,
)
from loader_detection_workbench.report.redact import Redactor
from loader_detection_workbench.report.site import SiteService

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
HOST = "LAB-PC07"
USER = "jdoe"
SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


def _identifying_events() -> bytes:
    def event(event_id: int, record: int, fields: dict[str, str]) -> str:
        data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
        return (
            f'<Event xmlns="{NS}"><System><Provider Name="Microsoft-Windows-Sysmon"/>'
            f"<EventID>{event_id}</EventID><EventRecordID>{record}</EventRecordID>"
            f"<Computer>{HOST}.lab.example</Computer></System>"
            f"<EventData>{data}</EventData></Event>"
        )

    events = [
        event(13, 900, {
            "UtcTime": "2026-11-17 02:00:00.000",
            "EventType": "SetValue",
            "Image": f"C:\\Users\\{USER}\\AppData\\Local\\Temp\\drop.exe",
            "TargetObject": f"HKU\\{SID}\\Software\\Run\\x",
            "User": f"{HOST}\\{USER}",
        }),
        event(22, 901, {
            "UtcTime": "2026-11-17 02:00:01.000",
            "QueryName": HOST,
            "Image": "C:\\Windows\\System32\\svchost.exe",
        }),
        event(17, 902, {
            "UtcTime": "2026-11-17 02:00:02.000",
            "PipeName": f"\\VBoxTrayIPC-{USER}",
            "Image": "C:\\Users\\Public\\tool.exe",
        }),
    ]  # fmt: skip
    return ("<Events>" + "".join(events) + "</Events>").encode()


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = build_workspace(tmp_path)
    source = tmp_path / "identifying.xml"
    source.write_bytes(_identifying_events())
    ArtifactService(path).add("CASE-0001", source, "sysmon")
    monkeypatch.chdir(path)
    return path


def _clock() -> datetime:
    return datetime(2026, 11, 17, 3, 0, tzinfo=UTC)


def test_redactor_learns_names_and_keeps_trusted_text() -> None:
    document = Document(
        "Case",
        (
            Paragraph(untrusted(f"C:\\Users\\{USER}\\x.exe and \\VBoxTrayIPC-{USER}")),
            Bullets((item("SID", SID), item("Run", "VMR-0001", is_trusted=True))),
            Code(f"path: C:\\Users\\{USER.upper()}\\a"),
            Paragraph(untrusted("C:\\Users\\Public\\ok.exe and C:\\Users\\Default\\x")),
            Paragraph(trusted(f"trusted {USER}")),
        ),
    )
    redactor = Redactor.learn([document], hosts_seen=[f"{HOST}.lab"])
    assert {u.lower() for u in redactor.users} == {USER}
    assert redactor.hosts == frozenset({HOST})
    cleaned = redactor.document(document)
    first, second, code, builtin, kept = cleaned.blocks
    assert isinstance(first, Paragraph) and isinstance(second, Bullets)
    assert first.text.value == "C:\\Users\\<user>\\x.exe and \\VBoxTrayIPC-<user>"
    assert second.items[0].value.value == "S-1-5-21-<sid>"
    assert second.items[1].value.value == "VMR-0001"
    assert isinstance(code, Code) and code.content == "path: C:\\Users\\<user>\\a"
    assert isinstance(builtin, Paragraph) and "Public" in builtin.text.value
    assert "Default" in builtin.text.value
    assert isinstance(kept, Paragraph) and kept.text.value == f"trusted {USER}"
    assert redactor.replaced == 4
    # A host name is replaced as a whole word only.
    assert redactor.apply(f"{HOST} {HOST}X x{HOST}") == f"<host> {HOST}X x{HOST}"


def test_redactor_learns_accounts_only_from_user_fields() -> None:
    document = Document(
        "x", (Paragraph(untrusted("HKLM\\SOFTWARE\\Windows Defender\\Features")),)
    )
    redactor = Redactor.learn(
        [document], accounts_seen=[f"{HOST}\\{USER}", "NT AUTHORITY\\SYSTEM"]
    )
    assert redactor.hosts == frozenset({HOST})
    assert redactor.users == frozenset({USER})
    assert redactor.apply("Windows Defender\\Features") == "Windows Defender\\Features"


def test_links_accept_only_relative_html_targets() -> None:
    Links((("index.html", trusted("i")), ("../index.html", trusted("u"))))
    for bad in (
        "https://x.html",
        "javascript:a.html",
        "a/../b.html",
        "x.htm",
        "/a.html",
    ):
        with pytest.raises(ValueError):
            Links(((bad, trusted("x")),))


def test_site_is_built_de_identified_and_inert(root: Path) -> None:
    summary = SiteService(root, clock=_clock).build(Path("site"))
    site = root / "site"
    assert summary.output == site
    assert summary.cases == 4 and summary.pages == 6
    assert summary.redactions > 0
    pages = sorted(p.relative_to(site).as_posix() for p in site.rglob("*.html"))
    assert pages == [
        "cases/CASE-0001.html",
        "cases/CASE-0002.html",
        "cases/CASE-0003.html",
        "cases/CASE-0004.html",
        "index.html",
        "rules.html",
    ]
    combined = "\n".join(p.read_text(encoding="utf-8") for p in site.rglob("*.html"))
    for secret in (USER, HOST, SID):
        assert secret.lower() not in combined.lower(), secret
    assert "C:\\Users\\&lt;user&gt;\\AppData" in combined
    assert "QueryName=&lt;host&gt;" in combined
    assert "C:\\Users\\Public\\tool.exe" in combined
    assert "<script" not in combined and UNTRUSTED not in combined
    hrefs = set(re.findall(r'href="([^"]+)"', combined))
    assert hrefs == {
        "rules.html",
        "index.html",
        "../index.html",
        "cases/CASE-0001.html",
        "cases/CASE-0002.html",
        "cases/CASE-0003.html",
        "cases/CASE-0004.html",
    }
    index = (site / "index.html").read_text(encoding="utf-8")
    assert "Quantitative Goals" in index and "Latest Validation per Rule" in index
    assert '<td>Analyzed malware Cases</td><td class="num">6</td>' in index
    rules = (site / "rules.html").read_text(encoding="utf-8")
    assert "RULE-0001" in rules and "TP / malicious" in rules
    assert not list(root.glob(".site-*"))


def test_existing_output_is_never_overwritten(root: Path) -> None:
    (root / "site").mkdir()
    (root / "site" / "keep.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(DomainError) as error:
        SiteService(root).build(Path("site"))
    assert error.value.code is DomainErrorCode.REPORT_OUTPUT_EXISTS
    assert [p.name for p in (root / "site").iterdir()] == ["keep.txt"]


def test_cli(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["report", "site", "out"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("site: created (6 pages, 4 Cases)\nredactions: ")
    assert "nothing was published" in out
    assert main(["report", "site", "out"]) == 2
    assert "REPORT_OUTPUT_EXISTS" in capsys.readouterr().err
