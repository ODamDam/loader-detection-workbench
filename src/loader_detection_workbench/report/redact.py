"""De-identification of report documents before they are published (ADR-012).

Escaping keeps evidence text inert; it does not hide who ran the analysis VM.
Sysmon telemetry is full of user profile paths, per-user names (for example
named pipes such as ``VBoxTrayIPC-<user>``), domain-qualified account names
and per-machine SIDs. This module removes them from every *untrusted* text and
code block of a document. Workbench-generated values (display IDs, counts,
hashes) are left alone.

Names are learned from the documents themselves in a first pass, so a name
that appears once in a profile path is also removed wherever it appears
alone. This is pattern based and errs on the side of over-redaction; it does
not find a name that never appears in a recognizable position.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace

from loader_detection_workbench.report.document import (
    Block,
    Bullets,
    Code,
    Document,
    Heading,
    Item,
    Links,
    Paragraph,
    Table,
    Text,
)

USER_PLACEHOLDER = "<user>"
HOST_PLACEHOLDER = "<host>"
SID_PLACEHOLDER = "S-1-5-21-<sid>"

# X:\Users\<name> and \Device\HarddiskVolumeN\Users\<name>
_PROFILE = re.compile(
    r"(?i)((?:\b[A-Z]:|\\Device\\HarddiskVolume\d+)\\Users\\)([^\\/:*?\"<>|\r\n]+)"
)
# HOST\user as written in the Sysmon User field.
_ACCOUNT = re.compile(r"(?i)^([A-Z0-9][A-Z0-9-]{0,62})\\([^\\/:*?\"<>|\s]{1,64})$")
_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+(?:-\d+)?")
_BUILTIN_PROFILES = frozenset(
    {"public", "default", "default user", "all users", "defaultapppool"}
)
_BUILTIN_ACCOUNTS = frozenset(
    {"nt authority", "nt service", "builtin", "window manager", "font driver host"}
)


def _unique(names: Iterable[str]) -> frozenset[str]:
    """One spelling per name; matching is case-insensitive anyway."""
    chosen: dict[str, str] = {}
    for name in sorted(names):
        chosen.setdefault(name.lower(), name)
    return frozenset(chosen.values())


def _texts(document: Document) -> Iterable[str]:
    for block in document.blocks:
        if isinstance(block, Heading):
            yield block.text.value
        elif isinstance(block, Bullets):
            yield from (entry.value.value for entry in block.items)
        elif isinstance(block, Paragraph):
            yield block.text.value
        elif isinstance(block, Table):
            yield from (cell.value for row in block.rows for cell in row)
        elif isinstance(block, Code):
            yield block.content
        elif isinstance(block, Links):
            yield from (label.value for _, label in block.items)


@dataclass
class Redactor:
    users: frozenset[str]
    hosts: frozenset[str]
    replaced: int = field(default=0)

    @classmethod
    def learn(
        cls,
        documents: Iterable[Document],
        *,
        hosts_seen: Iterable[str] = (),
        accounts_seen: Iterable[str] = (),
    ) -> Redactor:
        """Learn names from document text and from raw event fields.

        ``hosts_seen`` are Sysmon ``Computer`` values and ``accounts_seen``
        ``User`` field values (host, backslash, user). Neither may be shown as
        such, but both leak elsewhere, for example as a DNS query for the own
        host name.
        """
        users: set[str] = set()
        hosts: set[str] = set()
        for host in hosts_seen:
            short = host.split(".", 1)[0].strip()
            if len(short) >= 2:
                hosts.add(short)
        for value in accounts_seen:
            account = _ACCOUNT.match(value.strip())
            if account is None or account.group(1).lower() in _BUILTIN_ACCOUNTS:
                continue
            hosts.add(account.group(1))
            users.add(account.group(2))
        for document in documents:
            for text in _texts(document):
                for match in _PROFILE.finditer(text):
                    name = match.group(2).strip()
                    if name and name.lower() not in _BUILTIN_PROFILES:
                        users.add(name)
        # Accounts are learned only from the User fields above: guessing
        # "a\b" shapes in free text mistakes registry path pieces for hosts.
        return cls(_unique(users), _unique(hosts))

    def _pattern(self) -> re.Pattern[str] | None:
        names = sorted(
            {*(re.escape(n) for n in self.users), *(re.escape(h) for h in self.hosts)},
            key=len,
            reverse=True,
        )
        if not names:
            return None
        return re.compile(
            r"(?i)(?<![A-Za-z0-9_])(" + "|".join(names) + r")(?![A-Za-z0-9_])"
        )

    def apply(self, value: str) -> str:
        if not hasattr(self, "_compiled"):
            self._compiled = self._pattern()
            self._hosts_lower = {h.lower() for h in self.hosts}
        count = 0

        def profile(match: re.Match[str]) -> str:
            nonlocal count
            if match.group(2).strip().lower() in _BUILTIN_PROFILES:
                return match.group(0)
            count += 1
            return match.group(1) + USER_PLACEHOLDER

        result = _PROFILE.sub(profile, value)
        result, sids = _SID.subn(SID_PLACEHOLDER, result)
        count += sids
        if self._compiled is not None:

            def name(match: re.Match[str]) -> str:
                nonlocal count
                count += 1
                return (
                    HOST_PLACEHOLDER
                    if match.group(1).lower() in self._hosts_lower
                    else USER_PLACEHOLDER
                )

            result = self._compiled.sub(name, result)
        self.replaced += count
        return result

    def _text(self, text: Text) -> Text:
        return text if text.trusted else replace(text, value=self.apply(text.value))

    def _block(self, block: Block) -> Block:
        if isinstance(block, Heading):
            return replace(block, text=self._text(block.text))
        if isinstance(block, Bullets):
            return Bullets(
                tuple(
                    Item(entry.label, self._text(entry.value)) for entry in block.items
                )
            )
        if isinstance(block, Paragraph):
            return Paragraph(self._text(block.text))
        if isinstance(block, Table):
            return replace(
                block,
                rows=tuple(
                    tuple(self._text(cell) for cell in row) for row in block.rows
                ),
            )
        if isinstance(block, Code):
            return Code(self.apply(block.content))
        return Links(tuple((href, self._text(label)) for href, label in block.items))

    def document(self, document: Document) -> Document:
        return Document(
            self.apply(document.title),
            tuple(self._block(block) for block in document.blocks),
        )
