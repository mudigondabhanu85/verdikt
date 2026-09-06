"""Pure command parsing for the Microsoft Teams conversational trigger
(§9). Deliberately decoupled from the Bot Framework transport layer (see
activity_handler.py) so the actual command grammar is provable without
any Azure/Teams infrastructure — a real ActivityHandler just needs to
strip the @Verdikt mention entity Teams sends as structured data (not
literal text) before calling parse_command() with the remaining text.

Hard security constraint (§9): the bot must NEVER process a credential
typed into a chat message, even defensively — Teams messages are
retained under the org's own Teams/Exchange retention policy, so a
plaintext secret in a chat thread is a standing liability regardless of
what this tool does with it. Every command is checked for
credential-shaped content before being parsed as anything else.
"""

import re
from dataclasses import dataclass

_CREDENTIAL_SHAPED = re.compile(
    r"""(?ix)
    (?: password | passwd | pwd | secret | token | api[_-]?key | bearer ) \s* [:=] \s* \S+
    """
)


@dataclass(frozen=True)
class ScanCommand:
    project_name: str


@dataclass(frozen=True)
class StatusCommand:
    project_name: str


@dataclass(frozen=True)
class NewProjectCommand:
    url: str


@dataclass(frozen=True)
class UnknownCommand:
    raw: str


@dataclass(frozen=True)
class RejectedCommand:
    reason: str


ParsedCommand = ScanCommand | StatusCommand | NewProjectCommand | UnknownCommand | RejectedCommand

_SCAN_RE = re.compile(r"(?i)^\s*scan\s+(.+?)\s*$")
_STATUS_RE = re.compile(r"(?i)^\s*status\s+(.+?)\s*$")
_NEW_PROJECT_RE = re.compile(r"(?i)^\s*new\s+project\s+(.+?)\s*$")


def parse_command(text: str) -> ParsedCommand:
    """`text` is the message content with the @Verdikt bot-mention entity
    already stripped by the caller (a real ActivityHandler receives the
    mention as a structured entity, not as literal "@Verdikt" text — see
    activity_handler.py's docstring)."""
    if _CREDENTIAL_SHAPED.search(text):
        return RejectedCommand(
            reason=(
                "This message looks like it contains a credential (password/token/API "
                "key). Verdikt never accepts target-application credentials via chat — "
                "configure credentials in the Verdikt web app instead."
            )
        )

    stripped = text.strip()

    match = _SCAN_RE.match(stripped)
    if match:
        return ScanCommand(project_name=match.group(1))

    match = _STATUS_RE.match(stripped)
    if match:
        return StatusCommand(project_name=match.group(1))

    match = _NEW_PROJECT_RE.match(stripped)
    if match:
        return NewProjectCommand(url=match.group(1))

    return UnknownCommand(raw=text)
