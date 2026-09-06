"""Bot Framework transport glue for the Teams conversational trigger
(§9). Structurally correct against the documented botbuilder-core
ActivityHandler shape, but NOT verified by import in this environment —
`botbuilder-core` was deliberately not added as a dependency here (adding
a new dependency mid-session risked destabilizing other work running
against the same shared virtualenv concurrently). Whoever wires this up
against a real Azure Bot Service registration should `uv add
botbuilder-core botbuilder-schema` first and smoke-test the import.

The two things this module is responsible for that commands.py/
dispatcher.py deliberately do NOT handle:
1. Stripping the @Verdikt mention entity Teams sends as structured data
   (turn_context.activity.entities), not literal "@Verdikt " text, from
   the incoming message before handing the remainder to parse_command().
2. Resolving which Verdikt org + acting User this Teams
   tenant/conversation maps to — a real deployment needs a config table
   (Teams tenant ID -> Verdikt org + bot service account) that doesn't
   exist yet; _resolve_acting_user below is a placeholder raising
   NotImplementedError so this is impossible to silently misuse.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from app.integrations.teams_bot.commands import parse_command
from app.integrations.teams_bot.dispatcher import TeamsCommandDispatcher
from app.models.organization import User

if TYPE_CHECKING:  # pragma: no cover - type-checking only, see module docstring
    from botbuilder.core import ActivityHandler, TurnContext
else:
    try:
        from botbuilder.core import ActivityHandler, TurnContext
    except ImportError:  # pragma: no cover - expected in this environment
        class ActivityHandler:  # type: ignore[no-redef]
            """Placeholder base class used only when botbuilder-core isn't
            installed, so this module still imports cleanly for anything
            that only needs commands.py/dispatcher.py."""

        TurnContext = object  # type: ignore[assignment,misc]


def _strip_mention(text: str, entities: list[dict] | None) -> str:
    """Removes the @Verdikt mention's literal text (Teams includes it in
    both `activity.text` and as a structured `mention` entity) from the
    front of the message, leaving just the command. Falls back to
    stripping a literal "@Verdikt" prefix if no entities are present
    (e.g. in a test harness constructing a bare Activity)."""
    if entities:
        for entity in entities:
            if entity.get("type") == "mention":
                mention_text = entity.get("text", "")
                if mention_text and text.startswith(mention_text):
                    return text[len(mention_text) :].strip()
    if text.lstrip().lower().startswith("@verdikt"):
        return text.lstrip()[len("@verdikt") :].strip()
    return text.strip()


async def _resolve_acting_user(turn_context: "TurnContext") -> User:
    """Maps an incoming Teams activity's tenant/conversation to a Verdikt
    org + acting User. Not implemented in this pass — see module
    docstring. Left as a clear, loud failure point rather than a silent
    stub that would let a message through without real org scoping.
    """
    raise NotImplementedError(
        "Teams tenant -> Verdikt org/user resolution is not implemented yet; "
        "see app/integrations/teams_bot/activity_handler.py's module docstring."
    )


class VerdiktTeamsActivityHandler(ActivityHandler):
    def __init__(self, db_session: AsyncSession):
        self._session = db_session

    async def on_message_activity(self, turn_context: "TurnContext") -> None:
        activity = turn_context.activity
        entities = getattr(activity, "entities", None)
        text = _strip_mention(activity.text or "", entities)

        command = parse_command(text)
        acting_user = await _resolve_acting_user(turn_context)
        dispatcher = TeamsCommandDispatcher(self._session, acting_user=acting_user)
        reply = await dispatcher.dispatch(command)

        await turn_context.send_activity(reply)
