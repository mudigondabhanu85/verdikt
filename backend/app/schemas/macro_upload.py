from pydantic import BaseModel, field_validator

from app.agents.macro import MacroStep

_VALID_ACTIONS = {"goto", "click", "fill"}


class MacroUploadRequest(BaseModel):
    """Body shape for uploading a macro recorded by the standalone
    browser extension (browser-extension/) — identical to the JSON file
    it exports (`{"steps": [...]}`), and identical to what
    MacroRecorder.record() produces in-app, so either path lands as the
    same LoginMacro.steps shape.
    """

    steps: list[dict]

    @field_validator("steps")
    @classmethod
    def _validate_steps(cls, steps: list[dict]) -> list[dict]:
        if not steps:
            raise ValueError("steps must not be empty")
        for raw in steps:
            if "action" not in raw:
                raise ValueError(f"step missing required 'action' key: {raw!r}")
            if raw["action"] not in _VALID_ACTIONS:
                raise ValueError(f"unknown action {raw['action']!r}; must be one of {_VALID_ACTIONS}")
            # Round-trip through MacroStep to confirm the shape is
            # otherwise well-formed (extra/missing optional keys handled
            # the same way MacroStep.from_dict already tolerates them).
            MacroStep.from_dict(raw)
        return steps
