from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel

from app.ai.adapters.base import Message

_PROMPTS_DIR = Path(__file__).parent


class PromptTemplate(BaseModel):
    id: str
    system_prompt: str
    user_prompt_template: str


@lru_cache
def load_prompt(prompt_id: str) -> PromptTemplate:
    path = _PROMPTS_DIR / f"{prompt_id}.yaml"
    raw = yaml.safe_load(path.read_text())
    return PromptTemplate(id=prompt_id, **raw)


def render_prompt(prompt_id: str, **context: str) -> list[Message]:
    """Loads a versioned prompt config (§15 — never hardcoded inline) and
    fills in its user-prompt placeholders."""
    prompt = load_prompt(prompt_id)
    return [
        Message("system", prompt.system_prompt),
        Message("user", prompt.user_prompt_template.format(**context)),
    ]
