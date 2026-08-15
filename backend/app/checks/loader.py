from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel

_CATALOG_PATH = Path(__file__).parent / "catalog.yaml"


class CheckDefinition(BaseModel):
    id: str
    title: str
    owasp_2025_category: str
    cwe_id: str
    severity: str
    cvss_vector: str
    cvss_score: float
    portswigger_reference_url: str | None = None
    plain_language_summary: str
    technical_description: str
    remediation: str
    references: list[str] = []


@lru_cache
def load_catalog() -> dict[str, CheckDefinition]:
    raw = yaml.safe_load(_CATALOG_PATH.read_text())
    definitions = [CheckDefinition(**entry) for entry in raw]
    return {d.id: d for d in definitions}


def get_check(check_id: str) -> CheckDefinition:
    catalog = load_catalog()
    if check_id not in catalog:
        raise KeyError(f"Unknown check id: {check_id!r}")
    return catalog[check_id]
