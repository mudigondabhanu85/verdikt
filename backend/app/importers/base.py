from abc import ABC, abstractmethod

from app.schemas.traffic import HttpInteraction


class TrafficImporter(ABC):
    """Normalizes a source-specific traffic file into the canonical
    HttpInteraction schema (§4). Every importer (HAR, Burp file, Checkmarx
    .zst, WebInspect macro) implements this same interface so downstream
    agents are source-agnostic.
    """

    @abstractmethod
    def parse(self, file_path: str) -> list[HttpInteraction]: ...
