from app.importers.base import TrafficImporter
from app.schemas.traffic import HttpInteraction


class WebInspectMacroImporter(TrafficImporter):
    """Stub — no genuine WebInspect login macro export was obtainable
    while building this (no WebInspect installation available in this
    environment, unlike Burp/Checkmarx where either a real installed
    tool or genuine documentation+sample was available). The interface
    exists and slots in later; this stub raises a clear, typed error
    rather than guessing at an undocumented format.
    """

    def parse(self, file_path: str) -> list[HttpInteraction]:
        raise NotImplementedError(
            "WebInspectMacroImporter needs a real WebInspect macro export to build "
            "against — none was obtainable during this build. Provide a genuine "
            "sample export to implement this importer against its actual format."
        )
