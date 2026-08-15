from app.importers.base import TrafficImporter
from app.schemas.traffic import HttpInteraction


class BurpFileImporter(TrafficImporter):
    """Stub — Burp's `.burp` project file is a proprietary, undocumented
    binary format. Implementing this against a guess would risk silently
    mis-parsing real analyst data. No genuine `.burp` sample was
    obtainable while building this (Burp Suite Community Edition, the
    only edition available, cannot save or export project files at all
    — that's a Pro/Enterprise-only feature). The interface exists and
    slots in later; this stub raises a clear, typed error rather than
    guessing.
    """

    def parse(self, file_path: str) -> list[HttpInteraction]:
        raise NotImplementedError(
            "BurpFileImporter needs a real .burp project export to build against — "
            "none was obtainable during this build (Burp Community Edition cannot "
            "save/export projects). Provide a genuine .burp sample to implement "
            "this importer against its actual on-disk format."
        )
