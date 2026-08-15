import pytest

from app.importers.burp_file_importer import BurpFileImporter
from app.importers.webinspect_importer import WebInspectMacroImporter


def test_burp_file_importer_raises_clear_error_not_silent_failure():
    with pytest.raises(NotImplementedError, match="real .burp project export"):
        BurpFileImporter().parse("/some/path.burp")


def test_webinspect_importer_raises_clear_error_not_silent_failure():
    with pytest.raises(NotImplementedError, match="real WebInspect macro export"):
        WebInspectMacroImporter().parse("/some/path.webmacro")
