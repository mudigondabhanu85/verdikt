import io
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response

from app.auth.dependencies import get_current_user
from app.config import get_settings
from app.models.organization import User

router = APIRouter(prefix="/browser-extension", tags=["browser-extension"])

# The folder name a downloaded zip unpacks into — chosen so
# chrome://extensions' "Load unpacked" picker shows something
# recognizable rather than a bare "browser-extension" (this repo's
# source directory name, meaningless out of context).
_ZIP_ROOT_FOLDER = "verdikt-login-macro-recorder"


@router.get("/download")
async def download_browser_extension(user: User = Depends(get_current_user)) -> Response:
    """Zips browser-extension/ (the standalone login-macro-recorder
    extension — see its own README) on demand for the "Download
    extension" button next to Record macro. Not RBAC-gated to a
    specific resource/action: this is a static, org-independent asset,
    not org data — any authenticated user may fetch it.
    """
    source_dir = Path(get_settings().browser_extension_source_dir)
    if not source_dir.is_dir():
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Browser extension source not found on this server — check "
            "the BROWSER_EXTENSION_SOURCE_DIR setting.",
        )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(source_dir.rglob("*")):
            if file_path.is_file():
                zf.write(file_path, f"{_ZIP_ROOT_FOLDER}/{file_path.relative_to(source_dir)}")
    buffer.seek(0)

    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{_ZIP_ROOT_FOLDER}.zip"'},
    )
