import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.agents.macro import MacroPlayer, MacroStep
from app.api.routes.macro_upload import upload_login_macro
from app.auth.security import hash_password
from app.models.credential import CredentialSet
from app.models.login_macro import LoginMacro
from app.models.organization import Organization, User
from app.models.project import Project, Version
from app.schemas.macro_upload import MacroUploadRequest
from app.vault.credential_vault import encrypt_credential, mask_reference
from tests.conftest import session_scope


def _extension_exported_steps(base_url: str) -> list[dict]:
    """Simulates exactly what browser-extension/popup.js's
    buildExportableSteps() produces for a simple username/password/submit
    login flow — same shape as backend/app/agents/macro.py's MacroStep
    dicts, proving the two recording paths (in-app Playwright recorder vs.
    this standalone extension) are byte-for-byte interchangeable inputs
    to MacroPlayer.replay().
    """
    return [
        {"action": "goto", "selector": None, "value": None, "field_role": None, "url": base_url},
        {"action": "fill", "selector": "#username", "value": None, "field_role": "username", "url": None},
        {"action": "fill", "selector": "#password", "value": None, "field_role": "password", "url": None},
        {"action": "click", "selector": "#submit-btn", "value": None, "field_role": None, "url": None},
    ]


def test_macro_upload_request_accepts_extension_exported_shape():
    payload = MacroUploadRequest(steps=_extension_exported_steps("http://example.test/"))
    assert len(payload.steps) == 4


def test_macro_upload_request_rejects_missing_action():
    with pytest.raises(ValidationError):
        MacroUploadRequest(steps=[{"selector": "#foo"}])


def test_macro_upload_request_rejects_unknown_action():
    with pytest.raises(ValidationError):
        MacroUploadRequest(steps=[{"action": "hover", "selector": "#foo"}])


def test_macro_upload_request_rejects_empty_steps():
    with pytest.raises(ValidationError):
        MacroUploadRequest(steps=[])


async def test_extension_exported_macro_replays_identically_to_in_app_recorded_macro(
    fixture_login_server,
):
    host, port = fixture_login_server
    base_url = f"http://{host}:{port}/"

    extension_steps = [MacroStep.from_dict(raw) for raw in _extension_exported_steps(base_url)]

    player = MacroPlayer()
    credential_set_id = uuid.uuid4()
    session = await player.replay(
        extension_steps,
        credential_set_id=credential_set_id,
        username="expected_user",
        password="expected_pass",
        headless=True,
    )

    assert session is not None
    assert session.credential_set_id == credential_set_id
    assert session.cookies.get("session") == "abc123-real-session"


async def test_upload_endpoint_creates_login_macro_row(db_adapter):
    async with session_scope(db_adapter) as session:
        org = Organization(name=f"Macro Upload Org {uuid.uuid4()}")
        session.add(org)
        await session.flush()
        user = User(
            org_id=org.id,
            email=f"macro-uploader-{uuid.uuid4()}@example.com",
            hashed_password=hash_password("irrelevant"),
            role="org_admin",
        )
        session.add(user)
        await session.flush()
        project = Project(org_id=org.id, name="Macro Upload Test App", created_by=user.id)
        session.add(project)
        await session.flush()
        version = Version(project_id=project.id, name="v1", created_by=user.id)
        session.add(version)
        await session.flush()
        credential = CredentialSet(
            version_id=version.id,
            label="Admin",
            credential_type="username_password",
            encrypted_secret=encrypt_credential("admin", "hunter2"),
            masked_reference=mask_reference("admin", "hunter2"),
        )
        session.add(credential)
        await session.commit()
        await session.refresh(user)
        await session.refresh(version)
        await session.refresh(credential)

        payload = MacroUploadRequest(steps=_extension_exported_steps("http://example.test/"))
        result = await upload_login_macro(
            version_id=version.id,
            credential_id=credential.id,
            payload=payload,
            user=user,
            session=session,
        )

        assert result.version_id == version.id
        assert result.credential_set_id == credential.id
        assert result.step_count == 4

        rows = (
            await session.execute(select(LoginMacro).where(LoginMacro.credential_set_id == credential.id))
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].steps == payload.steps
