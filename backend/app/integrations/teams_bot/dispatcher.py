"""Dispatches parsed Teams commands (commands.py) against real Verdikt
data (§9). Deliberately does not resolve "which Verdikt org/user does
this Teams message belong to" — that mapping (Teams tenant/channel ->
Verdikt org + an acting User whose identity backs requested_by/RBAC
checks) is a real Bot Framework registration concern, out of scope for
this scaffold. Callers (eventually activity_handler.py, wired to a real
Azure Bot Service registration) are expected to have already resolved an
`acting_user` before calling dispatch() — this keeps the dispatch logic
itself fully testable against a real Project/User fixture without
inventing new schema for a bot config table this pass doesn't need.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.runner import execute_scan_run
from app.config import get_settings
from app.integrations.teams_bot.commands import (
    NewProjectCommand,
    ParsedCommand,
    RejectedCommand,
    ScanCommand,
    StatusCommand,
    UnknownCommand,
)
from app.models.organization import User
from app.models.project import Project, Version
from app.models.scan import ScanRun


class TeamsCommandDispatcher:
    def __init__(self, db_session: AsyncSession, *, acting_user: User):
        self._session = db_session
        self._user = acting_user

    async def dispatch(self, command: ParsedCommand) -> str:
        if isinstance(command, RejectedCommand):
            return command.reason
        if isinstance(command, ScanCommand):
            return await self._scan(command.project_name)
        if isinstance(command, StatusCommand):
            return await self._status(command.project_name)
        if isinstance(command, NewProjectCommand):
            return await self._new_project(command.url)
        if isinstance(command, UnknownCommand):
            return (
                f'Unrecognized command: "{command.raw}". Try:\n'
                '"scan <project-name>", "status <project-name>", or '
                '"new project <url>".'
            )
        raise TypeError(f"Unhandled command type: {type(command)!r}")  # pragma: no cover

    async def _find_project(self, project_name: str) -> Project | None:
        result = await self._session.execute(
            select(Project).where(
                Project.org_id == self._user.org_id,
                Project.name == project_name,
                Project.archived_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    async def _latest_version(self, project_id: uuid.UUID) -> Version | None:
        result = await self._session.execute(
            select(Version)
            .where(Version.project_id == project_id)
            .order_by(Version.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _scan(self, project_name: str) -> str:
        project = await self._find_project(project_name)
        if project is None:
            return f'No project named "{project_name}" found. Use "new project <url>" to create one.'

        version = await self._latest_version(project.id)
        if version is None:
            return f'Project "{project_name}" has no versions yet — finish setup in the Verdikt web app first.'

        scan_run = ScanRun(
            version_id=version.id,
            status="pending",
            requested_by=self._user.id,
        )
        self._session.add(scan_run)
        await self._session.commit()
        await self._session.refresh(scan_run)

        # Fire-and-forget, same as the API's BackgroundTasks path
        # (app.api.routes.scans.create_scan_run) — a chat reply shouldn't
        # block on a full scan's wall-clock time.
        import asyncio

        asyncio.create_task(execute_scan_run(scan_run.id))

        return f'Scan started for "{project_name}" (scan_run_id={scan_run.id}).'

    async def _status(self, project_name: str) -> str:
        project = await self._find_project(project_name)
        if project is None:
            return f'No project named "{project_name}" found.'

        result = await self._session.execute(
            select(ScanRun)
            .join(Version, ScanRun.version_id == Version.id)
            .where(Version.project_id == project.id)
            .order_by(ScanRun.id.desc())
            .limit(1)
        )
        scan_run = result.scalar_one_or_none()
        if scan_run is None:
            return f'Project "{project_name}" has no scan runs yet.'

        return f'Latest scan for "{project_name}": {scan_run.status} (scan_run_id={scan_run.id}).'

    async def _new_project(self, url: str) -> str:
        project = Project(org_id=self._user.org_id, name=url, created_by=self._user.id)
        self._session.add(project)
        await self._session.commit()
        await self._session.refresh(project)

        settings = get_settings()
        deep_link = f"{settings.frontend_origin}/projects/{project.id}"
        return (
            f'Created project shell for {url}. Finish setup (scope, target, '
            f"credentials) in the Verdikt web app: {deep_link}"
        )
