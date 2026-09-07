"""Tracks the real asyncio.Task backing each in-flight scan/retest run,
so a cancel request can actually reach it. FastAPI's own BackgroundTasks
is fire-and-forget by design — it gives the caller no handle to the
scheduled coroutine, so there was previously no way to stop one short of
killing the whole process. Process-local only (an in-memory dict, not
persisted): a backend restart naturally drops every in-flight task
anyway, at which point there's nothing left to cancel — see
app.api.routes.scans' cancel endpoint for the fallback that handles that
case (just mark the row cancelled directly).
"""

import asyncio
import uuid

_running_tasks: dict[uuid.UUID, asyncio.Task] = {}


def register(scan_run_id: uuid.UUID, task: asyncio.Task) -> None:
    _running_tasks[scan_run_id] = task
    task.add_done_callback(lambda _t: _running_tasks.pop(scan_run_id, None))


def cancel(scan_run_id: uuid.UUID) -> bool:
    """Returns True if a running task was actually found and cancelled —
    the caller still needs to update the ScanRun row itself either way
    (this only reaches the in-process task, not the database)."""
    task = _running_tasks.get(scan_run_id)
    if task is None or task.done():
        return False
    task.cancel()
    return True
