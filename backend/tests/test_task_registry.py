import asyncio
import uuid

import pytest

from app.agents import task_registry


async def test_cancel_returns_false_for_unknown_scan_run():
    assert task_registry.cancel(uuid.uuid4()) is False


async def test_cancel_stops_a_registered_task():
    started = asyncio.Event()

    async def _forever():
        started.set()
        await asyncio.sleep(10)

    scan_run_id = uuid.uuid4()
    task = asyncio.create_task(_forever())
    task_registry.register(scan_run_id, task)
    await started.wait()

    assert task_registry.cancel(scan_run_id) is True

    with pytest.raises(asyncio.CancelledError):
        await task

    assert task.cancelled()


async def test_a_task_that_already_finished_is_not_reported_as_cancellable():
    scan_run_id = uuid.uuid4()
    task = asyncio.create_task(asyncio.sleep(0))
    task_registry.register(scan_run_id, task)
    await task

    assert task_registry.cancel(scan_run_id) is False
