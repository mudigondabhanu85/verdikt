"""Fetches captured screenshot evidence (Evidence.screenshot_refs — raw
ObjectStorageAdapter keys, see app.agents.xss's browser-proof capture)
for embedding directly into report exports (§8). A missing/unreadable
file is skipped, not fatal — a report should still render even if one
screenshot went missing from disk.
"""

import uuid

from app.models.finding import Finding
from app.storage.local_disk import get_object_storage


async def load_screenshots_by_finding(findings: list[Finding]) -> dict[uuid.UUID, list[bytes]]:
    storage = get_object_storage()
    result: dict[uuid.UUID, list[bytes]] = {}

    for finding in findings:
        evidence = finding.evidence
        if evidence is None or not evidence.screenshot_refs:
            continue
        images: list[bytes] = []
        for ref in evidence.screenshot_refs:
            try:
                images.append(await storage.get(ref))
            except OSError:
                continue
        if images:
            result[finding.id] = images

    return result
