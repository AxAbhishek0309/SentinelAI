"""
In-memory scan state store.

Holds the live state for every running/completed scan.
SSE consumers poll this store for status updates.

In a production deployment this would be backed by Redis.
For now, plain Python dicts with asyncio locks.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, UTC
from typing import Any
from uuid import uuid4

from models import ScanLogEntry, ScanRequest, ScanStatus, SecurityReport


class ScanState:
    """Mutable state object for a single scan."""

    def __init__(self, scan_id: str, request: ScanRequest) -> None:
        self.scan_id = scan_id
        self.request = request
        self.status: ScanStatus = ScanStatus.queued
        self.progress: int = 0
        self.current_step: str = "Queued"
        self.logs: list[dict[str, Any]] = []
        self.report: SecurityReport | None = None
        self.error: str | None = None
        self._lock = asyncio.Lock()
        self._waiters: list[asyncio.Event] = []

    # Status progression map — progress %
    _PROGRESS = {
        ScanStatus.queued: 0,
        ScanStatus.initializing: 5,
        ScanStatus.launching_browser: 12,
        ScanStatus.collecting_requests: 25,
        ScanStatus.exploring_pages: 45,
        ScanStatus.analyzing_javascript: 60,
        ScanStatus.inspecting_headers: 70,
        ScanStatus.checking_cookies: 78,
        ScanStatus.finding_secrets: 86,
        ScanStatus.generating_report: 93,
        ScanStatus.completed: 100,
        ScanStatus.failed: 100,
        ScanStatus.cancelled: 100,
    }

    async def transition(self, status: ScanStatus, step: str) -> None:
        async with self._lock:
            self.status = status
            self.progress = self._PROGRESS.get(status, self.progress)
            self.current_step = step
        await self.log("info", step)
        self._notify()

    async def log(self, level: str, message: str) -> None:
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "level": level,
            "message": message,
        }
        async with self._lock:
            self.logs.append(entry)
        self._notify()

    async def complete(self, report: SecurityReport) -> None:
        async with self._lock:
            self.status = ScanStatus.completed
            self.progress = 100
            self.current_step = "Scan complete"
            self.report = report
        await self.log("ok", f"Scan completed — score {report.score}/100 grade {report.grade}")
        self._notify()

    async def fail(self, error: str) -> None:
        async with self._lock:
            self.status = ScanStatus.failed
            self.progress = 100
            self.current_step = "Scan failed"
            self.error = error
        await self.log("error", f"Scan failed: {error}")
        self._notify()

    async def cancel(self) -> None:
        async with self._lock:
            self.status = ScanStatus.cancelled
            self.current_step = "Cancelled"
        await self.log("warn", "Scan cancelled")
        self._notify()

    def snapshot(self) -> dict[str, Any]:
        """Thread-safe dict snapshot for SSE serialisation."""
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "progress": self.progress,
            "current_step": self.current_step,
            "logs": list(self.logs),
            "report": self.report.model_dump(mode="json") if self.report else None,
            "error": self.error,
        }

    # --- SSE notification helpers ---

    def _notify(self) -> None:
        for ev in list(self._waiters):
            ev.set()

    def subscribe(self) -> asyncio.Event:
        ev = asyncio.Event()
        self._waiters.append(ev)
        return ev

    def unsubscribe(self, ev: asyncio.Event) -> None:
        try:
            self._waiters.remove(ev)
        except ValueError:
            pass


class ScanStore:
    """Global registry of ScanState objects."""

    def __init__(self) -> None:
        self._scans: dict[str, ScanState] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    def create(self, request: ScanRequest) -> ScanState:
        scan_id = uuid4().hex
        state = ScanState(scan_id=scan_id, request=request)
        self._scans[scan_id] = state
        return state

    def get(self, scan_id: str) -> ScanState | None:
        return self._scans.get(scan_id)

    def register_task(self, scan_id: str, task: asyncio.Task) -> None:
        self._tasks[scan_id] = task

    def cancel(self, scan_id: str) -> bool:
        task = self._tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

    def all_scans(self) -> list[dict]:
        """Return lightweight summaries for the dashboard."""
        summaries = []
        for state in reversed(list(self._scans.values())):
            summaries.append({
                "scan_id": state.scan_id,
                "url": state.request.url,
                "status": state.status,
                "progress": state.progress,
                "score": state.report.score if state.report else None,
                "grade": state.report.grade if state.report else None,
                "critical_count": state.report.critical_count if state.report else 0,
                "high_count": state.report.high_count if state.report else 0,
                "completed_at": state.report.completed_at.isoformat() if state.report else None,
                "duration_seconds": state.report.duration_seconds if state.report else None,
            })
        return summaries


# Singleton — imported by the FastAPI app
scan_store = ScanStore()
