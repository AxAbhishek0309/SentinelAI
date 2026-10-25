"""Shared Pydantic models — single source of truth for API contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, HttpUrl


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ScanStatus(str, Enum):
    queued = "queued"
    initializing = "initializing"
    launching_browser = "launching_browser"
    collecting_requests = "collecting_requests"
    exploring_pages = "exploring_pages"
    analyzing_javascript = "analyzing_javascript"
    inspecting_headers = "inspecting_headers"
    checking_cookies = "checking_cookies"
    finding_secrets = "finding_secrets"
    generating_report = "generating_report"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingCategory(str, Enum):
    secret = "secret"
    header = "header"
    cookie = "cookie"
    storage = "storage"
    network = "network"
    javascript = "javascript"
    tls = "tls"
    cors = "cors"
    csp = "csp"
    mixed_content = "mixed_content"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class NetworkRequest(BaseModel):
    method: str
    url: str
    status: int
    content_type: str | None = None
    duration_ms: int | None = None
    flagged: bool = False
    flag_reason: str | None = None


class CookieItem(BaseModel):
    name: str
    domain: str
    path: str
    secure: bool
    http_only: bool
    same_site: str | None
    session: bool
    issues: list[str] = Field(default_factory=list)


class StorageItem(BaseModel):
    key: str
    value_preview: str  # first 120 chars, never full value
    storage_type: str  # localStorage | sessionStorage | indexedDB
    flagged: bool = False
    flag_reason: str | None = None


class SecurityHeader(BaseModel):
    name: str
    present: bool
    value: str | None = None
    grade: str  # A / B / C / F
    recommendation: str | None = None


class SecretFinding(BaseModel):
    pattern_name: str
    location: str  # e.g. "localStorage:key", "bundle.js:L42", "network:/env.js"
    value_preview: str  # redacted preview — never store raw secret
    confidence: float  # 0–1 pattern-match confidence
    # Live verification results
    verified: bool = False
    verification_status: str = "unverified"   # unverified | confirmed | invalid | unverifiable | error
    verification_detail: str = ""
    account_info: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    location: str | None = None
    evidence: str | None = None
    recommendation: str
    references: list[str] = Field(default_factory=list)
    fixed: bool = False
    fix_location: str | None = None  # Exact file:line with context for fixing


class PageInfo(BaseModel):
    url: str
    title: str | None = None
    status: int | None = None
    visited: bool = True


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


class SecurityReport(BaseModel):
    scan_id: str
    target_url: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float

    # Score
    score: int  # 0–100
    grade: str  # A / B+ / B / C / D / F

    # Summary counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Data collected
    pages: list[PageInfo] = Field(default_factory=list)
    network_requests: list[NetworkRequest] = Field(default_factory=list)
    cookies: list[CookieItem] = Field(default_factory=list)
    storage_items: list[StorageItem] = Field(default_factory=list)
    security_headers: list[SecurityHeader] = Field(default_factory=list)
    secrets: list[SecretFinding] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    # AI output
    ai_summary: str | None = None
    ai_recommendations: list[str] = Field(default_factory=list)

    # Tech stack detected
    tech_stack: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# API request / response shapes
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    url: str


class ScanCreateResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    progress: int  # 0–100
    current_step: str
    logs: list[dict[str, Any]] = Field(default_factory=list)
    report: SecurityReport | None = None
    error: str | None = None


class ScanLogEntry(BaseModel):
    ts: datetime = Field(default_factory=datetime.utcnow)
    level: str  # info | warn | error | ok
    message: str
