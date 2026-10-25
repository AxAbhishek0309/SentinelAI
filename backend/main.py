"""
Sentinel AI — FastAPI backend

Routes:
  POST /api/scans              Start a new scan
  GET  /api/scans              List all scans (dashboard)
  GET  /api/scans/{id}         Get scan status + report
  GET  /api/scans/{id}/stream  SSE stream of live scan events
  DELETE /api/scans/{id}       Cancel a running scan
  GET  /api/health             Health check
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from config import settings
from models import ScanCreateResponse, ScanRequest, ScanStatus, ScanStatusResponse
from scanner.state import scan_store


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Warm up Playwright browser pool (optional — just validates install)
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
            await browser.close()
        print("✓ Playwright Chromium ready")
    except Exception as e:
        print(f"⚠ Playwright warmup failed: {e}")
    yield


app = FastAPI(
    title="Sentinel AI API",
    version="1.0.0",
    description="Real security scanning backend for Sentinel AI",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin, "http://localhost:3000", "http://localhost:5173", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@app.post("/api/scans", response_model=ScanCreateResponse, status_code=201)
async def start_scan(body: ScanRequest):
    """Validate URL and kick off a background scan."""
    url = body.url.strip()

    # Basic validation
    if not url:
        raise HTTPException(400, "URL is required")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")

    # Quick reachability pre-check
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.head(url)
            # Accept any HTTP response — even 4xx means it's reachable
    except httpx.ConnectError:
        raise HTTPException(422, f"Cannot connect to {url} — check the URL and try again")
    except httpx.TimeoutException:
        raise HTTPException(422, f"Connection to {url} timed out")
    except Exception as e:
        raise HTTPException(422, f"URL unreachable: {e}")

    state = scan_store.create(ScanRequest(url=url))

    # Launch scan in background
    from scanner.engine import run_scan
    task = asyncio.create_task(
        _run_with_timeout(state, settings.max_scan_duration_seconds)
    )
    scan_store.register_task(state.scan_id, task)

    return ScanCreateResponse(
        scan_id=state.scan_id,
        status=ScanStatus.queued,
        message="Scan started",
    )


async def _run_with_timeout(state, timeout_seconds: int):
    from scanner.engine import run_scan
    try:
        await asyncio.wait_for(run_scan(state), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        await state.fail(f"Scan exceeded {timeout_seconds}s timeout")
    except asyncio.CancelledError:
        await state.cancel()
    except Exception as exc:
        await state.fail(str(exc))


@app.get("/api/scans")
async def list_scans():
    """Return all scans (most recent first) for the dashboard."""
    return {"scans": scan_store.all_scans()}


@app.get("/api/scans/{scan_id}", response_model=ScanStatusResponse)
async def get_scan(scan_id: str):
    state = scan_store.get(scan_id)
    if not state:
        raise HTTPException(404, "Scan not found")
    snap = state.snapshot()
    return ScanStatusResponse(**snap)


@app.delete("/api/scans/{scan_id}", status_code=204)
async def cancel_scan(scan_id: str):
    state = scan_store.get(scan_id)
    if not state:
        raise HTTPException(404, "Scan not found")
    if state.status in (ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled):
        raise HTTPException(400, f"Scan already in terminal state: {state.status}")
    scan_store.cancel(scan_id)


# ---------------------------------------------------------------------------
# SSE stream
# ---------------------------------------------------------------------------

@app.get("/api/scans/{scan_id}/stream")
async def stream_scan(scan_id: str, request: Request):
    """
    Server-Sent Events stream.
    Sends a 'status' event on every state change until terminal.
    """
    state = scan_store.get(scan_id)
    if not state:
        raise HTTPException(404, "Scan not found")

    async def event_generator():
        terminal = {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled}

        # Send current state immediately
        yield _sse_event(state.snapshot())

        if state.status in terminal:
            return

        ev = state.subscribe()
        try:
            while True:
                # Wait for next update (with heartbeat every 15s)
                try:
                    await asyncio.wait_for(ev.wait(), timeout=15)
                except asyncio.TimeoutError:
                    # Send heartbeat comment so the connection stays alive
                    yield ": heartbeat\n\n"
                    continue

                # Check if client disconnected
                if await request.is_disconnected():
                    break

                snapshot = state.snapshot()
                yield _sse_event(snapshot)

                ev.clear()

                if snapshot["status"] in terminal:
                    break

        finally:
            state.unsubscribe(ev)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


def _sse_event(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


# ---------------------------------------------------------------------------
# PDF Report Generation
# ---------------------------------------------------------------------------

@app.get("/api/scans/{scan_id}/report.pdf")
async def generate_pdf_report(scan_id: str):
    """Generate and return a PDF report for the scan."""
    state = scan_store.get(scan_id)
    if not state:
        raise HTTPException(404, "Scan not found")
    
    snap = state.snapshot()
    report = snap.get("report")
    if not report:
        raise HTTPException(400, "Scan not completed yet or has no report")
    
    # Generate PDF
    from io import BytesIO
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=1*inch,
        bottomMargin=0.75*inch,
    )
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a202c'),
        spaceAfter=30,
        alignment=TA_CENTER,
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#2d3748'),
        spaceAfter=12,
        spaceBefore=20,
    )
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=10,
        leading=14,
    )
    
    story = []
    
    # Cover Page
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("Sentinel AI Security Report", title_style))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(f"<b>Target:</b> {report['target_url']}", body_style))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph(f"<b>Scan Date:</b> {report['started_at'][:10]}", body_style))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph(f"<b>Security Score:</b> {report['score']}/100 (Grade: {report['grade']})", body_style))
    story.append(Spacer(1, 0.3*inch))
    
    # Severity Summary Table
    summary_data = [
        ['Severity', 'Count'],
        ['Critical', str(report['critical_count'])],
        ['High', str(report['high_count'])],
        ['Medium', str(report['medium_count'])],
        ['Low', str(report['low_count'])],
        ['Info', str(report['info_count'])],
    ]
    summary_table = Table(summary_data, colWidths=[2*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f7fafc')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
    ]))
    story.append(summary_table)
    story.append(PageBreak())
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    story.append(Paragraph(report.get('ai_summary', 'No summary available.'), body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # AI Recommendations
    if report.get('ai_recommendations'):
        story.append(Paragraph("Key Recommendations", heading_style))
        for i, rec in enumerate(report['ai_recommendations'], 1):
            story.append(Paragraph(f"{i}. {rec}", body_style))
            story.append(Spacer(1, 0.05*inch))
    
    story.append(PageBreak())
    
    # Security Headers
    story.append(Paragraph("Security Headers Analysis", heading_style))
    if report.get('security_headers'):
        headers_data = [['Header', 'Present', 'Grade', 'Recommendation']]
        for h in report['security_headers'][:10]:  # Limit to 10
            headers_data.append([
                h['name'][:30],
                'Yes' if h['present'] else 'No',
                h.get('grade', 'N/A'),
                (h.get('recommendation', '')[:50] + '...') if h.get('recommendation') and len(h.get('recommendation', '')) > 50 else h.get('recommendation', 'None'),
            ])
        headers_table = Table(headers_data, colWidths=[2*inch, 0.8*inch, 0.7*inch, 2.5*inch])
        headers_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (1, 1), (2, -1), 'CENTER'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f7fafc')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(headers_table)
    else:
        story.append(Paragraph("No header analysis available.", body_style))
    
    story.append(PageBreak())
    
    # Findings
    story.append(Paragraph("Security Findings", heading_style))
    findings = report.get('findings', [])
    if findings:
        for i, finding in enumerate(findings[:20], 1):  # Limit to 20 findings
            severity = finding.get('severity', 'unknown').upper()
            severity_color = {
                'CRITICAL': colors.HexColor('#e53e3e'),
                'HIGH': colors.HexColor('#dd6b20'),
                'MEDIUM': colors.HexColor('#d69e2e'),
                'LOW': colors.HexColor('#38a169'),
                'INFO': colors.HexColor('#3182ce'),
            }.get(severity, colors.gray)
            
            finding_content = [
                Paragraph(f"<b>{i}. [{severity}] {finding['title']}</b>", body_style),
                Spacer(1, 0.05*inch),
                Paragraph(f"<b>Description:</b> {finding.get('description', 'N/A')[:200]}{'...' if len(finding.get('description', '')) > 200 else ''}", body_style),
                Spacer(1, 0.05*inch),
                Paragraph(f"<b>Recommendation:</b> {finding.get('recommendation', 'N/A')[:200]}{'...' if len(finding.get('recommendation', '')) > 200 else ''}", body_style),
            ]
            if finding.get('fix_location'):
                finding_content.append(Spacer(1, 0.05*inch))
                finding_content.append(Paragraph(f"<b>Fix Location:</b> {finding['fix_location'][:150]}{'...' if len(finding['fix_location']) > 150 else ''}", body_style))
            
            story.append(KeepTogether(finding_content))
            story.append(Spacer(1, 0.15*inch))
    else:
        story.append(Paragraph("No findings to report.", body_style))
    
    story.append(PageBreak())
    
    # Network Summary
    story.append(Paragraph("Network Requests Summary", heading_style))
    story.append(Paragraph(f"Total requests captured: {len(report.get('network_requests', []))}", body_style))
    story.append(Paragraph(f"Pages scanned: {len(report.get('pages', []))}", body_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Tech Stack
    if report.get('tech_stack'):
        story.append(Paragraph("Detected Technology Stack", heading_style))
        story.append(Paragraph(", ".join(report['tech_stack']), body_style))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    
    from fastapi.responses import Response
    return Response(
        content=buffer.read(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=sentinel-report-{scan_id}.pdf"
        },
    )

