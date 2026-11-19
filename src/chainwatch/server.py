import json
import sqlite3
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .analysis import analyze
from .changes import compare
from .cli import DEMO
from .inputs import MAX_TOTAL, local_files, upload_files
from .parsers import build_inventory
from .reports import comparison_text, scan_text

WEB = Path(__file__).with_name("web")
MAX_BODY = MAX_TOTAL * 12
MAX_STORED = 8 * 1024 * 1024


def connection(path: Path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    return db


def save(path: Path, report: dict) -> int | None:
    serialized = json.dumps(report, ensure_ascii=True)
    if len(serialized) > MAX_STORED:
        return None
    with closing(connection(path)) as db, db:
        cur = db.execute(
            "INSERT INTO scans (name, score, level, report) VALUES (?, ?, ?, ?)",
            (report["project"], report["summary"]["score"], report["summary"]["level"], serialized),
        )
        db.execute("DELETE FROM scans WHERE id IN (SELECT id FROM scans ORDER BY id DESC LIMIT -1 OFFSET 20)")
        return cur.lastrowid


async def request_payload(request: Request) -> dict:
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise HTTPException(415, "Expected application/json.")
    origin = request.headers.get("origin")
    if origin and origin != f"http://{request.headers.get('host')}":
        raise HTTPException(403, "Upload must come from the local dashboard.")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > (MAX_BODY if request.url.path == "/api/compare" else MAX_BODY // 2):
            raise HTTPException(413, "Manifest upload exceeds the request size limit.")
        body.extend(chunk)
    try:
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError
    except (ValueError, RecursionError):
        raise HTTPException(400, "Expected a valid JSON object.") from None
    return data


def project(data: dict, default: str):
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        name = default
    name = "".join(c for c in name if c.isprintable()).strip()[:120] or default
    return build_inventory(name, upload_files(data.get("files")))


def create_app(database: Path) -> FastAPI:
    with closing(connection(database)) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, score INTEGER NOT NULL,
            level TEXT NOT NULL, report TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
    app = FastAPI(title="ChainWatch", docs_url=None, redoc_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        return FileResponse(WEB / "index.html")

    @app.get("/assets/{asset}")
    def static(asset: str):
        if asset not in {"app.js", "styles.css"}:
            raise HTTPException(404)
        return FileResponse(WEB / asset)

    @app.get("/api/demo")
    def demo():
        before = build_inventory("Before", *local_files(DEMO / "before"))
        after = build_inventory("Northstar Store", *local_files(DEMO / "after"))
        return {"report": analyze(after), "comparison": compare(before, after)}

    @app.post("/api/scan")
    async def scan(request: Request):
        data = await request_payload(request)
        try:
            inv = await run_in_threadpool(project, data, "Local project")
        except ValueError as error:
            raise HTTPException(400, str(error)) from None
        report = await run_in_threadpool(analyze, inv, online=data.get("online") is True)
        report_id = await run_in_threadpool(save, database, report)
        return {"id": report_id, "report": report}

    @app.post("/api/compare")
    async def compare_upload(request: Request):
        data = await request_payload(request)

        def run():
            before, after = data.get("before"), data.get("after")
            if not isinstance(before, dict) or not isinstance(after, dict):
                raise ValueError("Choose both a before and an after project.")
            return compare(project(before, "Before"), project(after, "After"))

        try:
            return await run_in_threadpool(run)
        except ValueError as error:
            raise HTTPException(400, str(error)) from None

    @app.get("/api/history")
    def history():
        with closing(connection(database)) as db:
            return [dict(row) for row in db.execute(
                "SELECT id, name, score, level, created_at FROM scans ORDER BY id DESC LIMIT 20"
            )]

    @app.get("/api/history/{scan_id}")
    def previous(scan_id: int):
        with closing(connection(database)) as db:
            row = db.execute("SELECT report FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Scan history entry not found.")
        return json.loads(row["report"])

    @app.post("/api/export/{kind}")
    async def export(kind: str, request: Request):
        renderers = {"scan": scan_text, "comparison": comparison_text}
        if kind not in renderers:
            raise HTTPException(404)
        data = await request_payload(request)
        try:
            content = await run_in_threadpool(renderers[kind], data)
        except (AttributeError, KeyError, TypeError):
            raise HTTPException(400, "Invalid report.") from None
        return PlainTextResponse(content)

    return app
