"""
Agent-facing HTTP API at /api/v1/agent/*.

Bypasses oauth2-proxy OIDC via skip_auth_routes; authenticates independently
with a bearer token issued during enrolment. Also serves the bootstrap
install script rendered from a Jinja template.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import uuid
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Path as PathParam, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from db import sha256, utcnow
from schemas import (
    AttackEvent,
    CommandAck,
    EnrolRequest,
    EnrolResponse,
    EventBatch,
    HeartbeatRequest,
    HeartbeatResponse,
    Command,
)
import es_sink

log = logging.getLogger("honeypot-mgmt.agent")

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])

TEMPLATES_DIR = Path(__file__).parent / "templates"
_templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Constants derived from plan's skip_auth_routes regexes.
_ENROL_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")
_ARTEFACT_NAME_RE = re.compile(r"^[a-z0-9_.-]+$")

AGENT_BUNDLE_PATH = Path("/opt/honeypot-mgmt/agent-bundle/agent.tar.gz")
HEARTBEAT_INTERVAL_SEC = 30


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

async def current_node(
    request: Request,
    authorization: str = Header(default=""),
) -> dict[str, Any]:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="missing bearer token")
    db = request.app.state.db
    row = await (await db.execute(
        "SELECT id, label, revoked_at FROM nodes WHERE token_sha256 = ?",
        (sha256(token),),
    )).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="unknown token")
    if row["revoked_at"]:
        raise HTTPException(status_code=401, detail="revoked")
    return {"id": row["id"], "label": row["label"]}


def _client_ip(request: Request) -> str:
    # oauth2-proxy and ALB set X-Forwarded-For; agent requests skip oauth2-proxy
    # but still pass through host nginx which sets it too.
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


# ---------------------------------------------------------------------------
# POST /enrol — exchange enrolment token for agent token
# ---------------------------------------------------------------------------

@router.post("/enrol", response_model=EnrolResponse)
async def enrol(req: EnrolRequest, request: Request) -> EnrolResponse:
    db = request.app.state.db
    et_hash = sha256(req.enrolment_token)
    row = await (await db.execute(
        "SELECT label, expires_at, used_at FROM enrolment_tokens WHERE token_sha256 = ?",
        (et_hash,),
    )).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="unknown enrolment token")
    if row["used_at"]:
        raise HTTPException(status_code=409, detail="token already used")
    if utcnow() > row["expires_at"]:
        raise HTTPException(status_code=410, detail="token expired")

    label = row["label"]
    agent_token = secrets.token_urlsafe(33)  # ~44 chars
    token_hash = sha256(agent_token)
    now = utcnow()
    public_ip = _client_ip(request)

    await db.execute(
        """
        INSERT INTO nodes (
            label, hostname, os_id, os_version, agent_version,
            token_sha256, public_ip, enrolled_at, last_seen, last_status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(label) DO UPDATE SET
            hostname = excluded.hostname,
            os_id = excluded.os_id,
            os_version = excluded.os_version,
            agent_version = excluded.agent_version,
            token_sha256 = excluded.token_sha256,
            public_ip = excluded.public_ip,
            enrolled_at = excluded.enrolled_at,
            last_seen = excluded.last_seen,
            last_status = excluded.last_status,
            revoked_at = NULL
        """,
        (
            label, req.hostname, req.os_id, req.os_version, req.agent_version,
            token_hash, public_ip, now, now, "online", now,
        ),
    )
    await db.execute(
        "UPDATE enrolment_tokens SET used_at = ? WHERE token_sha256 = ?",
        (now, et_hash),
    )
    await db.commit()

    row = await (await db.execute(
        "SELECT id FROM nodes WHERE token_sha256 = ?", (token_hash,),
    )).fetchone()
    log.info("node enrolled: label=%s id=%s from=%s", label, row["id"], public_ip)
    return EnrolResponse(
        node_id=row["id"],
        label=label,
        agent_token=agent_token,
        heartbeat_interval_sec=HEARTBEAT_INTERVAL_SEC,
    )


# ---------------------------------------------------------------------------
# POST /heartbeat — ack pending, receive new commands
# ---------------------------------------------------------------------------

@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    req: HeartbeatRequest,
    request: Request,
    node: dict = Depends(current_node),
) -> HeartbeatResponse:
    db = request.app.state.db
    now = utcnow()
    public_ip = _client_ip(request)
    await db.execute(
        """
        UPDATE nodes SET last_seen = ?, last_status = ?, public_ip = ?, agent_version = ?
        WHERE id = ?
        """,
        (now, "online", public_ip, req.agent_version, node["id"]),
    )
    for a in req.acks:
        await db.execute(
            """
            UPDATE commands
               SET ack_at = ?, ack_status = ?, ack_output = ?
             WHERE id = ? AND node_id = ? AND ack_at IS NULL
            """,
            (now, a.status, a.output[:2000], a.command_id, node["id"]),
        )

    pending = await (await db.execute(
        """
        SELECT id, type, payload_json FROM commands
        WHERE node_id = ? AND ack_at IS NULL
        ORDER BY created_at ASC LIMIT 20
        """,
        (node["id"],),
    )).fetchall()
    commands: list[Command] = []
    for row in pending:
        payload = json.loads(row["payload_json"])
        payload["type"] = row["type"]
        try:
            commands.append(Command(id=row["id"], payload=payload))
        except Exception as exc:
            log.error("malformed queued command %s: %s", row["id"], exc)
            await db.execute(
                "UPDATE commands SET ack_at=?, ack_status='error', ack_output=? WHERE id=?",
                (now, f"validation: {exc}", row["id"]),
            )
            continue
        await db.execute(
            "UPDATE commands SET delivered_at = COALESCE(delivered_at, ?) WHERE id = ?",
            (now, row["id"]),
        )
    await db.commit()
    return HeartbeatResponse(commands=commands)


# ---------------------------------------------------------------------------
# POST /events — ship attack events to Elasticsearch
# ---------------------------------------------------------------------------

@router.post("/events")
async def ingest_events(
    batch: EventBatch,
    request: Request,
    node: dict = Depends(current_node),
) -> dict:
    db = request.app.state.db
    es: httpx.AsyncClient = request.app.state.http
    indexed, failed = await es_sink.index_events(batch.events, node["label"], es)
    await db.execute(
        "INSERT INTO events_ingest (node_id, received_at, count, indexed) VALUES (?, ?, ?, ?)",
        (node["id"], utcnow(), len(batch.events), indexed),
    )
    await db.commit()
    return {"received": len(batch.events), "indexed": indexed, "failed": failed}


# ---------------------------------------------------------------------------
# GET /bootstrap/{token} — render install.sh for the one-liner
# ---------------------------------------------------------------------------

@router.get("/bootstrap/{token}", response_class=PlainTextResponse)
async def bootstrap(request: Request, token: str = PathParam(...)):
    if not _ENROL_TOKEN_RE.match(token):
        raise HTTPException(status_code=400, detail="invalid token format")
    db = request.app.state.db
    row = await (await db.execute(
        "SELECT label, expires_at, used_at FROM enrolment_tokens WHERE token_sha256 = ?",
        (sha256(token),),
    )).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="unknown enrolment token")
    if row["used_at"]:
        raise HTTPException(status_code=409, detail="token already used")
    if utcnow() > row["expires_at"]:
        raise HTTPException(status_code=410, detail="token expired")

    server_url = os.environ.get("TPOT_FQDN", "")
    if server_url and not server_url.startswith("http"):
        server_url = f"https://{server_url}"
    tpl = _templates.get_template("install.sh.j2")
    body = tpl.render(
        enrolment_token=token,
        server_url=server_url or f"{request.url.scheme}://{request.url.netloc}",
        node_label=row["label"],
    )
    return PlainTextResponse(
        body,
        media_type="text/x-shellscript",
        headers={"Cache-Control": "no-store"},
    )


# ---------------------------------------------------------------------------
# GET /artefacts/{name} — serve agent.tar.gz etc.
# ---------------------------------------------------------------------------

@router.get("/artefacts/{name}")
async def artefact(name: str):
    if not _ARTEFACT_NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="invalid name")
    path = AGENT_BUNDLE_PATH.parent / name
    # Prevent traversal; resolved path must stay under parent.
    try:
        resolved = path.resolve()
        resolved.relative_to(AGENT_BUNDLE_PATH.parent.resolve())
    except (ValueError, OSError):
        raise HTTPException(status_code=400, detail="invalid path")
    if not resolved.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(str(resolved), media_type="application/octet-stream")


# ---------------------------------------------------------------------------
# Internal helpers (used by /manage UI routes)
# ---------------------------------------------------------------------------

async def create_enrolment_token(db, label: str, created_by: str, ttl_sec: int = 900) -> str:
    """Return the plaintext token (shown once to the admin)."""
    from datetime import datetime, timedelta, timezone
    token = secrets.token_urlsafe(16)  # 22 chars
    expires = (datetime.now(timezone.utc) + timedelta(seconds=ttl_sec)).isoformat(timespec="seconds")
    await db.execute(
        "INSERT INTO enrolment_tokens (token_sha256, label, expires_at, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
        (sha256(token), label, expires, utcnow(), created_by),
    )
    await db.commit()
    return token


async def queue_command(
    db,
    node_id: int,
    cmd_type: str,
    payload: dict,
    created_by: str,
) -> str:
    cid = str(uuid.uuid4())
    # Strip the 'type' field from payload_json since it's stored in its own column.
    payload = {k: v for k, v in payload.items() if k != "type"}
    await db.execute(
        "INSERT INTO commands (id, node_id, type, payload_json, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
        (cid, node_id, cmd_type, json.dumps(payload), utcnow(), created_by),
    )
    await db.commit()
    return cid
