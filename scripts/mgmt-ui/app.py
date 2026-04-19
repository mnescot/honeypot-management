#!/usr/bin/env python3
"""
T-Pot Management UI — FastAPI backend.

Served at /manage via host nginx proxy (no path stripping).
All routes carry the /manage prefix so nginx proxies without rewriting.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import yaml
import httpx
import docker as docker_sdk
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import db as db_module
from db import utcnow
from agent_api import router as agent_router, create_enrolment_token, queue_command

log = logging.getLogger("honeypot-mgmt")
logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PREFIX             = "/manage"
BEELZEBUB_CFG      = Path("/etc/beelzebub/configurations/beelzebub.yaml")
BEELZEBUB_SVC_DIR  = Path("/etc/beelzebub/configurations/services")
BEELZEBUB_SSH_CFG  = BEELZEBUB_SVC_DIR / "ssh.yaml"
BEELZEBUB_HTTP_CFG = BEELZEBUB_SVC_DIR / "http.yaml"
BEELZEBUB_SERVICE  = "beelzebub"
OLLAMA_API         = "http://127.0.0.1:11434"
TEMPLATES_DIR      = Path(__file__).parent / "templates"

# T-Pot infrastructure containers — shown separately from honeypots.
# "map_*" variants (map_data, map_web) are matched by prefix below.
INFRA_NAMES = frozenset({
    "nginx", "elasticsearch", "kibana", "logstash",
    "spiderfoot", "tanner_phpox", "tanner_redis", "tpotinit",
})


def _is_infra(name: str) -> bool:
    return name in INFRA_NAMES or name.startswith("map_")

app       = FastAPI(title="T-Pot Management UI", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Node health thresholds (seconds since last_seen).
ONLINE_MAX_SEC   = 90       # 3× heartbeat
DEGRADED_MAX_SEC = 300


def _status_from_last_seen(last_seen: str | None) -> str:
    if not last_seen:
        return "offline"
    try:
        ts = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except ValueError:
        return "offline"
    delta = (datetime.now(timezone.utc) - ts).total_seconds()
    if delta < ONLINE_MAX_SEC:
        return "online"
    if delta < DEGRADED_MAX_SEC:
        return "degraded"
    return "offline"


async def _recompute_statuses_loop(app: FastAPI) -> None:
    """Background task: refresh nodes.last_status so the dashboard and any
    external consumers see up-to-date health without needing per-request
    recomputation."""
    while True:
        try:
            db = app.state.db
            rows = await (await db.execute(
                "SELECT id, last_seen, revoked_at FROM nodes"
            )).fetchall()
            for r in rows:
                if r["revoked_at"]:
                    continue
                status = _status_from_last_seen(r["last_seen"])
                await db.execute(
                    "UPDATE nodes SET last_status = ? WHERE id = ?",
                    (status, r["id"]),
                )
            await db.commit()
        except Exception as exc:
            log.warning("status recompute failed: %s", exc)
        await asyncio.sleep(60)


@app.on_event("startup")
async def _startup() -> None:
    app.state.db = await db_module.connect()
    app.state.http = httpx.AsyncClient(timeout=10)
    app.state.bg_status = asyncio.create_task(_recompute_statuses_loop(app))
    log.info("startup complete")


@app.on_event("shutdown")
async def _shutdown() -> None:
    task = getattr(app.state, "bg_status", None)
    if task:
        task.cancel()
    http = getattr(app.state, "http", None)
    if http:
        await http.aclose()
    db = getattr(app.state, "db", None)
    if db:
        await db.close()


app.include_router(agent_router)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def landing(request: Request):
    """Fred Hutch landing page. Served by nginx at exact match `/`, routed
    here instead of the upstream T-Pot nginx. All other paths still flow to
    T-Pot nginx via the catch-all `location /` block."""
    return templates.TemplateResponse("landing.html", {"request": request})


def _fqdn_url() -> str:
    fqdn = os.environ.get("TPOT_FQDN", "")
    if not fqdn:
        return ""
    return fqdn if fqdn.startswith("http") else f"https://{fqdn}"


def _admin_user(request: Request) -> str:
    return (
        request.headers.get("x-forwarded-user")
        or request.headers.get("x-forwarded-email")
        or "admin"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _docker() -> docker_sdk.DockerClient:
    return docker_sdk.from_env(timeout=10)


def _docker_ok() -> tuple[bool, str]:
    """Return (True, "") if Docker daemon is reachable, else (False, error)."""
    try:
        docker_sdk.from_env(timeout=3).ping()
        return True, ""
    except Exception as exc:
        return False, str(exc)


def list_containers() -> list[dict[str, Any]]:
    try:
        rows = []
        for c in _docker().containers.list(all=True):
            try:
                image = c.image.tags[0] if c.image.tags else c.image.short_id
            except Exception:
                image = "<unknown>"
            rows.append({
                "name":    c.name,
                "image":   image,
                "status":  c.status,
                "running": c.status == "running",
                "infra":   _is_infra(c.name),
            })
        return sorted(rows, key=lambda x: (x["infra"], x["name"]))
    except Exception as exc:
        log.error("list_containers failed: %s", exc, exc_info=True)
        return []


def service_active(name: str) -> bool:
    return subprocess.run(
        ["systemctl", "is-active", "--quiet", name],
        capture_output=True,
    ).returncode == 0


async def ollama_models() -> list[dict]:
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(f"{OLLAMA_API}/api/tags")
            return r.json().get("models", [])
    except Exception:
        return []


def read_file(path: Path) -> str:
    return path.read_text() if path.exists() else f"# {path} does not exist yet\n"


# ---------------------------------------------------------------------------
# Routes — Dashboard
# ---------------------------------------------------------------------------

@app.get(PREFIX, response_class=HTMLResponse)
@app.get(PREFIX + "/", response_class=HTMLResponse)
async def dashboard(request: Request):
    # All Docker and subprocess calls are blocking I/O — run them in a thread
    # pool so they never block the uvicorn event loop.  Without this, a slow
    # Docker daemon (e.g. T-Pot is busy) causes every dashboard request to
    # stall the event loop for the full timeout, queuing up subsequent requests
    # until nginx gives up with 504.
    docker_ok, docker_err = await asyncio.to_thread(_docker_ok)
    containers, bzb, ollama_up, models = await asyncio.gather(
        asyncio.to_thread(list_containers) if docker_ok else asyncio.sleep(0, result=[]),
        asyncio.to_thread(service_active, BEELZEBUB_SERVICE),
        asyncio.to_thread(service_active, "ollama"),
        ollama_models(),
    )
    return templates.TemplateResponse("index.html", {
        "request":        request,
        "prefix":         PREFIX,
        "containers":     containers,
        "docker_ok":      docker_ok,
        "docker_err":     docker_err,
        "bzb_active":     bzb,
        "ollama_active":  ollama_up,
        "models":         models,
    })


# ---------------------------------------------------------------------------
# Routes — Container management
# ---------------------------------------------------------------------------

def _start_container(name: str) -> None:
    _docker().containers.get(name).start()


def _stop_container(name: str) -> None:
    _docker().containers.get(name).stop(timeout=10)


def _stop_all_honeypots() -> None:
    for c in _docker().containers.list():
        if not _is_infra(c.name):
            try:
                c.stop(timeout=10)
            except Exception:
                pass


def _start_all_honeypots() -> None:
    for c in _docker().containers.list(all=True):
        if not _is_infra(c.name) and c.status != "running":
            try:
                c.start()
            except Exception:
                pass


@app.post(PREFIX + "/container/{name}/start")
async def start_container(name: str):
    try:
        await asyncio.to_thread(_start_container, name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return RedirectResponse(PREFIX + "/", status_code=303)


@app.post(PREFIX + "/container/{name}/stop")
async def stop_container(name: str):
    try:
        await asyncio.to_thread(_stop_container, name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return RedirectResponse(PREFIX + "/", status_code=303)


@app.post(PREFIX + "/containers/stop-all")
async def stop_all_honeypots():
    """Stop every running honeypot container (leaves infra containers untouched)."""
    await asyncio.to_thread(_stop_all_honeypots)
    return RedirectResponse(PREFIX + "/", status_code=303)


@app.post(PREFIX + "/containers/start-all")
async def start_all_honeypots():
    """Start every stopped honeypot container."""
    await asyncio.to_thread(_start_all_honeypots)
    return RedirectResponse(PREFIX + "/", status_code=303)


# ---------------------------------------------------------------------------
# Routes — Beelzebub LLM honeypot
# ---------------------------------------------------------------------------

@app.get(PREFIX + "/beelzebub", response_class=HTMLResponse)
async def beelzebub_page(request: Request, saved: str = "", error: str = ""):
    active, main_cfg, ssh_cfg, http_cfg = await asyncio.gather(
        asyncio.to_thread(service_active, BEELZEBUB_SERVICE),
        asyncio.to_thread(read_file, BEELZEBUB_CFG),
        asyncio.to_thread(read_file, BEELZEBUB_SSH_CFG),
        asyncio.to_thread(read_file, BEELZEBUB_HTTP_CFG),
    )
    return templates.TemplateResponse("beelzebub.html", {
        "request":     request,
        "prefix":      PREFIX,
        "active":      active,
        "main_cfg":    main_cfg,
        "ssh_cfg":     ssh_cfg,
        "http_cfg":    http_cfg,
        "saved":       bool(saved),
        "error":       error,
    })


@app.post(PREFIX + "/beelzebub/save")
async def save_beelzebub(
    config_file: str = Form(...),
    config_body: str = Form(...),
):
    paths = {
        "main": BEELZEBUB_CFG,
        "ssh":  BEELZEBUB_SSH_CFG,
        "http": BEELZEBUB_HTTP_CFG,
    }
    target = paths.get(config_file)
    if not target:
        raise HTTPException(status_code=400, detail="Unknown config file")
    try:
        yaml.safe_load(config_body)
    except yaml.YAMLError as e:
        return RedirectResponse(
            f"{PREFIX}/beelzebub?error={str(e)[:80]}", status_code=303
        )
    def _write_and_restart() -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(config_body)
        subprocess.run(["systemctl", "restart", BEELZEBUB_SERVICE], check=False)
    await asyncio.to_thread(_write_and_restart)
    return RedirectResponse(PREFIX + "/beelzebub?saved=1", status_code=303)


@app.post(PREFIX + "/beelzebub/toggle")
async def toggle_beelzebub():
    def _toggle() -> None:
        action = "stop" if service_active(BEELZEBUB_SERVICE) else "start"
        subprocess.run(["systemctl", action, BEELZEBUB_SERVICE], check=False)
    await asyncio.to_thread(_toggle)
    return RedirectResponse(PREFIX + "/beelzebub", status_code=303)


# ---------------------------------------------------------------------------
# Routes — Ollama model management
# ---------------------------------------------------------------------------

@app.get(PREFIX + "/ollama", response_class=HTMLResponse)
async def ollama_page(request: Request, pulling: str = ""):
    active, models = await asyncio.gather(
        asyncio.to_thread(service_active, "ollama"),
        ollama_models(),
    )
    return templates.TemplateResponse("ollama.html", {
        "request":  request,
        "prefix":   PREFIX,
        "active":   active,
        "models":   models,
        "pulling":  bool(pulling),
    })


@app.post(PREFIX + "/ollama/pull")
async def pull_model(model: str = Form(...)):
    # Fire-and-forget; progress visible in journalctl -u ollama
    subprocess.Popen(
        ["ollama", "pull", model.strip()],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return RedirectResponse(PREFIX + "/ollama?pulling=1", status_code=303)


@app.post(PREFIX + "/ollama/delete")
async def delete_model(model: str = Form(...)):
    await asyncio.to_thread(subprocess.run, ["ollama", "rm", model.strip()], check=False)
    return RedirectResponse(PREFIX + "/ollama", status_code=303)


# ---------------------------------------------------------------------------
# Routes — Red team target guide
# ---------------------------------------------------------------------------

def _beelzebub_endpoints() -> list[dict[str, Any]]:
    """Parse every Beelzebub service YAML and return endpoint metadata."""
    endpoints = []
    if not BEELZEBUB_SVC_DIR.exists():
        return endpoints
    for cfg_path in sorted(BEELZEBUB_SVC_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(cfg_path.read_text()) or {}
        except yaml.YAMLError:
            continue
        protocol = str(data.get("protocol", "")).lower()
        address  = str(data.get("address", ""))
        port     = address.lstrip(":") if address.startswith(":") else address
        plugin   = data.get("plugin", {})
        instructions = str(plugin.get("instructions", "")).strip()
        endpoints.append({
            "file":         cfg_path.name,
            "protocol":     protocol,
            "port":         port,
            "description":  data.get("description", cfg_path.stem),
            "instructions": instructions[:120] + "…" if len(instructions) > 120 else instructions,
        })
    return endpoints


@app.get(PREFIX + "/redteam", response_class=HTMLResponse)
async def redteam_page(request: Request):
    endpoints = _beelzebub_endpoints()
    http_eps  = [e for e in endpoints if e["protocol"] == "http"]
    ssh_eps   = [e for e in endpoints if e["protocol"] == "ssh"]
    return templates.TemplateResponse("redteam.html", {
        "request":    request,
        "prefix":     PREFIX,
        "endpoints":  endpoints,
        "http_eps":   http_eps,
        "ssh_eps":    ssh_eps,
    })


# ---------------------------------------------------------------------------
# Routes — Remote nodes
# ---------------------------------------------------------------------------

def _node_view(row: dict) -> dict:
    status = _status_from_last_seen(row["last_seen"]) if not row["revoked_at"] else "revoked"
    return {**row, "status": status}


@app.get(PREFIX + "/nodes", response_class=HTMLResponse)
async def nodes_list(request: Request, token: str = "", label: str = ""):
    db = request.app.state.db
    rows = await (await db.execute(
        """SELECT id, label, hostname, public_ip, os_id, os_version,
                  agent_version, enrolled_at, last_seen, revoked_at
             FROM nodes ORDER BY revoked_at IS NOT NULL, label"""
    )).fetchall()
    nodes = [_node_view(dict(r)) for r in rows]
    return templates.TemplateResponse("nodes.html", {
        "request":     request,
        "prefix":      PREFIX,
        "nodes":       nodes,
        "server_url":  _fqdn_url() or str(request.base_url).rstrip("/"),
        "fresh_token": token or None,
        "fresh_label": label or None,
    })


@app.get(PREFIX + "/nodes/new", response_class=HTMLResponse)
async def nodes_new_form(request: Request):
    return templates.TemplateResponse("node_new.html", {
        "request":    request,
        "prefix":     PREFIX,
        "server_url": _fqdn_url() or str(request.base_url).rstrip("/"),
    })


@app.post(PREFIX + "/nodes/new")
async def nodes_new_submit(request: Request, label: str = Form(...)):
    label = label.strip().lower()
    if not label or len(label) > 32:
        raise HTTPException(status_code=400, detail="invalid label")
    db = request.app.state.db
    token = await create_enrolment_token(db, label, _admin_user(request))
    return RedirectResponse(
        f"{PREFIX}/nodes?token={token}&label={label}",
        status_code=303,
    )


@app.get(PREFIX + "/nodes/{node_id}", response_class=HTMLResponse)
async def node_detail(request: Request, node_id: int):
    db = request.app.state.db
    row = await (await db.execute(
        """SELECT id, label, hostname, public_ip, os_id, os_version,
                  agent_version, enrolled_at, last_seen, revoked_at
             FROM nodes WHERE id = ?""",
        (node_id,),
    )).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="unknown node")
    node = _node_view(dict(row))
    cmd_rows = await (await db.execute(
        """SELECT id, type, created_at, delivered_at, ack_at, ack_status, ack_output
             FROM commands WHERE node_id = ?
             ORDER BY created_at DESC LIMIT 50""",
        (node_id,),
    )).fetchall()
    return templates.TemplateResponse("node_detail.html", {
        "request":  request,
        "prefix":   PREFIX,
        "node":     node,
        "commands": [dict(c) for c in cmd_rows],
    })


async def _queue(db, node_id: int, cmd_type: str, payload: dict, user: str) -> str:
    # Verify node exists and isn't revoked.
    row = await (await db.execute(
        "SELECT revoked_at FROM nodes WHERE id = ?", (node_id,),
    )).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="unknown node")
    if row["revoked_at"]:
        raise HTTPException(status_code=409, detail="node revoked")
    return await queue_command(db, node_id, cmd_type, payload, user)


@app.post(PREFIX + "/nodes/{node_id}/deploy-beelzebub")
async def deploy_beelzebub(request: Request, node_id: int):
    await _queue(
        request.app.state.db, node_id,
        "install_beelzebub",
        {"image": "mariocandela/beelzebub:latest"},
        _admin_user(request),
    )
    return RedirectResponse(f"{PREFIX}/nodes/{node_id}", status_code=303)


@app.post(PREFIX + "/nodes/{node_id}/stop-beelzebub")
async def stop_beelzebub_remote(request: Request, node_id: int):
    await _queue(
        request.app.state.db, node_id,
        "stop_honeypot", {"name": "beelzebub"},
        _admin_user(request),
    )
    return RedirectResponse(f"{PREFIX}/nodes/{node_id}", status_code=303)


@app.post(PREFIX + "/nodes/{node_id}/ping")
async def ping_node(request: Request, node_id: int):
    await _queue(
        request.app.state.db, node_id,
        "ping", {}, _admin_user(request),
    )
    return RedirectResponse(f"{PREFIX}/nodes/{node_id}", status_code=303)


@app.post(PREFIX + "/nodes/{node_id}/revoke")
async def revoke_node(request: Request, node_id: int):
    db = request.app.state.db
    await db.execute(
        "UPDATE nodes SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        (utcnow(), node_id),
    )
    await db.commit()
    return RedirectResponse(f"{PREFIX}/nodes", status_code=303)
