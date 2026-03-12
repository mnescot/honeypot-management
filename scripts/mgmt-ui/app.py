#!/usr/bin/env python3
"""
T-Pot Management UI — FastAPI backend.

Served at /manage via host nginx proxy (no path stripping).
All routes carry the /manage prefix so nginx proxies without rewriting.
"""
from __future__ import annotations

import logging
import subprocess
import yaml
import httpx
import docker as docker_sdk
from pathlib import Path
from typing import Any
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _docker() -> docker_sdk.DockerClient:
    return docker_sdk.from_env()


def _docker_ok() -> tuple[bool, str]:
    """Return (True, "") if Docker daemon is reachable, else (False, error)."""
    try:
        _docker().ping()
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
    docker_ok, docker_err = _docker_ok()
    return templates.TemplateResponse("index.html", {
        "request":        request,
        "prefix":         PREFIX,
        "containers":     list_containers() if docker_ok else [],
        "docker_ok":      docker_ok,
        "docker_err":     docker_err,
        "bzb_active":     service_active(BEELZEBUB_SERVICE),
        "ollama_active":  service_active("ollama"),
        "models":         await ollama_models(),
    })


# ---------------------------------------------------------------------------
# Routes — Container management
# ---------------------------------------------------------------------------

@app.post(PREFIX + "/container/{name}/start")
async def start_container(name: str):
    try:
        _docker().containers.get(name).start()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return RedirectResponse(PREFIX + "/", status_code=303)


@app.post(PREFIX + "/container/{name}/stop")
async def stop_container(name: str):
    try:
        _docker().containers.get(name).stop(timeout=10)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return RedirectResponse(PREFIX + "/", status_code=303)


@app.post(PREFIX + "/containers/stop-all")
async def stop_all_honeypots():
    """Stop every running honeypot container (leaves infra containers untouched)."""
    client = _docker()
    for c in client.containers.list():
        if not _is_infra(c.name):
            try:
                c.stop(timeout=10)
            except Exception:
                pass
    return RedirectResponse(PREFIX + "/", status_code=303)


@app.post(PREFIX + "/containers/start-all")
async def start_all_honeypots():
    """Start every stopped honeypot container."""
    client = _docker()
    for c in client.containers.list(all=True):
        if not _is_infra(c.name) and c.status != "running":
            try:
                c.start()
            except Exception:
                pass
    return RedirectResponse(PREFIX + "/", status_code=303)


# ---------------------------------------------------------------------------
# Routes — Beelzebub LLM honeypot
# ---------------------------------------------------------------------------

@app.get(PREFIX + "/beelzebub", response_class=HTMLResponse)
async def beelzebub_page(request: Request, saved: str = "", error: str = ""):
    return templates.TemplateResponse("beelzebub.html", {
        "request":     request,
        "prefix":      PREFIX,
        "active":      service_active(BEELZEBUB_SERVICE),
        "main_cfg":    read_file(BEELZEBUB_CFG),
        "ssh_cfg":     read_file(BEELZEBUB_SSH_CFG),
        "http_cfg":    read_file(BEELZEBUB_HTTP_CFG),
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
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(config_body)
    subprocess.run(["systemctl", "restart", BEELZEBUB_SERVICE], check=False)
    return RedirectResponse(PREFIX + "/beelzebub?saved=1", status_code=303)


@app.post(PREFIX + "/beelzebub/toggle")
async def toggle_beelzebub():
    action = "stop" if service_active(BEELZEBUB_SERVICE) else "start"
    subprocess.run(["systemctl", action, BEELZEBUB_SERVICE], check=False)
    return RedirectResponse(PREFIX + "/beelzebub", status_code=303)


# ---------------------------------------------------------------------------
# Routes — Ollama model management
# ---------------------------------------------------------------------------

@app.get(PREFIX + "/ollama", response_class=HTMLResponse)
async def ollama_page(request: Request, pulling: str = ""):
    return templates.TemplateResponse("ollama.html", {
        "request":  request,
        "prefix":   PREFIX,
        "active":   service_active("ollama"),
        "models":   await ollama_models(),
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
    subprocess.run(["ollama", "rm", model.strip()], check=False)
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
