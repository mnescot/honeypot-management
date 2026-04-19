#!/usr/bin/env python3
"""
Honeypot remote-node agent.

Runs as systemd service on a remote Linux host. Uses outbound HTTPS only to
poll the central management server, execute queued commands, and ship
attack events. On 401 (revoked token) the agent stops local honeypots and
exits cleanly.

Config: /etc/honeypot-agent/config.yaml
Token:  /etc/honeypot-agent/token (0600)
State:  /var/lib/honeypot-agent/
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml

AGENT_VERSION = "1.0.0"

log = logging.getLogger("honeypot-agent")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


# ---------------------------------------------------------------------------
# Config + token management
# ---------------------------------------------------------------------------

@dataclass
class Config:
    server_url: str
    node_label: str
    enrolment_token: str
    token_file: Path
    state_dir: Path
    heartbeat_interval_sec: int = 30

    @classmethod
    def load(cls, path: Path) -> "Config":
        data = yaml.safe_load(path.read_text())
        return cls(
            server_url=data["server_url"].rstrip("/"),
            node_label=data["node_label"],
            enrolment_token=data.get("enrolment_token", ""),
            token_file=Path(data["token_file"]),
            state_dir=Path(data["state_dir"]),
            heartbeat_interval_sec=int(data.get("heartbeat_interval_sec", 30)),
        )


def read_token(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text().strip()


def write_token(path: Path, token: str) -> None:
    path.write_text(token)
    os.chmod(path, 0o600)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

BEELZEBUB_CONTAINER = "beelzebub"
BEELZEBUB_CONFIG_DIR = Path("/etc/beelzebub")


def _run(cmd: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s"
    out = (r.stdout + r.stderr).strip()
    return r.returncode, out[-1800:]


def handle_ping(payload: dict) -> tuple[str, str]:
    return "ok", "pong"


def handle_install_beelzebub(payload: dict) -> tuple[str, str]:
    image = payload.get("image", "mariocandela/beelzebub:latest")
    BEELZEBUB_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    (BEELZEBUB_CONFIG_DIR / "services").mkdir(exist_ok=True)
    rc, out = _run(["docker", "pull", image])
    if rc != 0:
        return "error", f"docker pull failed: {out}"
    # Remove any previous container (idempotent).
    _run(["docker", "rm", "-f", BEELZEBUB_CONTAINER])
    rc, out = _run([
        "docker", "run", "-d",
        "--name", BEELZEBUB_CONTAINER,
        "--restart", "unless-stopped",
        "-p", "2222:2222",
        "-p", "8888:8080",
        "-v", f"{BEELZEBUB_CONFIG_DIR}:/configurations:ro",
        image,
    ])
    if rc != 0:
        return "error", f"docker run failed: {out}"
    return "ok", f"installed {image}"


def handle_apply_beelzebub_config(payload: dict) -> tuple[str, str]:
    main = payload.get("main_yaml", "")
    ssh  = payload.get("ssh_yaml", "")
    http = payload.get("http_yaml", "")
    BEELZEBUB_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    (BEELZEBUB_CONFIG_DIR / "services").mkdir(exist_ok=True)
    if main:
        (BEELZEBUB_CONFIG_DIR / "beelzebub.yaml").write_text(main)
    if ssh:
        (BEELZEBUB_CONFIG_DIR / "services" / "ssh.yaml").write_text(ssh)
    if http:
        (BEELZEBUB_CONFIG_DIR / "services" / "http.yaml").write_text(http)
    rc, out = _run(["docker", "restart", BEELZEBUB_CONTAINER])
    if rc != 0:
        return "error", f"restart failed: {out}"
    return "ok", "configs applied"


def handle_start_honeypot(payload: dict) -> tuple[str, str]:
    name = payload.get("name", BEELZEBUB_CONTAINER)
    rc, out = _run(["docker", "start", name])
    return ("ok" if rc == 0 else "error"), out or f"started {name}"


def handle_stop_honeypot(payload: dict) -> tuple[str, str]:
    name = payload.get("name", BEELZEBUB_CONTAINER)
    rc, out = _run(["docker", "stop", name])
    return ("ok" if rc == 0 else "error"), out or f"stopped {name}"


def handle_remove_honeypot(payload: dict) -> tuple[str, str]:
    name = payload.get("name", BEELZEBUB_CONTAINER)
    rc, out = _run(["docker", "rm", "-f", name])
    return ("ok" if rc == 0 else "error"), out or f"removed {name}"


def handle_upgrade_agent(payload: dict) -> tuple[str, str]:
    # Deferred to a follow-up — left as a no-op handler so the command isn't
    # reported as "unsupported" once queued during rollout.
    return "ok", "upgrade_agent is a no-op in this version"


HANDLERS = {
    "ping":                    handle_ping,
    "install_beelzebub":       handle_install_beelzebub,
    "apply_beelzebub_config":  handle_apply_beelzebub_config,
    "start_honeypot":          handle_start_honeypot,
    "stop_honeypot":           handle_stop_honeypot,
    "remove_honeypot":         handle_remove_honeypot,
    "upgrade_agent":           handle_upgrade_agent,
}


# ---------------------------------------------------------------------------
# Seen-commands cache (idempotency)
# ---------------------------------------------------------------------------

class SeenCommands:
    def __init__(self, path: Path, limit: int = 500):
        self.path = path
        self.limit = limit
        self.items: dict[str, dict] = {}
        self.order: deque[str] = deque()
        if path.exists():
            try:
                data = json.loads(path.read_text())
                for entry in data:
                    self.items[entry["id"]] = entry
                    self.order.append(entry["id"])
            except (ValueError, OSError) as exc:
                log.warning("failed to load seen-commands: %s", exc)

    def has(self, cid: str) -> bool:
        return cid in self.items

    def record(self, cid: str, status: str, output: str) -> None:
        if cid in self.items:
            return
        self.items[cid] = {"id": cid, "status": status, "output": output}
        self.order.append(cid)
        while len(self.order) > self.limit:
            old = self.order.popleft()
            self.items.pop(old, None)
        try:
            self.path.write_text(json.dumps(list(self.items.values())))
        except OSError as exc:
            log.warning("failed to persist seen-commands: %s", exc)

    def result_for(self, cid: str) -> dict | None:
        return self.items.get(cid)


# ---------------------------------------------------------------------------
# Event tailer — pulls attacks from Beelzebub container logs
# ---------------------------------------------------------------------------

# Beelzebub emits JSON per line to stdout. Fields vary per protocol but
# typically include: source_ip, remote_addr, protocol, user, password, command.
_JSON_LINE_RE = re.compile(r"^\{.*\}$")


class EventTailer(threading.Thread):
    def __init__(self, agent: "Agent"):
        super().__init__(daemon=True, name="event-tailer")
        self.agent = agent
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tail_once()
            except Exception as exc:
                log.warning("tailer error: %s", exc)
                time.sleep(5)
        log.info("event tailer stopped")

    def _tail_once(self) -> None:
        if shutil.which("docker") is None:
            time.sleep(10)
            return
        # Only tail if the container is running.
        rc, out = _run(["docker", "inspect", "-f", "{{.State.Running}}", BEELZEBUB_CONTAINER], timeout=5)
        if rc != 0 or out.strip() != "true":
            time.sleep(10)
            return
        proc = subprocess.Popen(
            ["docker", "logs", "-f", "--tail", "0", BEELZEBUB_CONTAINER],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        assert proc.stdout is not None
        batch: list[dict] = []
        last_flush = time.time()
        try:
            for line in proc.stdout:
                if self._stop.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                ev = self._parse(line)
                if ev:
                    batch.append(ev)
                if batch and (len(batch) >= 50 or time.time() - last_flush > 5):
                    self.agent.ship_events(batch)
                    batch = []
                    last_flush = time.time()
        finally:
            proc.terminate()
            if batch:
                self.agent.ship_events(batch)

    def _parse(self, line: str) -> dict | None:
        if not _JSON_LINE_RE.match(line):
            return None
        try:
            d = json.loads(line)
        except ValueError:
            return None
        src = str(d.get("remote_addr") or d.get("source_ip") or d.get("SourceIp") or "")
        if ":" in src:
            src_ip, _, src_port = src.rpartition(":")
            try:
                src_port_n = int(src_port)
            except ValueError:
                src_port_n = 0
        else:
            src_ip, src_port_n = src, 0
        proto = str(d.get("protocol") or d.get("Protocol") or "").lower()
        dst_port = 2222 if proto == "ssh" else (8888 if proto == "http" else 0)
        return {
            "ts":        d.get("timestamp") or d.get("@timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "src_ip":    src_ip,
            "src_port":  src_port_n,
            "dst_port":  dst_port,
            "protocol":  proto,
            "honeypot":  "beelzebub",
            "username":  str(d.get("user") or d.get("User") or ""),
            "password":  str(d.get("password") or d.get("Password") or ""),
            "command":   str(d.get("command") or d.get("Command") or ""),
            "raw":       line[:2000],
        }


# ---------------------------------------------------------------------------
# Metrics collection
# ---------------------------------------------------------------------------

def _mem_used_pct() -> float:
    try:
        with open("/proc/meminfo") as f:
            info = {}
            for line in f:
                k, _, v = line.partition(":")
                info[k.strip()] = int(v.strip().split()[0])
        total = info.get("MemTotal", 1)
        avail = info.get("MemAvailable", total)
        return round((1 - avail / total) * 100, 1)
    except OSError:
        return 0.0


def _disk_used_pct(path: str = "/") -> float:
    try:
        st = os.statvfs(path)
        used = (st.f_blocks - st.f_bavail) / st.f_blocks * 100
        return round(used, 1)
    except OSError:
        return 0.0


def _load_1() -> float:
    try:
        return round(os.getloadavg()[0], 2)
    except OSError:
        return 0.0


def _uptime_sec() -> int:
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except OSError:
        return 0


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    rc, _ = _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=5)
    return rc == 0


def _honeypots_running() -> int:
    rc, out = _run(
        ["docker", "ps", "--filter", f"name={BEELZEBUB_CONTAINER}", "--format", "{{.ID}}"],
        timeout=5,
    )
    return 0 if rc != 0 else len([l for l in out.splitlines() if l.strip()])


# ---------------------------------------------------------------------------
# Agent main class
# ---------------------------------------------------------------------------

class Agent:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.token = read_token(cfg.token_file)
        self.seen = SeenCommands(cfg.state_dir / "seen-commands.json")
        self.events_queue: list[dict] = []
        self.events_lock = threading.Lock()
        self._stop = threading.Event()
        self.http = httpx.Client(timeout=15, http2=False)

    # --- HTTP helpers -----------------------------------------------------

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def enrol(self) -> bool:
        if self.token:
            return True
        if not self.cfg.enrolment_token:
            log.error("no token and no enrolment_token in config")
            return False
        log.info("enrolling with central server")
        try:
            r = self.http.post(
                f"{self.cfg.server_url}/api/v1/agent/enrol",
                json={
                    "enrolment_token": self.cfg.enrolment_token,
                    "hostname": socket.gethostname(),
                    "os_id": os.environ.get("OS_ID", ""),
                    "os_version": "",
                    "agent_version": AGENT_VERSION,
                },
            )
        except httpx.HTTPError as exc:
            log.error("enrol request failed: %s", exc)
            return False
        if r.status_code != 200:
            log.error("enrol rejected: %d %s", r.status_code, r.text[:200])
            return False
        data = r.json()
        self.token = data["agent_token"]
        write_token(self.cfg.token_file, self.token)
        self.cfg.heartbeat_interval_sec = int(data.get("heartbeat_interval_sec", 30))
        log.info("enrolled as node %s (label=%s)", data["node_id"], data["label"])
        # Remove the enrolment token from config so it is never reused.
        try:
            cfg_path = Path("/etc/honeypot-agent/config.yaml")
            raw = cfg_path.read_text()
            raw = re.sub(r'^enrolment_token:.*$', 'enrolment_token: ""', raw, flags=re.M)
            cfg_path.write_text(raw)
            self.cfg.enrolment_token = ""
        except OSError:
            pass
        return True

    def heartbeat(self, acks: list[dict]) -> list[dict] | None:
        body = {
            "agent_version": AGENT_VERSION,
            "uptime_sec": _uptime_sec(),
            "load_1": _load_1(),
            "mem_used_pct": _mem_used_pct(),
            "disk_used_pct": _disk_used_pct(),
            "docker_ok": _docker_ok(),
            "honeypots_running": _honeypots_running(),
            "acks": acks,
        }
        try:
            r = self.http.post(
                f"{self.cfg.server_url}/api/v1/agent/heartbeat",
                json=body, headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            log.warning("heartbeat failed: %s", exc)
            return None
        if r.status_code == 401:
            log.error("token revoked by central; shutting down")
            self._revoke_shutdown()
            return None
        if r.status_code >= 300:
            log.warning("heartbeat rejected: %d %s", r.status_code, r.text[:200])
            return None
        return r.json().get("commands", [])

    def ship_events(self, batch: list[dict]) -> None:
        with self.events_lock:
            self.events_queue.extend(batch)

    def _flush_events(self) -> None:
        with self.events_lock:
            if not self.events_queue:
                return
            batch = self.events_queue
            self.events_queue = []
        try:
            r = self.http.post(
                f"{self.cfg.server_url}/api/v1/agent/events",
                json={"events": batch}, headers=self._headers(), timeout=20,
            )
            if r.status_code >= 300:
                log.warning("events rejected: %d %s", r.status_code, r.text[:200])
                # Re-queue on transient failure (bounded to prevent unbounded growth).
                with self.events_lock:
                    if len(self.events_queue) < 5000:
                        self.events_queue[:0] = batch
        except httpx.HTTPError as exc:
            log.warning("ship_events failed: %s", exc)
            with self.events_lock:
                if len(self.events_queue) < 5000:
                    self.events_queue[:0] = batch

    def _revoke_shutdown(self) -> None:
        log.info("executing revoke shutdown: stopping local honeypots")
        _run(["docker", "stop", BEELZEBUB_CONTAINER], timeout=15)
        # Clear token so next start requires re-enrolment.
        try:
            self.cfg.token_file.write_text("")
        except OSError:
            pass
        self.stop()

    # --- Command execution -----------------------------------------------

    def _execute(self, cmd: dict) -> dict:
        cid = cmd["id"]
        payload = cmd["payload"] or {}
        ctype = payload.get("type", "")
        handler = HANDLERS.get(ctype)
        if handler is None:
            return {"command_id": cid, "status": "unsupported", "output": f"unknown type: {ctype}"}
        try:
            status, output = handler(payload)
        except Exception as exc:
            log.exception("handler %s raised", ctype)
            status, output = "error", f"{type(exc).__name__}: {exc}"
        return {"command_id": cid, "status": status, "output": output[:1800]}

    # --- Main loop --------------------------------------------------------

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> int:
        if not self.enrol():
            return 2
        tailer = EventTailer(self)
        tailer.start()
        try:
            pending_acks: list[dict] = []
            while not self._stop.is_set():
                commands = self.heartbeat(pending_acks)
                pending_acks = []
                self._flush_events()
                if commands is None:
                    # network or 4xx — back off.
                    self._stop.wait(self.cfg.heartbeat_interval_sec)
                    continue
                for cmd in commands:
                    cid = cmd.get("id", "")
                    if self.seen.has(cid):
                        cached = self.seen.result_for(cid)
                        if cached:
                            pending_acks.append({
                                "command_id": cid,
                                "status": cached["status"],
                                "output": cached["output"],
                            })
                        continue
                    result = self._execute(cmd)
                    self.seen.record(cid, result["status"], result["output"])
                    pending_acks.append(result)
                    log.info("cmd %s type=%s -> %s", cid[:8], cmd.get("payload", {}).get("type"), result["status"])
                self._stop.wait(self.cfg.heartbeat_interval_sec)
        finally:
            tailer.stop()
            self.http.close()
        return 0


def main() -> int:
    cfg_path = Path(os.environ.get("HONEYPOT_AGENT_CONFIG", "/etc/honeypot-agent/config.yaml"))
    if not cfg_path.exists():
        log.error("config not found: %s", cfg_path)
        return 2
    cfg = Config.load(cfg_path)
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    agent = Agent(cfg)

    def _sig(_signum, _frame):
        log.info("received signal, stopping")
        agent.stop()

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    return agent.run()


if __name__ == "__main__":
    sys.exit(main())
