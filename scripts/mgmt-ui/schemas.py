"""
Pydantic v2 models shared between the agent API and the remote agent.

Commands are a tagged union discriminated on `type`; unknown types are
rejected server- and agent-side.
"""
from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enrolment
# ---------------------------------------------------------------------------

class EnrolRequest(BaseModel):
    enrolment_token: str = Field(..., min_length=8, max_length=64)
    hostname: str
    os_id: str = ""
    os_version: str = ""
    agent_version: str = "1.0.0"


class EnrolResponse(BaseModel):
    node_id: int
    label: str
    agent_token: str
    heartbeat_interval_sec: int = 30


# ---------------------------------------------------------------------------
# Commands (tagged union)
# ---------------------------------------------------------------------------

class InstallBeelzebubPayload(BaseModel):
    type: Literal["install_beelzebub"] = "install_beelzebub"
    image: str = "mariocandela/beelzebub:latest"


class ApplyBeelzebubConfigPayload(BaseModel):
    type: Literal["apply_beelzebub_config"] = "apply_beelzebub_config"
    main_yaml: str
    ssh_yaml: str = ""
    http_yaml: str = ""


class StartHoneypotPayload(BaseModel):
    type: Literal["start_honeypot"] = "start_honeypot"
    name: str


class StopHoneypotPayload(BaseModel):
    type: Literal["stop_honeypot"] = "stop_honeypot"
    name: str


class RemoveHoneypotPayload(BaseModel):
    type: Literal["remove_honeypot"] = "remove_honeypot"
    name: str


class UpgradeAgentPayload(BaseModel):
    type: Literal["upgrade_agent"] = "upgrade_agent"
    artefact_url: str


class PingPayload(BaseModel):
    type: Literal["ping"] = "ping"


CommandPayload = Annotated[
    Union[
        InstallBeelzebubPayload,
        ApplyBeelzebubConfigPayload,
        StartHoneypotPayload,
        StopHoneypotPayload,
        RemoveHoneypotPayload,
        UpgradeAgentPayload,
        PingPayload,
    ],
    Field(discriminator="type"),
]


class Command(BaseModel):
    id: str
    payload: CommandPayload


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------

class CommandAck(BaseModel):
    command_id: str
    status: Literal["ok", "error", "unsupported"]
    output: str = ""


class HeartbeatRequest(BaseModel):
    agent_version: str = "1.0.0"
    uptime_sec: int = 0
    load_1: float = 0.0
    mem_used_pct: float = 0.0
    disk_used_pct: float = 0.0
    docker_ok: bool = False
    honeypots_running: int = 0
    acks: list[CommandAck] = []


class HeartbeatResponse(BaseModel):
    commands: list[Command] = []
    revoked: bool = False


# ---------------------------------------------------------------------------
# Attack events
# ---------------------------------------------------------------------------

class AttackEvent(BaseModel):
    ts: str                 # ISO 8601 UTC
    src_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""      # e.g. "ssh", "http"
    honeypot: str = "beelzebub"
    username: str = ""
    password: str = ""
    command: str = ""
    raw: str = ""


class EventBatch(BaseModel):
    events: list[AttackEvent]
