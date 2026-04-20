"""
OpenAI-compatible LLM proxy for remote honeypot nodes.

Exposes a single endpoint — POST /llm/v1/chat/completions — that remote
Beelzebub instances point their `openAIBaseURL` at. The model identifier
in the request body picks the backend:

  * "bedrock:<model-id>"  → AWS Bedrock Converse API (via boto3, using the
                            EC2 instance role; no API keys in flight)
  * any other value       → local Ollama on 127.0.0.1:11434 (OpenAI-compat)

Authentication reuses the agent bearer-token dependency from agent_api so
only enrolled, non-revoked remote nodes can invoke LLMs through the central
host. oauth2-proxy skips OIDC on /llm/v1/* (see tpot_setup.sh Phase 10).
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request

from db import sha256

log = logging.getLogger("honeypot-mgmt.llm")

router = APIRouter(prefix="/llm/v1", tags=["llm"])

OLLAMA_API = "http://127.0.0.1:11434"
BEDROCK_PREFIX = "bedrock:"
BEDROCK_REGION = os.environ.get("AWS_REGION") or os.environ.get("BEDROCK_REGION", "us-east-1")


async def current_llm_node(
    request: Request,
    authorization: str = Header(default=""),
) -> dict:
    """Validate the bearer token against `llm_tokens`; return node row.

    LLM tokens are minted per-deploy and stored alongside nodes so the LLM
    proxy can be scoped to non-revoked enrolled nodes only, independent of
    the agent heartbeat token.
    """
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="missing bearer token")
    db = request.app.state.db
    row = await (await db.execute(
        """
        SELECT n.id, n.label, n.revoked_at
          FROM llm_tokens t
          JOIN nodes n ON n.id = t.node_id
         WHERE t.token_sha256 = ?
        """,
        (sha256(token),),
    )).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="unknown llm token")
    if row["revoked_at"]:
        raise HTTPException(status_code=401, detail="revoked")
    return {"id": row["id"], "label": row["label"]}

# boto3 is only imported when a Bedrock request actually arrives so that
# installations without enable_bedrock don't pay the import cost.
_bedrock_client = None
_bedrock_lock = asyncio.Lock()


async def _get_bedrock_client():
    global _bedrock_client
    if _bedrock_client is not None:
        return _bedrock_client
    async with _bedrock_lock:
        if _bedrock_client is None:
            import boto3  # noqa: WPS433 — deferred import on purpose
            _bedrock_client = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)
    return _bedrock_client


def _openai_to_bedrock(messages: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split an OpenAI chat payload into Bedrock Converse (system, messages).

    Bedrock Converse takes `system` as a separate top-level argument and
    expects user/assistant messages with content blocks of
    `{"text": "..."}`.
    """
    system_blocks: list[dict] = []
    converse_messages: list[dict] = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        if isinstance(content, list):
            text = "".join(
                p.get("text", "") for p in content if isinstance(p, dict)
            )
        else:
            text = str(content)
        if role == "system":
            system_blocks.append({"text": text})
        elif role in ("user", "assistant"):
            converse_messages.append({
                "role": role,
                "content": [{"text": text}],
            })
        # Unknown roles are dropped — Beelzebub only emits system/user.
    return system_blocks, converse_messages


def _bedrock_to_openai(
    resp: dict, model: str,
) -> dict:
    """Convert a Bedrock Converse response to an OpenAI chat.completion."""
    try:
        msg = resp["output"]["message"]
        parts = msg.get("content", [])
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
    except (KeyError, TypeError):
        text = ""
    usage = resp.get("usage", {}) or {}
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": text},
            "finish_reason": resp.get("stopReason", "stop"),
        }],
        "usage": {
            "prompt_tokens":     int(usage.get("inputTokens", 0)),
            "completion_tokens": int(usage.get("outputTokens", 0)),
            "total_tokens":      int(usage.get("totalTokens", 0)),
        },
    }


async def _invoke_bedrock(model_id: str, body: dict) -> dict:
    client = await _get_bedrock_client()
    system_blocks, messages = _openai_to_bedrock(body.get("messages") or [])
    inference_config: dict[str, Any] = {}
    if "temperature" in body:
        inference_config["temperature"] = float(body["temperature"])
    if "max_tokens" in body:
        inference_config["maxTokens"] = int(body["max_tokens"])
    if "top_p" in body:
        inference_config["topP"] = float(body["top_p"])
    kwargs: dict[str, Any] = {"modelId": model_id, "messages": messages}
    if system_blocks:
        kwargs["system"] = system_blocks
    if inference_config:
        kwargs["inferenceConfig"] = inference_config

    def _call():
        return client.converse(**kwargs)

    try:
        resp = await asyncio.to_thread(_call)
    except Exception as exc:
        log.warning("bedrock converse failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"bedrock: {exc}") from exc
    return _bedrock_to_openai(resp, f"{BEDROCK_PREFIX}{model_id}")


async def _invoke_ollama(request: Request, body: dict) -> dict:
    client: httpx.AsyncClient = request.app.state.http
    try:
        r = await client.post(
            f"{OLLAMA_API}/v1/chat/completions",
            json=body,
            timeout=120,
        )
    except httpx.HTTPError as exc:
        log.warning("ollama request failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"ollama: {exc}") from exc
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=r.text[:500])
    return r.json()


@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    node: dict = Depends(current_llm_node),
) -> dict:
    """OpenAI-compatible chat completion; routes by model-name prefix."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")
    model = str(body.get("model") or "")
    if not model:
        raise HTTPException(status_code=400, detail="'model' is required")

    if model.startswith(BEDROCK_PREFIX):
        bedrock_model = model[len(BEDROCK_PREFIX):]
        if not bedrock_model:
            raise HTTPException(status_code=400, detail="empty bedrock model id")
        log.info("llm proxy: node=%s bedrock=%s", node["label"], bedrock_model)
        return await _invoke_bedrock(bedrock_model, body)

    log.info("llm proxy: node=%s ollama=%s", node["label"], model)
    return await _invoke_ollama(request, body)


@router.get("/models")
async def list_models(
    request: Request,
    node: dict = Depends(current_llm_node),
) -> dict:
    """OpenAI-compatible model list — Ollama tags plus configured Bedrock IDs."""
    models: list[dict] = []
    client: httpx.AsyncClient = request.app.state.http
    try:
        r = await client.get(f"{OLLAMA_API}/api/tags", timeout=3)
        for m in r.json().get("models", []):
            models.append({
                "id": m.get("name", ""),
                "object": "model",
                "owned_by": "ollama",
            })
    except Exception:
        pass
    bedrock_ids = os.environ.get("BEDROCK_MODEL_IDS", "").strip()
    if bedrock_ids:
        for mid in (m.strip() for m in bedrock_ids.split(",") if m.strip()):
            models.append({
                "id": f"{BEDROCK_PREFIX}{mid}",
                "object": "model",
                "owned_by": "bedrock",
            })
    return {"object": "list", "data": models}
