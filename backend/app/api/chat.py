"""WebSocket chat endpoint and chat session persistence APIs."""

from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.security import verify_token
from app.api.deps import get_current_user, normalize_user
from app.agent.context_compressor import compact_tool_observation
from app.agent.react import ReActAgent
from app.agent.context import context_manager, Message
from app.agent.tool_executor import tool_registry

router = APIRouter(tags=["chat"])

PCAP_REQUEST_PATTERN = re.compile(r"\[文件路径:\s*(?P<path>[^\]]+\.(?:pcapng?|pcap))\]", re.IGNORECASE)
PCAP_INLINE_PATTERN = re.compile(
    r"(?P<path>(?:[A-Za-z]:[\\/]|/)[^\s\[\]]+\.(?:pcapng?|pcap))",
    re.IGNORECASE,
)


def _extract_pcap_path(content: str) -> Optional[str]:
    """Extract a pcap/pcapng path from user content."""
    if not content:
        return None

    match = PCAP_REQUEST_PATTERN.search(content)
    if match:
        return match.group("path").strip().strip("\"'")

    match = PCAP_INLINE_PATTERN.search(content)
    if match:
        return match.group("path").strip().strip("\"'")

    return None


def _extract_attachment_pcap_info(data: dict[str, Any]) -> Optional[dict[str, str]]:
    attachments = data.get("attachments") or []
    if not isinstance(attachments, list):
        return None
    for attachment in attachments:
        if not isinstance(attachment, dict):
            continue
        path = attachment.get("path")
        name = str(attachment.get("name", "")).lower()
        if path and name.endswith((".pcap", ".pcapng")):
            return {
                "path": str(path),
                "name": str(attachment.get("name") or os.path.basename(str(path))),
            }
    return None


def _extract_attachment_pcap_path(data: dict[str, Any]) -> Optional[str]:
    info = _extract_attachment_pcap_info(data)
    return info["path"] if info else None


def _sanitize_pcap_request(content: str) -> str:
    return (
        "请基于已完成的PCAP分析结果与后续威胁情报，生成详细研判报告，"
        "不要再次调用 pcap_analysis。"
    )


def _sanitize_messages_for_llm(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop persisted tool-call protocol messages before sending history to the LLM.

    Strict providers can reject tool-role history unless it appears in a perfectly
    matched assistant/tool sequence. For persisted conversation history, we only
    need the final plain-text assistant summaries.
    """
    sanitized: list[dict[str, Any]] = []
    for message in messages:
        role = message.get("role")
        if role == "tool":
            continue
        if role == "assistant" and message.get("tool_calls"):
            continue
        sanitized.append(message)
    return sanitized


def _infer_response_type(content: str, *, pcap_bootstrapped: bool = False) -> Optional[str]:
    """Infer a structured response type from the final assistant markdown."""
    text = content or ""
    if pcap_bootstrapped:
        return "pcap"
    if re.search(r"^##\s*CVE\s*/\s*KEV\s*结构化查询结果", text, re.MULTILINE):
        return "cve_catalog"
    if re.search(r"^##\s+CVE-\d+-\d+", text, re.MULTILINE):
        return "cve"
    if re.search(r"^##\s*IoC\s*分析报告", text, re.MULTILINE):
        return "ioc"
    if re.search(r"^##\s*IP\s*威胁分析报告", text, re.MULTILINE):
        return "ip"
    if re.search(r"^##\s*PCAP", text, re.MULTILINE):
        return "pcap"
    return None


def _build_pcap_fallback_report(pcap_result: dict[str, Any]) -> str:
    """Build a deterministic PCAP incident report when LLM synthesis fails.

    This keeps the PCAP workflow useful even if the provider rejects a streamed
    turn or the ReAct synthesis layer cannot complete.
    """
    from app.reports.generator import generate_pcap_incident_report

    return generate_pcap_incident_report(
        title="PCAP 安全事件报告",
        pcap_result=pcap_result,
        alerts=[],
        attack_chains=[],
        correlation_result={},
        analyst_notes="自动回退：LLM 汇总失败，报告基于 PCAP 工具分析与威胁情报生成。",
    )


class ChatSessionItem(BaseModel):
    id: str
    title: str
    lastMessage: str = ""
    updatedAt: int
    messageCount: int = 0
    summary: Optional[str] = None
    modelName: Optional[str] = None
    userId: Optional[str] = None
    tenantId: str


class ChatMessageItem(BaseModel):
    id: str
    role: str
    content: str
    timestamp: int
    toolCalls: list[dict[str, Any]] = Field(default_factory=list)
    toolCallId: Optional[str] = None
    thinking: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RenameSessionPayload(BaseModel):
    title: str


def _session_item(payload: dict[str, Any]) -> ChatSessionItem:
    return ChatSessionItem(
        id=payload["id"],
        title=payload.get("title", "新会话"),
        lastMessage=payload.get("lastMessage", ""),
        updatedAt=int(payload.get("updatedAt", 0)),
        messageCount=int(payload.get("messageCount", 0)),
        summary=payload.get("summary"),
        modelName=payload.get("modelName"),
        userId=payload.get("userId"),
        tenantId=payload.get("tenantId", "default"),
    )


def _message_item(payload: dict[str, Any]) -> ChatMessageItem:
    timestamp = payload.get("timestamp", 0)
    try:
        timestamp_ms = int(float(timestamp) * 1000)
    except (TypeError, ValueError):
        timestamp_ms = 0
    return ChatMessageItem(
        id=payload["id"],
        role=payload.get("role", "assistant"),
        content=payload.get("content", ""),
        timestamp=timestamp_ms,
        toolCalls=payload.get("tool_calls") or payload.get("toolCalls") or [],
        toolCallId=payload.get("tool_call_id") or payload.get("toolCallId"),
        thinking=payload.get("thinking"),
        metadata=payload.get("metadata") or {},
    )


async def _bootstrap_pcap_analysis(
    *,
    session_id: str,
    user_content: str,
    pcap_path: Optional[str] = None,
    tenant_id: str,
    trace_id: str,
    websocket: WebSocket,
    settings,
    progress_callback: Optional[Any] = None,
    bootstrap_context: Optional[dict[str, Any]] = None,
    pcap_display_filename: Optional[str] = None,
) -> bool:
    """Run pcap_analysis + follow-up IoC tools before the ReAct loop.

    This avoids relying on the LLM to remember the mandatory pcap tool rule.
    Returns True when a PCAP request was detected and bootstrapped.
    """
    pcap_path = pcap_path or _extract_pcap_path(user_content)
    if not pcap_path:
        return False

    async def _emit_progress(content: str) -> None:
        if progress_callback:
            try:
                progress_callback(content)
            except Exception:
                pass
        await websocket.send_json({
            "type": "thinking",
            "content": content,
        })

    tool_call_index = 1
    summary_lines: list[str] = []

    async def _persist_tool_turn(tool_name: str, tool_args: dict[str, Any], tool_result: dict[str, Any]) -> None:
        nonlocal tool_call_index
        tool_call_id = f"{trace_id}-pcap-{tool_call_index}"
        tool_call_index += 1
        assistant_payload = {
            "thought": f"检测到 PCAP 请求，自动调用 {tool_name}",
            "action": tool_name,
            "action_input": tool_args,
        }
        await context_manager.add_message(
            session_id,
            Message(
                role="assistant",
                content=json.dumps(assistant_payload, ensure_ascii=False),
                tool_calls=[{
                    "id": tool_call_id,
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "arguments": json.dumps(tool_args, ensure_ascii=False),
                    },
                }],
                tool_call_id=tool_call_id,
                metadata={"tool_name": tool_name, "bootstrap": "pcap_analysis", "hidden_in_ui": True},
            ),
        )
        await context_manager.add_message(
            session_id,
            Message(
                role="tool",
                content=compact_tool_observation(tool_result, settings.ctx_obs_max_tokens),
                tool_call_id=tool_call_id,
                metadata={"tool_name": tool_name, "bootstrap": "pcap_analysis", "hidden_in_ui": True},
            ),
        )

        await websocket.send_json({
            "type": "tool_call",
            "tool": tool_name,
            "status": "running",
            "tool_call_id": tool_call_id,
        })
        await websocket.send_json({
            "type": "tool_result",
            "tool": tool_name,
            "success": tool_result.get("success"),
            "tool_call_id": tool_call_id,
            "evidence_source": tool_result.get("evidence_source", []),
            "execution_time_ms": tool_result.get("execution_time_ms", 0),
        })

    display_name = os.path.basename(pcap_path) or pcap_path
    if pcap_display_filename:
        display_name = pcap_display_filename
    pcap_args = {
        "pcap_path": pcap_path,
        "max_packets": 10000,
        "display_filename": display_name,
    }
    await _emit_progress(f"检测到 PCAP 文件 `{display_name}`，开始自动分析。")
    pcap_result = await tool_registry.execute(
        name="pcap_analysis",
        arguments=pcap_args,
        trace_id=trace_id,
        tenant_id=tenant_id,
    )
    pcap_data = pcap_result.get("data") if isinstance(pcap_result.get("data"), dict) else None
    if pcap_data is not None:
        pcap_data.setdefault("display_filename", display_name)
        pcap_data.setdefault("pcap_identity", {
            "display_filename": display_name,
            "original_filename": pcap_display_filename or display_name,
            "source_path": pcap_path,
            "sha256": pcap_data.get("sha256"),
        })
    await _persist_tool_turn("pcap_analysis", pcap_args, pcap_result)

    pcap_summary_text = (pcap_result.get("data", {}) or {}).get("summary_text")
    if pcap_summary_text:
        summary_lines.append(pcap_summary_text)
    else:
        summary_lines.append("已完成 PCAP 自动分析并生成结构化结果。")

    if not pcap_result.get("success"):
        await websocket.send_json({
            "type": "error",
            "code": "pcap_analysis_failed",
            "message": pcap_result.get("error", "PCAP 分析失败"),
        })
        return True

    summary = pcap_result.get("data", {}).get("summary", {})
    external_ips = (pcap_result.get("data", {}) or {}).get("external_ips_for_lookup", [])
    domains = (pcap_result.get("data", {}) or {}).get("domains_for_lookup", [])

    summary_bits: list[str] = []
    total_packets = summary.get("total_packets")
    total_flows = summary.get("total_flows")
    anomaly_count = summary.get("anomaly_count")
    if total_packets is not None:
        summary_bits.append(f"{total_packets} 个数据包")
    if total_flows is not None:
        summary_bits.append(f"{total_flows} 条流")
    if anomaly_count is not None:
        summary_bits.append(f"{anomaly_count} 个异常")
    summary_text = "、".join(summary_bits) if summary_bits else "基础分析结果"
    await _emit_progress(f"基础分析完成：{summary_text}。正在串联外部 IP 威胁分析与域名 IoC 查询。")

    for ip in external_ips:
        ip_args = {"ip": ip}
        await _emit_progress(f"正在查询外部 IP 威胁情报：`{ip}`")
        ip_result = await tool_registry.execute(
            name="ip_threat_analysis",
            arguments=ip_args,
            trace_id=trace_id,
            tenant_id=tenant_id,
        )
        await _persist_tool_turn("ip_threat_analysis", ip_args, ip_result)
        summary_lines.append(compact_tool_observation(ip_result, settings.ctx_obs_max_tokens))

    for domain in domains:
        ioc_args = {"value": domain}
        await _emit_progress(f"正在查询可疑域名 IoC：`{domain}`")
        ioc_result = await tool_registry.execute(
            name="ioc_lookup",
            arguments=ioc_args,
            trace_id=trace_id,
            tenant_id=tenant_id,
        )
        await _persist_tool_turn("ioc_lookup", ioc_args, ioc_result)
        summary_lines.append(compact_tool_observation(ioc_result, settings.ctx_obs_max_tokens))

    await _emit_progress("自动分析已完成，正在整理详细研判输入。")

    # Leave a concise summary hint in the conversation so the ReAct model
    # can synthesize without re-triggering the mandatory PCAP rule.
    await context_manager.add_message(
        session_id,
        Message(
            role="assistant",
            content=(
                f"已完成 PCAP 自动分析，时间基准为 {summary.get('time_basis', 'unknown')}。\n"
                "请基于以下已完成的分析结果生成详细研判报告，不要再次调用 pcap_analysis。\n\n"
                + "\n\n".join(summary_lines[:6])
            ),
            metadata={"bootstrap": "pcap_analysis"},
        ),
    )

    if bootstrap_context is not None:
        bootstrap_context["pcap_result"] = pcap_result.get("data", {}) or {}
        bootstrap_context["summary_lines"] = list(summary_lines)

    return True


async def authenticate_ws(token: str) -> dict[str, Any] | None:
    """Verify JWT from WebSocket query param."""
    settings = get_settings()
    payload = verify_token(token, secret=settings.jwt_secret, algorithm=settings.jwt_algorithm)
    if not payload:
        return None
    return normalize_user(payload)


@router.get("/api/v1/agent/sessions", response_model=list[ChatSessionItem])
async def list_chat_sessions(
    current_user: dict[str, Any] = Depends(get_current_user),
    limit: int = 50,
    offset: int = 0,
):
    """List chat sessions for the authenticated user."""
    tenant_id = current_user["tenant_id"]
    user_id = current_user.get("user_id") or current_user.get("sub")
    sessions = await context_manager.list_sessions(tenant_id, user_id=user_id, limit=limit, offset=offset)
    return [_session_item(session) for session in sessions]


@router.post("/api/v1/agent/sessions", response_model=ChatSessionItem)
async def create_chat_session(current_user: dict[str, Any] = Depends(get_current_user)):
    """Create a new chat session for the authenticated user."""
    tenant_id = current_user["tenant_id"]
    user_id = current_user["user_id"]
    conv = await context_manager.create_session(tenant_id, user_id=user_id)
    return _session_item(
        {
            "id": conv.session_id,
            "title": conv.title,
            "lastMessage": conv.last_message_preview,
            "updatedAt": int(conv.updated_at * 1000),
            "messageCount": conv.message_count,
            "summary": conv.summary,
            "modelName": conv.model_name,
            "userId": conv.user_id,
            "tenantId": conv.tenant_id,
        }
    )


@router.get("/api/v1/agent/sessions/{session_id}", response_model=ChatSessionItem)
async def get_chat_session(
    session_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Get a single chat session summary."""
    conv = await context_manager.get_session(session_id, current_user["tenant_id"])
    if not conv:
        raise HTTPException(status_code=404, detail="Session not found")
    return _session_item(
        {
            "id": conv.session_id,
            "title": conv.title,
            "lastMessage": conv.last_message_preview,
            "updatedAt": int(conv.updated_at * 1000),
            "messageCount": conv.message_count,
            "summary": conv.summary,
            "modelName": conv.model_name,
            "userId": conv.user_id,
            "tenantId": conv.tenant_id,
        }
    )


@router.get("/api/v1/agent/sessions/{session_id}/messages", response_model=list[ChatMessageItem])
async def get_chat_session_messages(
    session_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Get persisted messages for a chat session."""
    messages = await context_manager.get_session_messages(session_id, current_user["tenant_id"])
    if not messages:
        conv = await context_manager.get_session(session_id, current_user["tenant_id"])
        if not conv:
            raise HTTPException(status_code=404, detail="Session not found")
    return [_message_item(message) for message in messages]


@router.patch("/api/v1/agent/sessions/{session_id}", response_model=ChatSessionItem)
async def rename_chat_session(
    session_id: str,
    payload: RenameSessionPayload,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Rename a chat session."""
    conv = await context_manager.rename_session(session_id, payload.title, current_user["tenant_id"])
    if not conv:
        raise HTTPException(status_code=404, detail="Session not found")
    return _session_item(
        {
            "id": conv.session_id,
            "title": conv.title,
            "lastMessage": conv.last_message_preview,
            "updatedAt": int(conv.updated_at * 1000),
            "messageCount": conv.message_count,
            "summary": conv.summary,
            "modelName": conv.model_name,
            "userId": conv.user_id,
            "tenantId": conv.tenant_id,
        }
    )


@router.delete("/api/v1/agent/sessions/{session_id}")
async def delete_chat_session(
    session_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Delete a chat session and its messages."""
    conv = await context_manager.get_session(session_id, current_user["tenant_id"])
    if not conv:
        raise HTTPException(status_code=404, detail="Session not found")
    await context_manager.clear_session(session_id)
    return {"success": True, "session_id": session_id}


@router.get("/api/v1/agent/sessions/{session_id}/export")
async def export_chat_session(
    session_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Export a chat session and its messages as JSON."""
    payload = await context_manager.export_session(session_id, current_user["tenant_id"])
    if not payload:
        raise HTTPException(status_code=404, detail="Session not found")
    return JSONResponse(content=payload)


@router.websocket("/api/v1/agent/chat")
async def websocket_chat(
    websocket: WebSocket,
    token: str = Query(...),
):
    """WebSocket endpoint for multi-turn Agent chat."""
    # Authenticate
    user = await authenticate_ws(token)
    if not user:
        await websocket.close(code=4001, reason="Invalid token")
        return

    await websocket.accept()

    tenant_id = user.get("tenant_id", "default")
    session_id = None

    settings = get_settings()
    pcap_bootstrap_context: dict[str, Any] = {}
    thinking_trace: list[str] = []

    # Background keepalive: send ping every 30s to prevent proxy timeout
    import asyncio
    _keepalive_state = {"running": True}

    async def _keepalive():
        while _keepalive_state["running"]:
            await asyncio.sleep(30)
            try:
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_json({"type": "ping"})
            except Exception:
                break

    keepalive_task = asyncio.create_task(_keepalive())

    try:
        while True:
            # Receive message
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "code": "invalid_json", "message": "Invalid JSON"})
                continue

            msg_type = data.get("type")
            if msg_type == "stop":
                # Client requested stop — close gracefully
                await websocket.close(code=4000, reason="client_stop")
                return
            if msg_type != "chat":
                await websocket.send_json({"type": "error", "code": "unsupported", "message": f"Unknown type: {msg_type}"})
                continue

            content = data.get("content", "")
            session_id = data.get("session_id")
            attachment_pcap_info = _extract_attachment_pcap_info(data)
            attachment_pcap_path = attachment_pcap_info["path"] if attachment_pcap_info else None

            # Send LLM backend info
            await websocket.send_json({
                "type": "llm_backend",
                "provider": "deepseek",
                "model": settings.llm_model,
            })

            # Get or create session
            if session_id:
                conv = await context_manager.get_session(session_id, tenant_id)
                if not conv:
                    conv = await context_manager.create_session(tenant_id, user_id=user["user_id"])
                    session_id = conv.session_id
            else:
                conv = await context_manager.create_session(tenant_id, user_id=user["user_id"])
                session_id = conv.session_id

            # Add user message
            await context_manager.add_message(session_id, Message(role="user", content=content))

            trace_id = str(uuid.uuid4())

            # If the user attached a PCAP path, run the analysis pipeline first so
            # the LLM receives concrete findings instead of trying to inspect the file itself.
            pcap_bootstrapped = await _bootstrap_pcap_analysis(
                session_id=session_id,
                user_content=content,
                pcap_path=attachment_pcap_path,
                tenant_id=tenant_id,
                trace_id=trace_id,
                websocket=websocket,
                settings=settings,
                progress_callback=thinking_trace.append,
                bootstrap_context=pcap_bootstrap_context,
                pcap_display_filename=attachment_pcap_info["name"] if attachment_pcap_info else None,
            )

            # Get context
            messages = await context_manager.get_messages(session_id)
            if pcap_bootstrapped:
                for idx in range(len(messages) - 1, -1, -1):
                    if messages[idx].get("role") == "user":
                        messages[idx]["content"] = _sanitize_pcap_request(messages[idx].get("content", ""))
                        break
            messages = _sanitize_messages_for_llm(messages)

            # Run ReAct agent

            agent = ReActAgent(
                llm_router=_get_llm_router(),
                tool_registry=tool_registry,
                max_turns=settings.react_max_turns,
                max_tool_retries=settings.react_max_tool_retries,
                compress_interval=settings.ctx_history_summary_interval,
                obs_max_tokens=settings.ctx_obs_max_tokens,
            )

            final_answer = ""
            total_tokens = 0

            async for event in agent.run_streaming(messages, tenant_id, trace_id):
                if event.type == "thought":
                    # Send thinking summary, not a tool_call
                    thought_text = event.content.get("thought", "")
                    if thought_text:
                        thinking_trace.append(thought_text)
                    await websocket.send_json({
                        "type": "thinking",
                        "content": thought_text,
                    })
                elif event.type == "tool_call":
                    await websocket.send_json({
                        "type": "tool_call",
                        "tool": event.content.get("tool", ""),
                        "status": "running",
                        "tool_call_id": event.content.get("tool_call_id", ""),
                    })
                elif event.type == "tool_result":
                    ws_msg = {
                        "type": "tool_result",
                        "tool": event.content.get("tool", ""),
                        "success": event.content.get("success"),
                        "tool_call_id": event.content.get("tool_call_id", ""),
                        "evidence_source": event.content.get("evidence_source", []),
                        "execution_time_ms": event.content.get("execution_time_ms", 0),
                    }
                    if "rag_summary" in event.content:
                        ws_msg["rag_summary"] = event.content["rag_summary"]
                    await websocket.send_json(ws_msg)
                elif event.type == "answer_token":
                    token_text = event.content if isinstance(event.content, str) else str(event.content)
                    final_answer += token_text
                    await websocket.send_json({
                        "type": "token",
                        "content": token_text,
                    })
                elif event.type == "usage":
                    total_tokens = int(event.content.get("total_tokens", total_tokens) or total_tokens)
                elif event.type == "error":
                    await websocket.send_json({
                        "type": "error",
                        "code": event.content.get("error", "unknown"),
                        "message": str(event.content),
                    })

            if pcap_bootstrapped and not final_answer.strip():
                pcap_result_data = pcap_bootstrap_context.get("pcap_result")
                if isinstance(pcap_result_data, dict) and pcap_result_data:
                    final_answer = _build_pcap_fallback_report(pcap_result_data)
                else:
                    final_answer = (
                        "## 结论\n"
                        "已完成 PCAP 自动分析，但本次模型汇总未生成完整正文。\n\n"
                        "## 处置建议\n"
                        "请查看上方工具调用与分析步骤，并基于已完成的分析结果继续研判。"
                    )

            # Save assistant response
            await context_manager.add_message(
                session_id,
                Message(
                    role="assistant",
                    content=final_answer,
                    thinking="\n".join(filter(None, thinking_trace)) or None,
                    metadata={
                        **({"response_type": inferred_response_type} if (inferred_response_type := _infer_response_type(final_answer, pcap_bootstrapped=pcap_bootstrapped)) else {}),
                    },
                ),
            )

            # Send done
            await websocket.send_json({
                "type": "done",
                "session_id": session_id,
                "total_tokens": total_tokens,
            })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        if websocket.client_state == WebSocketState.CONNECTED:
            await websocket.send_json({"type": "error", "code": "internal", "message": str(e)})
            await websocket.close()
    finally:
        _keepalive_state["running"] = False
        keepalive_task.cancel()
        try:
            await keepalive_task
        except asyncio.CancelledError:
            pass


def _get_llm_router():
    """Import LLM router (avoids circular imports)."""
    from app.llm.router import router
    return router
