"""
验证端点 — 仅用于 Runtime 主链路验证。

验证完成后，此文件可移除或重构为正式 API。
"""

import json
import time
import uuid
from typing import Any, Optional

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.llm.router import router as llm_router, LLMRequest
from app.agent.context import context_manager, Message
from app.agent.tool_executor import tool_registry as tool_executor

router = APIRouter(prefix="/verify", tags=["verify"])


class ChainRequest(BaseModel):
    """完整链路验证请求"""

    message: str = "请使用 echo 工具回显这句话: Hello CyberSec Agent"
    tenant_id: str = "test-tenant"


class ChatRequest(BaseModel):
    """聊天请求"""

    message: str
    session_id: Optional[str] = None
    tenant_id: str = "test-tenant"


# ============================================================
# 1. 健康检查
# ============================================================

@router.get("/health")
async def health():
    """基础健康检查"""
    return {
        "status": "ok",
        "components": {
            "fastapi": True,
            "llm_router": True,
        },
    }


# ============================================================
# 2. Streaming 验证
# ============================================================

@router.post("/streaming")
async def verify_streaming(request: ChainRequest):
    """验证 Streaming 响应"""

    async def event_stream():
        llm_request = LLMRequest(
            messages=[{"role": "user", "content": request.message}],
            stream=True,
        )

        async for chunk in llm_router.stream(llm_request):
            yield f"data: {json.dumps({'content': chunk})}\n\n"

        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ============================================================
# 3. Tool Calling 验证
# ============================================================

@router.post("/tool-calling")
async def verify_tool_calling(request: ChainRequest):
    """验证 Tool Calling 链路"""
    trace_id = str(uuid.uuid4())

    # Step 1: LLM 决定调用 Tool
    llm_request = LLMRequest(
        messages=[{"role": "user", "content": request.message}],
        tools=tool_executor.get_schemas(),
        trace_id=trace_id,
    )

    llm_response = await llm_router.complete(llm_request)

    # Step 2: 如果有 tool_calls，执行 Tool
    tool_results = []
    if llm_response.tool_calls:
        for tc in llm_response.tool_calls:
            func_name = tc["function"]["name"]
            func_args = json.loads(tc["function"]["arguments"])
            result = await tool_executor.execute(func_name, func_args, trace_id)
            tool_results.append(result)

    return {
        "trace_id": trace_id,
        "llm_response": {
            "content": llm_response.content,
            "tool_calls": llm_response.tool_calls,
            "model": llm_response.model,
            "usage": llm_response.usage,
            "latency_ms": llm_response.latency_ms,
        },
        "tool_results": tool_results,
    }


# ============================================================
# 4. Context Manager 验证
# ============================================================

@router.post("/context")
async def verify_context(request: ChatRequest):
    """验证多轮上下文管理"""
    # 创建或获取会话
    if request.session_id:
        conv = await context_manager.get_session(request.session_id)
        if not conv:
            conv = await context_manager.create_session(request.tenant_id)
    else:
        conv = await context_manager.create_session(request.tenant_id)

    # 添加用户消息
    await context_manager.add_message(
        conv.session_id,
        Message(role="user", content=request.message),
    )

    # 获取完整上下文
    messages = await context_manager.get_messages(conv.session_id)

    # 调用 LLM
    llm_request = LLMRequest(messages=messages)
    llm_response = await llm_router.complete(llm_request)

    # 保存助手回复
    await context_manager.add_message(
        conv.session_id,
        Message(role="assistant", content=llm_response.content),
    )

    message_count = await context_manager.get_message_count(conv.session_id)

    return {
        "session_id": conv.session_id,
        "message_count": message_count,
        "response": llm_response.content,
        "model": llm_response.model,
        "usage": llm_response.usage,
        "latency_ms": llm_response.latency_ms,
    }


# ============================================================
# 5. 完整链路验证（Streaming + Tool Calling + Context）
# ============================================================

@router.post("/chain")
async def verify_chain(request: ChainRequest):
    """验证完整 Runtime 主链路"""
    trace_id = str(uuid.uuid4())
    start = time.time()

    # Step 1: 创建会话
    conv = await context_manager.create_session(request.tenant_id)

    # Step 2: 添加用户消息
    await context_manager.add_message(
        conv.session_id,
        Message(role="user", content=request.message),
    )

    # Step 3: 获取上下文
    messages = await context_manager.get_messages(conv.session_id)

    # Step 4: LLM 调用（带 Tool）
    llm_request = LLMRequest(
        messages=messages,
        tools=tool_executor.get_schemas(),
        trace_id=trace_id,
    )

    llm_response = await llm_router.complete(llm_request)

    # Step 5: 执行 Tool（如有）
    tool_results = []
    if llm_response.tool_calls:
        for tc in llm_response.tool_calls:
            func_name = tc["function"]["name"]
            func_args = json.loads(tc["function"]["arguments"])
            result = await tool_executor.execute(func_name, func_args, trace_id)
            result["_tool_call_id"] = tc["id"]
            tool_results.append(result)

        # Step 6: 构建 Tool 反馈消息（直接构建，兼容 DeepSeek reasoning_content）
        messages = await context_manager.get_messages(conv.session_id)

        assistant_msg: dict[str, Any] = {
            "role": "assistant",
            "content": llm_response.content,
            "tool_calls": llm_response.tool_calls,
        }
        if llm_response.reasoning_content:
            assistant_msg["reasoning_content"] = llm_response.reasoning_content
        messages.append(assistant_msg)

        for tr in tool_results:
            messages.append({
                "role": "tool",
                "content": json.dumps(tr["data"]),
                "tool_call_id": tr["_tool_call_id"],
            })

        # 再次调用 LLM 获取最终回复
        llm_request_2 = LLMRequest(messages=messages, trace_id=trace_id)
        llm_response_2 = await llm_router.complete(llm_request_2)
        final_content = llm_response_2.content
    else:
        final_content = llm_response.content

    # Step 7: 保存最终回复
    await context_manager.add_message(
        conv.session_id,
        Message(role="assistant", content=final_content),
    )

    total_latency = int((time.time() - start) * 1000)

    return {
        "trace_id": trace_id,
        "session_id": conv.session_id,
        "status": "chain_verified",
        "steps": {
            "1_context_created": True,
            "2_message_added": True,
            "3_context_retrieved": True,
            "4_llm_called": True,
            "5_tools_executed": len(tool_results),
            "6_final_response": final_content,
        },
        "tool_results": tool_results,
        "model": llm_response.model,
        "total_latency_ms": total_latency,
    }
