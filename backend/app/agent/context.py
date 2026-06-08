"""Context Manager — 管理多轮对话上下文。"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import redis.asyncio as redis
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import selectinload

from app.models.base import get_session_factory
from app.models.models import ChatMessage, ChatSession, User


def _uuid() -> str:
    return str(uuid.uuid4())


def _normalize_uuid(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError):
        return None


def _utc_timestamp(dt: Optional[datetime]) -> float:
    if not dt:
        return time.time()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _preview_text(content: str, limit: int = 80) -> str:
    text = " ".join((content or "").split())
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


class Message(BaseModel):
    """对话消息"""

    id: str = Field(default_factory=_uuid)
    role: str  # user / assistant / system / tool
    content: str
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    tool_call_id: Optional[str] = None
    thinking: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)


class Conversation(BaseModel):
    """对话会话"""

    session_id: str = Field(default_factory=_uuid)
    tenant_id: str
    user_id: Optional[str] = None
    title: str = "新会话"
    summary: Optional[str] = None
    model_name: Optional[str] = None
    messages: list[Message] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    last_message_preview: str = ""
    message_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContextManager:
    """上下文管理器。

    当前实现：数据库为主存储，内存为热缓存。
    未来可在此之上叠加 Redis 热缓存。
    """

    def __init__(self, redis_url: Optional[str] = None):
        self._memory_store: dict[str, Conversation] = {}
        self._redis: Optional[redis.Redis] = None
        self._redis_url = redis_url

    async def connect(self):
        """连接 Redis（预留）"""
        if self._redis_url:
            self._redis = redis.from_url(self._redis_url)

    async def disconnect(self):
        """断开连接"""
        if self._redis:
            await self._redis.aclose()

    def _cache_conversation(self, conv: Conversation) -> Conversation:
        self._memory_store[conv.session_id] = conv
        return conv

    def _conversation_to_llm_messages(self, conv: Conversation) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for msg in conv.messages:
            item: dict[str, Any] = {"role": msg.role, "content": msg.content}
            if msg.tool_calls:
                item["tool_calls"] = msg.tool_calls
            if msg.tool_call_id:
                item["tool_call_id"] = msg.tool_call_id
            result.append(item)
        return result

    def _conversation_to_ui_messages(self, conv: Conversation) -> list[dict[str, Any]]:
        return [
            {
                "id": msg.id,
                "role": msg.role,
                "content": msg.content,
                "timestamp": msg.timestamp,
                "tool_calls": msg.tool_calls,
                "tool_call_id": msg.tool_call_id,
                "metadata": msg.metadata,
                **({"thinking": msg.thinking} if msg.thinking else {}),
            }
            for msg in conv.messages
        ]

    @staticmethod
    def _should_hide_from_ui(msg: Message) -> bool:
        metadata = msg.metadata or {}
        if metadata.get("hidden_in_ui"):
            return True
        if msg.role == "tool":
            return True
        if msg.role == "assistant" and msg.tool_calls and metadata.get("bootstrap"):
            return True
        return False

    def _conversation_from_row(self, session_row: ChatSession, messages: Optional[list[ChatMessage]] = None) -> Conversation:
        message_rows = messages if messages is not None else list(session_row.messages or [])
        return Conversation(
            session_id=session_row.id,
            tenant_id=session_row.tenant_id,
            user_id=session_row.user_id,
            title=session_row.title or "新会话",
            summary=session_row.summary,
            model_name=session_row.model_name,
            messages=[
                Message(
                    id=message.id,
                    role=message.role,
                    content=message.content,
                    tool_calls=message.tool_calls or [],
                    tool_call_id=message.tool_call_id,
                    thinking=message.thinking,
                    metadata=message.extra_data or {},
                    timestamp=_utc_timestamp(message.created_at),
                )
                for message in message_rows
            ],
            created_at=_utc_timestamp(session_row.created_at),
            updated_at=_utc_timestamp(session_row.updated_at),
            last_message_preview=session_row.last_message_preview or "",
            message_count=session_row.message_count or len(message_rows),
            metadata=session_row.extra_data or {},
        )

    async def _load_session_row(
        self,
        session_id: str,
        tenant_id: Optional[str] = None,
        include_messages: bool = True,
    ) -> Optional[Conversation]:
        factory = get_session_factory()
        async with factory() as db:
            query = select(ChatSession).where(ChatSession.id == session_id)
            if tenant_id is not None:
                query = query.where(ChatSession.tenant_id == tenant_id)
            if include_messages:
                query = query.options(selectinload(ChatSession.messages))
            result = await db.execute(query)
            session_row = result.scalar_one_or_none()
            if not session_row:
                return None
            conv = self._conversation_from_row(session_row)
            return self._cache_conversation(conv)

    async def create_session(self, tenant_id: str, user_id: Optional[str] = None) -> Conversation:
        """创建新会话并持久化。"""
        factory = get_session_factory()
        session_id = _uuid()
        now = datetime.now(timezone.utc)
        normalized_user_id = _normalize_uuid(user_id)
        resolved_user_id = None

        if normalized_user_id:
            async with factory() as db:
                result = await db.execute(select(User.id).where(User.id == normalized_user_id))
                resolved_user_id = result.scalar_one_or_none()

        async with factory() as db:
            session_row = ChatSession(
                id=session_id,
                tenant_id=tenant_id,
                user_id=resolved_user_id,
                title="新会话",
                message_count=0,
                created_at=now,
                updated_at=now,
                last_message_at=None,
            )
            db.add(session_row)
            await db.commit()
            await db.refresh(session_row)

        conv = Conversation(
            session_id=session_id,
            tenant_id=tenant_id,
            user_id=resolved_user_id,
            created_at=_utc_timestamp(now),
            updated_at=_utc_timestamp(now),
            model_name=None,
        )
        return self._cache_conversation(conv)

    async def get_session(self, session_id: str, tenant_id: Optional[str] = None) -> Optional[Conversation]:
        """获取会话，必要时校验租户归属。"""
        conv = self._memory_store.get(session_id)
        if conv and tenant_id is not None and conv.tenant_id != tenant_id:
            return None
        if conv:
            return conv
        return await self._load_session_row(session_id, tenant_id=tenant_id, include_messages=True)

    async def list_sessions(
        self,
        tenant_id: str,
        *,
        user_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """列出会话摘要，按租户和用户隔离。"""
        factory = get_session_factory()
        async with factory() as db:
            query = (
                select(ChatSession)
                .where(ChatSession.tenant_id == tenant_id)
            )
            # Filter by user_id only if it's a valid UUID
            normalized_uid = _normalize_uuid(user_id)
            if normalized_uid:
                query = query.where(ChatSession.user_id == normalized_uid)
            query = query.order_by(ChatSession.updated_at.desc()).offset(offset).limit(limit)
            result = await db.execute(query)
            rows = result.scalars().all()

        sessions: list[dict[str, Any]] = []
        for row in rows:
            sessions.append({
                "id": row.id,
                "title": row.title or "新会话",
                "lastMessage": row.last_message_preview or "",
                "updatedAt": int(_utc_timestamp(row.updated_at) * 1000),
                "messageCount": row.message_count or 0,
                "summary": row.summary,
                "modelName": row.model_name,
                "userId": row.user_id,
                "tenantId": row.tenant_id,
            })
        return sessions

    async def get_session_messages(self, session_id: str, tenant_id: Optional[str] = None) -> list[dict[str, Any]]:
        """获取会话消息，用于前端恢复聊天历史。"""
        conv = await self.get_session(session_id, tenant_id=tenant_id)
        if not conv:
            return []
        visible_messages = [msg for msg in conv.messages if not self._should_hide_from_ui(msg)]
        visible_conv = Conversation(
            session_id=conv.session_id,
            tenant_id=conv.tenant_id,
            user_id=conv.user_id,
            title=conv.title,
            summary=conv.summary,
            model_name=conv.model_name,
            messages=visible_messages,
            created_at=conv.created_at,
            updated_at=conv.updated_at,
            last_message_preview=conv.last_message_preview,
            message_count=len(visible_messages),
            metadata=conv.metadata,
        )
        return self._conversation_to_ui_messages(visible_conv)

    async def add_message(self, session_id: str, message: Message) -> bool:
        """添加消息到会话并持久化。"""
        conv = await self.get_session(session_id)
        if not conv:
            return False

        factory = get_session_factory()
        now = datetime.now(timezone.utc)
        next_seq = conv.message_count + 1
        preview = _preview_text(message.content)

        async with factory() as db:
            session_row = await db.get(ChatSession, session_id)
            if not session_row:
                return False

            db.add(ChatMessage(
                id=message.id,
                session_id=session_id,
                tenant_id=conv.tenant_id,
                seq=next_seq,
                role=message.role,
                content=message.content,
                thinking=message.thinking,
                tool_calls=message.tool_calls or [],
                tool_call_id=message.tool_call_id,
                extra_data=message.metadata or {},
                created_at=now,
            ))

            session_row.message_count = next_seq
            session_row.last_message_preview = preview
            session_row.last_message_at = now
            session_row.updated_at = now
            if session_row.title == "新会话" and message.role == "user" and preview:
                session_row.title = preview

            await db.commit()

        conv.messages.append(message)
        conv.message_count = next_seq
        conv.last_message_preview = preview
        conv.updated_at = _utc_timestamp(now)
        if conv.title == "新会话" and message.role == "user" and preview:
            conv.title = preview
        self._cache_conversation(conv)
        return True

    async def get_messages(self, session_id: str) -> list[dict[str, Any]]:
        """获取会话的所有消息（LLM 格式）。"""
        conv = await self.get_session(session_id)
        if not conv:
            return []
        return self._conversation_to_llm_messages(conv)

    async def get_message_count(self, session_id: str) -> int:
        """获取消息数量"""
        conv = await self.get_session(session_id)
        return conv.message_count if conv else 0

    async def clear_session(self, session_id: str) -> bool:
        """清空会话"""
        factory = get_session_factory()
        async with factory() as db:
            session_row = await db.get(ChatSession, session_id)
            if not session_row:
                return False
            await db.delete(session_row)
            await db.commit()
        self._memory_store.pop(session_id, None)
        return True

    async def rename_session(self, session_id: str, title: str, tenant_id: Optional[str] = None) -> Optional[Conversation]:
        """Rename a chat session."""
        new_title = (title or "").strip()
        if not new_title:
            return None

        factory = get_session_factory()
        now = datetime.now(timezone.utc)
        conv = await self.get_session(session_id, tenant_id=tenant_id)
        if not conv:
            return None

        async with factory() as db:
            session_row = await db.get(ChatSession, session_id)
            if not session_row:
                return None
            session_row.title = new_title[:256]
            session_row.updated_at = now
            await db.commit()

        conv.title = new_title[:256]
        conv.updated_at = _utc_timestamp(now)
        self._cache_conversation(conv)
        return conv

    async def export_session(self, session_id: str, tenant_id: Optional[str] = None) -> Optional[dict[str, Any]]:
        """Export a session with its messages for download."""
        conv = await self.get_session(session_id, tenant_id=tenant_id)
        if not conv:
            return None

        return {
            "session": {
                "id": conv.session_id,
                "tenant_id": conv.tenant_id,
                "user_id": conv.user_id,
                "title": conv.title,
                "summary": conv.summary,
                "model_name": conv.model_name,
                "created_at": conv.created_at,
                "updated_at": conv.updated_at,
                "last_message_preview": conv.last_message_preview,
                "message_count": conv.message_count,
                "metadata": conv.metadata,
            },
            "messages": self._conversation_to_ui_messages(conv),
        }

    async def get_recent_messages(self, session_id: str, n: int) -> list[dict[str, Any]]:
        """Get the N most recent messages in LLM format."""
        conv = await self.get_session(session_id)
        if not conv:
            return []
        recent = conv.messages[-n:] if n > 0 else conv.messages
        temp = Conversation(
            session_id=conv.session_id,
            tenant_id=conv.tenant_id,
            user_id=conv.user_id,
            title=conv.title,
            summary=conv.summary,
            model_name=conv.model_name,
            messages=recent,
            created_at=conv.created_at,
            updated_at=conv.updated_at,
            last_message_preview=conv.last_message_preview,
            message_count=len(recent),
            metadata=conv.metadata,
        )
        return self._conversation_to_llm_messages(temp)

    async def replace_messages(self, session_id: str, messages: list[dict[str, Any]]) -> bool:
        """Replace all messages in a session (used after compression)."""
        conv = await self.get_session(session_id)
        if not conv:
            return False

        factory = get_session_factory()
        now = datetime.now(timezone.utc)

        async with factory() as db:
            session_row = await db.get(ChatSession, session_id)
            if not session_row:
                return False

            await db.execute(delete(ChatMessage).where(ChatMessage.session_id == session_id))

            rebuilt: list[Message] = []
            for idx, m in enumerate(messages, start=1):
                msg = Message(
                    id=m.get("id") or _uuid(),
                    role=m.get("role", "user"),
                    content=m.get("content", ""),
                    tool_calls=m.get("tool_calls", []),
                    tool_call_id=m.get("tool_call_id"),
                    thinking=m.get("thinking"),
                    metadata=m.get("metadata", {}),
                )
                rebuilt.append(msg)
                db.add(ChatMessage(
                    id=msg.id,
                    session_id=session_id,
                    tenant_id=conv.tenant_id,
                    seq=idx,
                    role=msg.role,
                    content=msg.content,
                    thinking=msg.thinking,
                    tool_calls=msg.tool_calls or [],
                    tool_call_id=msg.tool_call_id,
                    extra_data=msg.metadata or {},
                    created_at=now,
                ))

            session_row.message_count = len(rebuilt)
            session_row.last_message_preview = _preview_text(rebuilt[-1].content) if rebuilt else ""
            session_row.last_message_at = now if rebuilt else None
            session_row.updated_at = now
            conv.messages = rebuilt
            conv.message_count = len(rebuilt)
            conv.last_message_preview = session_row.last_message_preview or ""
            conv.updated_at = _utc_timestamp(now)
            conv.model_name = session_row.model_name
            self._cache_conversation(conv)
            await db.commit()
        return True


context_manager = ContextManager()
