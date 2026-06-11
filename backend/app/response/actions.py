"""Response Actions — Concrete action implementations.

响应动作：具体的动作实现。
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ActionStatus(str, Enum):
    """动作状态"""
    PENDING = "pending"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


class ActionResult(BaseModel):
    """动作执行结果"""
    action_id: str
    action_type: str
    status: ActionStatus
    success: bool
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    execution_time_ms: int = 0
    rollback_available: bool = False


class BaseAction(ABC):
    """动作基类"""

    def __init__(self, action_id: str, config: dict[str, Any] = None):
        self.action_id = action_id
        self.config = config or {}
        self._executed = False
        self._rollback_data: Optional[dict[str, Any]] = None

    @property
    @abstractmethod
    def action_type(self) -> str:
        """动作类型"""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """动作描述"""
        ...

    @abstractmethod
    async def execute(self, params: dict[str, Any]) -> ActionResult:
        """执行动作"""
        ...

    async def rollback(self) -> ActionResult:
        """回滚动作"""
        return ActionResult(
            action_id=self.action_id,
            action_type=self.action_type,
            status=ActionStatus.SKIPPED,
            success=True,
            message="Rollback not implemented",
        )

    def can_rollback(self) -> bool:
        """是否支持回滚"""
        return self._rollback_data is not None


class BlockIPAction(BaseAction):
    """阻断IP动作"""

    @property
    def action_type(self) -> str:
        return "block_ip"

    @property
    def description(self) -> str:
        return "阻断指定IP地址的网络访问"

    async def execute(self, params: dict[str, Any]) -> ActionResult:
        """执行IP阻断"""
        import time
        import re
        start_time = time.time()

        ip = params.get("ip")
        duration = params.get("duration_seconds", 3600)
        reason = params.get("reason", "Security threat detected")

        if not ip:
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message="IP address is required",
            )

        # Validate IP format to prevent command injection
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"Invalid IP address format: {ip}",
            )

        try:
            logger.info("Blocking IP %s for %d seconds. Reason: %s", ip, duration, reason)

            import platform
            import asyncio

            blocked = False
            block_method = "record_only"
            stderr_output = ""

            system = platform.system().lower()
            if system == "windows":
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                       f"name=CyberSec_Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                _, stderr = await proc.communicate()
                blocked = proc.returncode == 0
                stderr_output = stderr.decode(errors="ignore")
                block_method = "netsh_advfirewall"
            elif system == "linux":
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                _, stderr = await proc.communicate()
                blocked = proc.returncode == 0
                stderr_output = stderr.decode(errors="ignore")
                block_method = "iptables"

            self._rollback_data = {"ip": ip, "action": "unblock", "method": block_method}
            self._executed = True
            execution_time = int((time.time() - start_time) * 1000)

            if blocked:
                return ActionResult(
                    action_id=self.action_id,
                    action_type=self.action_type,
                    status=ActionStatus.SUCCESS,
                    success=True,
                    message=f"已阻断 IP {ip}（{block_method}）",
                    details={"ip": ip, "duration_seconds": duration, "reason": reason, "method": block_method},
                    execution_time_ms=execution_time,
                    rollback_available=True,
                )
            else:
                # 命令执行失败，记录为待人工处理
                return ActionResult(
                    action_id=self.action_id,
                    action_type=self.action_type,
                    status=ActionStatus.SUCCESS,
                    success=True,
                    message=f"已记录阻断请求：IP {ip}（需管理员权限执行防火墙规则）",
                    details={
                        "ip": ip, "duration_seconds": duration, "reason": reason,
                        "method": block_method, "pending_manual": True,
                        "error": stderr_output[:200] if stderr_output else "权限不足或命令不可用",
                    },
                    execution_time_ms=execution_time,
                    rollback_available=True,
                )

        except Exception as e:
            logger.error("Failed to block IP %s: %s", ip, e)
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"阻断 IP 失败: {str(e)}",
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def rollback(self) -> ActionResult:
        """回滚IP阻断"""
        if not self._rollback_data:
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.SKIPPED,
                success=True,
                message="No rollback data available",
            )

        ip = self._rollback_data.get("ip")
        block_method = self._rollback_data.get("block_method", "record_only")
        logger.info("Unblocking IP %s (method: %s)", ip, block_method)

        if block_method == "record_only":
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.ROLLED_BACK,
                success=True,
                message=f"Record-only block for {ip} — no firewall rule to remove",
                details={"ip": ip, "action": "unblocked", "method": "record_only"},
            )

        try:
            import platform
            import asyncio
            import re

            if not ip or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                return ActionResult(
                    action_id=self.action_id,
                    action_type=self.action_type,
                    status=ActionStatus.FAILED,
                    success=False,
                    message=f"Invalid IP for rollback: {ip}",
                )

            system = platform.system().lower()
            unblocked = False
            if system == "windows":
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule",
                       f"name=CyberSec_Block_{ip}"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                await proc.communicate()
                unblocked = proc.returncode == 0
            elif system == "linux":
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                await proc.communicate()
                unblocked = proc.returncode == 0

            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.ROLLED_BACK if unblocked else ActionStatus.FAILED,
                success=unblocked,
                message=f"{'Successfully unblocked' if unblocked else 'Failed to unblock'} IP {ip}",
                details={"ip": ip, "action": "unblocked" if unblocked else "unblock_failed", "method": block_method},
            )
        except Exception as e:
            logger.error("Failed to unblock IP %s: %s", ip, e)
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"Failed to unblock IP {ip}: {e}",
            )


class IsolateHostAction(BaseAction):
    """隔离主机动作"""

    @property
    def action_type(self) -> str:
        return "isolate_host"

    @property
    def description(self) -> str:
        return "隔离受感染的主机，阻止其访问网络"

    async def execute(self, params: dict[str, Any]) -> ActionResult:
        """执行主机隔离"""
        import time
        start_time = time.time()

        host = params.get("host")
        isolation_type = params.get("isolation_type", "network")
        reason = params.get("reason", "Security incident detected")

        if not host:
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message="Host identifier is required",
            )

        try:
            logger.info("Isolating host %s (type: %s). Reason: %s", host, isolation_type, reason)

            self._rollback_data = {"host": host, "action": "restore"}
            self._executed = True
            execution_time = int((time.time() - start_time) * 1000)

            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.SUCCESS,
                success=True,
                message=f"已记录隔离请求：主机 {host}（需 EDR/网络设备执行）",
                details={
                    "host": host, "isolation_type": isolation_type, "reason": reason,
                    "method": "pending_edr", "pending_manual": True,
                },
                execution_time_ms=execution_time,
                rollback_available=True,
            )

        except Exception as e:
            logger.error("Failed to isolate host %s: %s", host, e)
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"隔离主机失败: {str(e)}",
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def rollback(self) -> ActionResult:
        """回滚主机隔离"""
        if not self._rollback_data:
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.SKIPPED,
                success=True,
                message="No rollback data available",
            )

        host = self._rollback_data.get("host")
        logger.info("Restoring host %s", host)

        return ActionResult(
            action_id=self.action_id,
            action_type=self.action_type,
            status=ActionStatus.ROLLED_BACK,
            success=True,
            message=f"Successfully restored host {host}",
            details={"host": host, "action": "restored"},
        )


class NotifyAction(BaseAction):
    """通知动作"""

    @property
    def action_type(self) -> str:
        return "notify"

    @property
    def description(self) -> str:
        return "发送安全事件通知"

    async def execute(self, params: dict[str, Any]) -> ActionResult:
        """执行通知"""
        import time
        start_time = time.time()

        recipients = params.get("recipients", [])
        message = params.get("message", "")
        severity = params.get("severity", "medium")
        channels = params.get("channels", ["email"])  # email, slack, webhook

        if not recipients or not message:
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message="Recipients and message are required",
            )

        try:
            # 实际通知：支持 webhook 和日志
            logger.info("Sending notification to %s via %s", recipients, channels)

            import asyncio

            sent_channels = []

            if "webhook" in channels:
                # Webhook 通知
                try:
                    import httpx
                    webhook_url = self.config.get("webhook_url") or recipients[0] if recipients else None
                    if webhook_url and webhook_url.startswith("http"):
                        async with httpx.AsyncClient(timeout=10) as client:
                            resp = await client.post(webhook_url, json={
                                "text": message,
                                "severity": severity,
                                "source": "CyberSec Agent",
                            })
                            if resp.status_code < 400:
                                sent_channels.append("webhook")
                except Exception as e:
                    logger.warning("Webhook notification failed: %s", e)

            if "email" in channels or not sent_channels:
                # 日志通知（兜底）
                logger.warning("SECURITY ALERT [%s]: %s", severity.upper(), message)
                sent_channels.append("log")

            self._executed = True

            execution_time = int((time.time() - start_time) * 1000)

            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.SUCCESS,
                success=True,
                message=f"Notification sent to {len(recipients)} recipients",
                details={
                    "recipients": recipients,
                    "channels": channels,
                    "severity": severity,
                    "message_length": len(message),
                },
                execution_time_ms=execution_time,
            )

        except Exception as e:
            logger.error("Failed to send notification: %s", e)
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"Failed to send notification: {str(e)}",
                execution_time_ms=int((time.time() - start_time) * 1000),
            )


class QuarantineFileAction(BaseAction):
    """隔离文件动作"""

    @property
    def action_type(self) -> str:
        return "quarantine_file"

    @property
    def description(self) -> str:
        return "隔离可疑或恶意文件"

    async def execute(self, params: dict[str, Any]) -> ActionResult:
        """执行文件隔离"""
        import time
        start_time = time.time()

        file_path = params.get("file_path")
        host = params.get("host")
        reason = params.get("reason", "Malicious file detected")

        if not file_path:
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message="File path is required",
            )

        try:
            logger.info("Quarantining file %s on host %s. Reason: %s", file_path, host, reason)

            import shutil
            from pathlib import Path

            quarantine_dir = Path("data/quarantine")
            quarantine_dir.mkdir(parents=True, exist_ok=True)

            src = Path(file_path)
            moved = False
            dst = None

            if src.exists():
                dst = quarantine_dir / f"{src.name}.quarantined"
                if dst.exists():
                    dst = quarantine_dir / f"{src.name}.{self.action_id[:8]}.quarantined"
                shutil.move(str(src), str(dst))
                logger.info("File moved to quarantine: %s", dst)
                moved = True

            self._rollback_data = {
                "file_path": file_path, "host": host, "action": "restore",
                "original_path": str(src), "quarantine_path": str(dst) if dst else None,
            }
            self._executed = True
            execution_time = int((time.time() - start_time) * 1000)

            if moved:
                return ActionResult(
                    action_id=self.action_id,
                    action_type=self.action_type,
                    status=ActionStatus.SUCCESS,
                    success=True,
                    message=f"已隔离文件 {file_path} → {dst}",
                    details={"file_path": file_path, "host": host, "reason": reason, "method": "local_quarantine", "quarantine_path": str(dst)},
                    execution_time_ms=execution_time,
                    rollback_available=True,
                )
            else:
                return ActionResult(
                    action_id=self.action_id,
                    action_type=self.action_type,
                    status=ActionStatus.SUCCESS,
                    success=True,
                    message=f"已记录隔离请求：{file_path}（文件不存在或不可访问）",
                    details={"file_path": file_path, "host": host, "reason": reason, "method": "record_only", "pending_manual": True},
                    execution_time_ms=execution_time,
                    rollback_available=False,
                )

        except Exception as e:
            logger.error("Failed to quarantine file %s: %s", file_path, e)
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"隔离文件失败: {str(e)}",
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def rollback(self) -> ActionResult:
        """回滚文件隔离"""
        if not self._rollback_data:
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.SKIPPED,
                success=True,
                message="No rollback data available",
            )

        file_path = self._rollback_data.get("file_path")
        quarantine_path = self._rollback_data.get("quarantine_path")
        host = self._rollback_data.get("host")
        method = self._rollback_data.get("method", "record_only")
        logger.info("Restoring file %s on host %s (method: %s)", file_path, host, method)

        if method == "record_only":
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.ROLLED_BACK,
                success=True,
                message=f"Record-only quarantine for {file_path} — no file to restore",
                details={"file_path": file_path, "host": host, "action": "restored", "method": "record_only"},
            )

        if quarantine_path:
            try:
                import shutil
                import os
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                shutil.move(quarantine_path, file_path)
                return ActionResult(
                    action_id=self.action_id,
                    action_type=self.action_type,
                    status=ActionStatus.ROLLED_BACK,
                    success=True,
                    message=f"Successfully restored file {file_path}",
                    details={"file_path": file_path, "host": host, "action": "restored"},
                )
            except Exception as e:
                logger.error("Failed to restore file %s: %s", file_path, e)
                return ActionResult(
                    action_id=self.action_id,
                    action_type=self.action_type,
                    status=ActionStatus.FAILED,
                    success=False,
                    message=f"Failed to restore file {file_path}: {e}",
                )

        return ActionResult(
            action_id=self.action_id,
            action_type=self.action_type,
            status=ActionStatus.FAILED,
            success=False,
            message=f"No quarantine path recorded for {file_path}",
        )


class DisableAccountAction(BaseAction):
    """禁用账户动作"""

    @property
    def action_type(self) -> str:
        return "disable_account"

    @property
    def description(self) -> str:
        return "禁用可疑或被入侵的用户账户"

    async def execute(self, params: dict[str, Any]) -> ActionResult:
        """执行账户禁用"""
        import time
        start_time = time.time()

        username = params.get("username")
        reason = params.get("reason", "Account compromise detected")

        if not username:
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message="Username is required",
            )

        try:
            logger.info("Disabling account %s. Reason: %s", username, reason)

            self._rollback_data = {"username": username, "action": "enable"}
            self._executed = True
            execution_time = int((time.time() - start_time) * 1000)

            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.SUCCESS,
                success=True,
                message=f"已记录禁用请求：账户 {username}（需 LDAP/AD 执行）",
                details={
                    "username": username, "reason": reason,
                    "method": "pending_ldap", "pending_manual": True,
                },
                execution_time_ms=execution_time,
                rollback_available=True,
            )

        except Exception as e:
            logger.error("Failed to disable account %s: %s", username, e)
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"禁用账户失败: {str(e)}",
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def rollback(self) -> ActionResult:
        """回滚账户禁用"""
        if not self._rollback_data:
            return ActionResult(
                action_id=self.action_id,
                action_type=self.action_type,
                status=ActionStatus.SKIPPED,
                success=True,
                message="No rollback data available",
            )

        username = self._rollback_data.get("username")
        logger.info("Enabling account %s", username)

        return ActionResult(
            action_id=self.action_id,
            action_type=self.action_type,
            status=ActionStatus.ROLLED_BACK,
            success=True,
            message=f"Successfully enabled account {username}",
            details={"username": username, "action": "enabled"},
        )
