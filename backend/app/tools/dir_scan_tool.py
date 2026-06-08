"""Directory Scan Tool — web directory and file enumeration.

Uses dirsearch CLI or a built-in wordlist-based scanner.
Falls back to a lightweight built-in scanner if dirsearch is not installed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time
from typing import Any

import httpx
from pydantic import Field

from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)

# Lightweight built-in common paths (top ~50)
_COMMON_PATHS = [
    "admin", "login", "api", "robots.txt", "sitemap.xml", ".env", ".git/HEAD",
    ".git/config", "wp-admin", "wp-login.php", "wp-content", "xmlrpc.php",
    "administrator", "phpmyadmin", "server-status", "server-info",
    ".htaccess", "web.config", "backup", "db", "database", "sql",
    "config", "conf", "test", "debug", "console", "actuator",
    "swagger", "api-docs", "openapi.json", "graphql",
    "uploads", "upload", "files", "static", "assets", "media",
    ".svn/entries", ".DS_Store", "crossdomain.xml", "favicon.ico",
    "info.php", "phpinfo.php", "shell", "cmd", "admin.php",
    "cgi-bin", "bin", "src", "vendor", "node_modules",
    "package.json", "composer.json", "Dockerfile", "docker-compose.yml",
    "README.md", "CHANGELOG.md", ".well-known/security.txt",
]


class DirScanInput(ToolInput):
    """Directory Scan Tool input."""

    target: str = Field(..., description="目标 URL，如 https://example.com")
    wordlist: str = Field(
        default="builtin",
        description="字表类型：builtin(内置常见路径) 或 dirsearch(使用 dirsearch 工具)",
    )
    extensions: str = Field(default="", description="文件扩展名过滤，如 'php,html,js'")
    threads: int = Field(default=10, ge=1, le=50, description="并发线程数")
    timeout: int = Field(default=120, ge=10, le=600, description="扫描超时（秒）")


async def _builtin_scan(target: str, paths: list[str], extensions: list[str], concurrency: int) -> list[dict[str, Any]]:
    """Lightweight async directory scanner using httpx."""
    base = target.rstrip("/")
    sem = asyncio.Semaphore(concurrency)
    results: list[dict[str, Any]] = []

    # Build URL list
    urls = [f"{base}/{p}" for p in paths]
    if extensions:
        ext_urls = []
        for p in paths:
            if "." not in p.split("/")[-1]:
                for ext in extensions:
                    ext_urls.append(f"{base}/{p}.{ext}")
        urls.extend(ext_urls)

    async def check_url(url: str) -> None:
        async with sem:
            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8) as client:
                    resp = await client.get(url)
                    if resp.status_code not in (404, 403, 400, 429):
                        results.append({
                            "url": str(resp.url),
                            "status": resp.status_code,
                            "content_length": len(resp.content),
                            "content_type": resp.headers.get("content-type", ""),
                            "redirect": str(resp.url) != url,
                        })
            except Exception:
                pass

    await asyncio.gather(*(check_url(u) for u in urls))
    results.sort(key=lambda x: x.get("status", 0))
    return results


class DirScanTool:
    """Web目录扫描工具 — 发现隐藏路径、备份文件和敏感文件。"""

    name = "dir_scan"
    version = "v1"
    input_class = DirScanInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": (
                    "Web 目录和文件枚举扫描。检测目标站点的隐藏路径、"
                    "备份文件、配置文件暴露、管理后台等。"
                    "支持内置常见路径字典或调用 dirsearch 工具。"
                    "渗透测试信息收集阶段使用。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "目标 URL"},
                        "wordlist": {
                            "type": "string",
                            "description": "字表类型：builtin 或 dirsearch",
                        },
                        "extensions": {"type": "string", "description": "文件扩展名过滤"},
                        "threads": {"type": "integer", "description": "并发线程数"},
                    },
                    "required": ["target"],
                },
            },
        }

    async def execute(self, input_data: DirScanInput) -> ToolResult:
        start = time.monotonic()
        extensions = [e.strip().lstrip(".") for e in input_data.extensions.split(",") if e.strip()]

        # Try dirsearch first if requested
        if input_data.wordlist == "dirsearch" and shutil.which("dirsearch"):
            try:
                return await self._run_dirsearch(input_data, start)
            except Exception as e:
                logger.warning("dirsearch failed, falling back to builtin: %s", e)

        # Built-in scanner
        try:
            findings = await _builtin_scan(
                input_data.target, _COMMON_PATHS, extensions, input_data.threads
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"Directory scan failed: {e}",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )

        # Classify findings
        sensitive = [f for f in findings if f.get("url", "").endswith(
            (".env", ".git/HEAD", ".git/config", ".htaccess", "web.config",
             "wp-config.php", "config.php", "database.sql", "backup.sql")
        )]
        high_status = [f for f in findings if f.get("status") in (200, 301, 302)]

        elapsed_ms = int((time.monotonic() - start) * 1000)

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data={
                "target": input_data.target,
                "total_found": len(findings),
                "sensitive_files": sensitive,
                "interesting": high_status[:30],
                "all_findings": findings,
            },
            error=None,
            confidence=0.8,
            evidence_source=["builtin_wordlist" if input_data.wordlist == "builtin" else "dirsearch"],
            trace_id=input_data.trace_id,
            execution_time_ms=elapsed_ms,
        )

    async def _run_dirsearch(self, input_data: DirScanInput, start: float) -> ToolResult:
        """Run dirsearch CLI."""
        args = [
            "dirsearch",
            "-u", input_data.target,
            "--format=json",
            "-t", str(input_data.threads),
            "-q",
        ]
        if input_data.extensions:
            args.extend(["-e", input_data.extensions])

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=input_data.timeout,
        )

        stdout_text = stdout.decode("utf-8", errors="replace")
        findings: list[dict[str, Any]] = []
        try:
            data = json.loads(stdout_text) if stdout_text.strip() else {}
            for entry in data.get("results", []):
                findings.append({
                    "url": entry.get("url", ""),
                    "status": entry.get("status", 0),
                    "content_length": entry.get("content-length", 0),
                    "redirect": entry.get("redirect", ""),
                })
        except json.JSONDecodeError:
            for line in stdout_text.strip().splitlines():
                if line.strip():
                    findings.append({"raw": line.strip()[:200]})

        elapsed_ms = int((time.monotonic() - start) * 1000)
        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data={
                "target": input_data.target,
                "total_found": len(findings),
                "findings": findings[:50],
            },
            error=None,
            confidence=0.85,
            evidence_source=["dirsearch"],
            trace_id=input_data.trace_id,
            execution_time_ms=elapsed_ms,
        )
