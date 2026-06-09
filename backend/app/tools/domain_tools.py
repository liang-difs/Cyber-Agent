"""Domain Investigation Tools — WHOIS, DNS, SSL certificate lookups.

域名调查工具集：WHOIS 注册信息、DNS 记录、SSL 证书查询。
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import Field

from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)


# ── WHOIS Lookup ──────────────────────────────────────────


class WhoisInput(ToolInput):
    domain: str = Field(..., description="域名，如 example.com")


class WhoisLookupTool:
    """查询域名 WHOIS 注册信息"""

    name = "whois_lookup"
    version = "v1"
    input_class = WhoisInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "whois_lookup",
                "description": "查询域名 WHOIS 注册信息：注册商、注册时间、过期时间、注册人国家。用于判断域名可信度（新注册域名风险更高）。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "域名，如 example.com"},
                    },
                    "required": ["domain"],
                },
            },
        }

    async def execute(self, input_data: WhoisInput) -> ToolResult:
        start = time.time()
        domain = input_data.domain.strip().lower()

        # 移除协议前缀
        if "://" in domain:
            domain = domain.split("://")[1].split("/")[0]

        try:
            import whois
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: whois.whois(domain)
            )

            data = {
                "domain": domain,
                "registrar": result.registrar,
                "creation_date": str(result.creation_date) if result.creation_date else None,
                "expiration_date": str(result.expiration_date) if result.expiration_date else None,
                "updated_date": str(result.updated_date) if result.updated_date else None,
                "name_servers": result.name_servers if result.name_servers else [],
                "country": result.country,
                "org": result.org,
                "registrant": result.name,
                "emails": result.emails if hasattr(result, "emails") and result.emails else [],
                "dnssec": result.dnssec if hasattr(result, "dnssec") else None,
                "status": result.status if result.status else [],
            }

            # 计算域名年龄
            if result.creation_date:
                try:
                    if isinstance(result.creation_date, list):
                        creation = result.creation_date[0]
                    else:
                        creation = result.creation_date
                    if isinstance(creation, datetime):
                        age_days = (datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)).days
                        data["age_days"] = age_days
                        data["is_new"] = age_days < 30
                except Exception:
                    pass

            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data=data,
                confidence=0.9,
                evidence_source=["whois"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        except ImportError:
            # python-whois 未安装，尝试 RDAP
            return await self._rdap_fallback(domain, input_data, start)
        except Exception as e:
            error_str = str(e)
            # "No match" 表示域名未注册/已过期，这是有效信息而非错误
            if "no match" in error_str.lower() or "not found" in error_str.lower():
                return ToolResult(
                    success=True,
                    tool_name=self.name,
                    tool_version=self.version,
                    data={
                        "domain": domain,
                        "registrar": None,
                        "creation_date": None,
                        "expiration_date": None,
                        "registered": False,
                        "status": ["not_found"],
                        "summary": "域名未在 WHOIS 数据库中找到，可能未注册、已过期或启用了隐私保护",
                    },
                    confidence=0.8,
                    evidence_source=["whois"],
                    trace_id=input_data.trace_id,
                    execution_time_ms=int((time.time() - start) * 1000),
                )
            logger.warning("WHOIS lookup failed for %s: %s", domain, e)
            return await self._rdap_fallback(domain, input_data, start)

    async def _rdap_fallback(self, domain: str, input_data: WhoisInput, start: float) -> ToolResult:
        """RDAP 协议查询（无需 python-whois）"""
        import httpx

        try:
            # 使用 RDAP 服务
            tld = domain.split(".")[-1]
            rdap_urls = [
                f"https://rdap.verisign.com/com/v1/domain/{domain}",
                f"https://rdap.org/domain/{domain}",
            ]

            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                for url in rdap_urls:
                    try:
                        resp = await client.get(url, headers={"Accept": "application/rdap+json"})
                        if resp.status_code == 200:
                            rdap = resp.json()

                            # 提取关键信息
                            events = {e.get("eventAction"): e.get("eventDate") for e in rdap.get("events", [])}
                            nameservers = [ns.get("ldhName", "") for ns in rdap.get("nameservers", [])]

                            data = {
                                "domain": domain,
                                "registrar": rdap.get("entities", [{}])[0].get("vcardArray", [])[1][0][3] if rdap.get("entities") else None,
                                "creation_date": events.get("registration"),
                                "expiration_date": events.get("expiration"),
                                "updated_date": events.get("last changed"),
                                "name_servers": nameservers,
                                "status": rdap.get("status", []),
                                "source": "rdap",
                            }

                            # 计算域名年龄
                            if data.get("creation_date"):
                                try:
                                    creation = datetime.fromisoformat(data["creation_date"].replace("Z", "+00:00"))
                                    age_days = (datetime.now(timezone.utc) - creation).days
                                    data["age_days"] = age_days
                                    data["is_new"] = age_days < 30
                                except Exception:
                                    pass

                            return ToolResult(
                                success=True,
                                tool_name=self.name,
                                tool_version=self.version,
                                data=data,
                                confidence=0.85,
                                evidence_source=["rdap"],
                                trace_id=input_data.trace_id,
                                execution_time_ms=int((time.time() - start) * 1000),
                            )
                    except Exception:
                        continue

            # 所有 RDAP 服务都失败 — 可能是域名未注册
            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data={
                    "domain": domain,
                    "registered": False,
                    "status": ["not_found"],
                    "summary": "域名未在 WHOIS/RDAP 数据库中找到，可能未注册、已过期或启用了隐私保护",
                },
                confidence=0.7,
                evidence_source=["whois"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={"domain": domain, "error": str(e)},
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )


# ── DNS Lookup ────────────────────────────────────────────


class DnsInput(ToolInput):
    domain: str = Field(..., description="域名")
    record_types: str = Field(default="A,AAAA,MX,NS,TXT,CNAME", description="查询的记录类型，逗号分隔")


class DnsLookupTool:
    """查询域名 DNS 记录"""

    name = "dns_lookup"
    version = "v1"
    input_class = DnsInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "dns_lookup",
                "description": "查询域名 DNS 记录（A/AAAA/MX/NS/TXT/CNAME）。用于分析域名基础设施、邮件服务器、CDN 配置等。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "域名"},
                        "record_types": {
                            "type": "string",
                            "description": "查询的记录类型，逗号分隔，默认 A,AAAA,MX,NS,TXT,CNAME",
                        },
                    },
                    "required": ["domain"],
                },
            },
        }

    async def execute(self, input_data: DnsInput) -> ToolResult:
        start = time.time()
        domain = input_data.domain.strip().lower()

        if "://" in domain:
            domain = domain.split("://")[1].split("/")[0]

        record_types = [t.strip().upper() for t in input_data.record_types.split(",")]

        results: dict[str, Any] = {"domain": domain, "records": {}}

        try:
            import dns.resolver
            import dns.rdatatype

            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            for rtype in record_types:
                try:
                    answers = resolver.resolve(domain, rtype)
                    records = []
                    for rdata in answers:
                        records.append(str(rdata))
                    if records:
                        results["records"][rtype] = records
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    results["records"][rtype] = []
                except Exception:
                    results["records"][rtype] = []

            # 检测可疑配置
            warnings = []
            if "TXT" in results["records"]:
                for txt in results["records"]["TXT"]:
                    if "spf" not in txt.lower() and "dmarc" not in txt.lower():
                        if len(txt) > 200:
                            warnings.append(f"异常长 TXT 记录（{len(txt)} 字符），可能用于数据外泄")

            if "NS" in results["records"]:
                ns_list = results["records"]["NS"]
                if len(ns_list) == 1:
                    warnings.append("仅有一个 NS 记录，缺乏冗余")

            results["warnings"] = warnings
            results["has_a_record"] = len(results["records"].get("A", [])) > 0
            results["a_records"] = results["records"].get("A", [])

            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data=results,
                confidence=0.95,
                evidence_source=["dns"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        except ImportError:
            # dnspython 未安装，使用 socket 降级
            return await self._socket_fallback(domain, input_data, start)
        except Exception as e:
            logger.warning("DNS lookup failed for %s: %s", domain, e)
            return await self._socket_fallback(domain, input_data, start)

    async def _socket_fallback(self, domain: str, input_data: DnsInput, start: float) -> ToolResult:
        """socket 降级查询（仅 A 记录）"""
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(domain))
            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data={"domain": domain, "records": {"A": [ip]}, "source": "socket_fallback"},
                confidence=0.7,
                evidence_source=["dns"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={"domain": domain, "error": str(e)},
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )


# ── SSL Certificate Lookup ────────────────────────────────


class SslInput(ToolInput):
    domain: str = Field(..., description="域名")
    port: int = Field(default=443, description="端口，默认 443")


class SslLookupTool:
    """查询域名 SSL/TLS 证书信息"""

    name = "ssl_lookup"
    version = "v1"
    input_class = SslInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "ssl_lookup",
                "description": "查询域名 SSL/TLS 证书信息：颁发者、有效期、主题、SAN。用于判断域名可信度（免费证书 + 新域名 = 高风险）。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "域名"},
                        "port": {"type": "integer", "description": "端口，默认 443"},
                    },
                    "required": ["domain"],
                },
            },
        }

    async def execute(self, input_data: SslInput) -> ToolResult:
        start = time.time()
        domain = input_data.domain.strip().lower()

        if "://" in domain:
            domain = domain.split("://")[1].split("/")[0]

        try:
            loop = asyncio.get_event_loop()
            cert_info = await loop.run_in_executor(None, self._get_cert, domain, input_data.port)

            # 判断证书风险
            warnings = []
            issuer = cert_info.get("issuer_str", "").lower()
            if "let's encrypt" in issuer or "letsencrypt" in issuer or "free ssl" in issuer:
                warnings.append("免费 SSL 证书（Let's Encrypt），钓鱼网站常用")

            not_before = cert_info.get("not_before")
            not_after = cert_info.get("not_after")
            if not_before:
                try:
                    nb = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                    cert_age = (datetime.now(timezone.utc) - nb).days
                    cert_info["cert_age_days"] = cert_age
                    if cert_age < 7:
                        warnings.append(f"证书签发仅 {cert_age} 天，新证书风险较高")
                except Exception:
                    pass

            cert_info["warnings"] = warnings
            cert_info["domain"] = domain

            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data=cert_info,
                confidence=0.9,
                evidence_source=["ssl"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        except Exception as e:
            logger.warning("SSL lookup failed for %s: %s", domain, e)
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={"domain": domain, "error": str(e)},
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

    @staticmethod
    def _get_cert(domain: str, port: int) -> dict[str, Any]:
        """获取 SSL 证书信息"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_bin = ssock.getpeercert(binary_form=True)

                # 解析证书信息
                def parse_name(name_tuples):
                    if not name_tuples:
                        return ""
                    parts = []
                    for rdn in name_tuples:
                        for attr in rdn:
                            parts.append(f"{attr[0]}={attr[1]}")
                    return ", ".join(parts)

                issuer = parse_name(cert.get("issuer", ()))
                subject = parse_name(cert.get("subject", ()))
                san = []
                for type_name, value in cert.get("subjectAltName", ()):
                    san.append(value)

                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")

                # 转换时间格式
                def parse_cert_time(t):
                    if not t:
                        return None
                    try:
                        return datetime.strptime(t, "%b %d %H:%M:%S %Y %Z").isoformat()
                    except Exception:
                        return t

                import hashlib
                fingerprint = hashlib.sha256(cert_bin).hexdigest() if cert_bin else None

                return {
                    "issuer_str": issuer,
                    "subject_str": subject,
                    "san": san,
                    "not_before": parse_cert_time(not_before),
                    "not_after": parse_cert_time(not_after),
                    "serial_number": cert.get("serialNumber"),
                    "version": cert.get("version"),
                    "fingerprint_sha256": fingerprint,
                    "is_expired": False,  # ssl 模块会自动验证
                }


# 创建工具实例
whois_lookup_tool = WhoisLookupTool()
dns_lookup_tool = DnsLookupTool()
ssl_lookup_tool = SslLookupTool()
