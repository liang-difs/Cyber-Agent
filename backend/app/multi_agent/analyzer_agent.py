"""Analyzer Agent — Performs deep data analysis.

分析Agent：执行深度数据分析，提取关键信息和洞察。
"""

from __future__ import annotations

import logging
from typing import Any

from app.multi_agent.base_agent import BaseAgent
from app.multi_agent.protocol import (
    AgentRole,
    TaskRequest,
    TaskResult,
)

logger = logging.getLogger(__name__)


class AnalyzerAgent(BaseAgent):
    """分析Agent — 负责深度数据分析"""

    def __init__(
        self,
        agent_id: str = "analyzer",
        llm_router: Any = None,
        tool_registry: Any = None,
    ):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.ANALYZER,
            llm_router=llm_router,
            tool_registry=tool_registry,
            capabilities=[
                "log_analysis",
                "traffic_analysis",
                "anomaly_detection",
                "pattern_recognition",
                "threat_correlation",
                "risk_assessment",
                "behavior_analysis",
            ],
        )

    async def execute_task(self, task: TaskRequest) -> TaskResult:
        """执行分析任务"""
        try:
            action = task.task_type
            parameters = task.parameters

            # 根据动作类型分发
            handler = self._get_handler(action)
            if handler:
                result = await handler(parameters)
            else:
                result = await self._generic_analysis(task)

            return TaskResult(
                task_id=task.task_id,
                success=True,
                result=result,
                agent_id=self.agent_id,
            )

        except Exception as e:
            logger.error("Analyzer task failed: %s", e)
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error=str(e),
                agent_id=self.agent_id,
            )

    def _get_handler(self, action: str):
        """获取动作处理器"""
        handlers = {
            "analyze_logs": self._analyze_logs,
            "analyze_network_traffic": self._analyze_traffic,
            "detect_anomalies": self._detect_anomalies,
            "extract_iocs": self._extract_iocs,
            "analyze_attack_vector": self._analyze_attack_vector,
            "analyze_attack_surface": self._analyze_attack_surface,
            "risk_analysis": self._risk_analysis,
            "risk_assessment": self._risk_analysis,
            "behavior_analysis": self._behavior_analysis,
            "pattern_recognition": self._pattern_recognition,
            "analyze_patterns": self._pattern_recognition,
            "threat_correlation": self._threat_correlation,
            "correlate_threat_intel": self._threat_correlation,
            "analyze_task": self._analyze_task_description,
        }
        return handlers.get(action)

    async def _analyze_logs(self, params: dict[str, Any]) -> dict[str, Any]:
        """分析日志数据"""
        log_content = params.get("content", "")
        log_type = params.get("log_type", "auto")

        # 使用log_analysis工具
        if self.tools and self.tools.get("log_analysis"):
            from app.governance.tool_protocol import ToolInput
            from app.tools.log_analysis_tool import LogAnalysisInput

            input_data = LogAnalysisInput(
                trace_id=params.get("trace_id", ""),
                tenant_id=params.get("tenant_id", "default"),
                log_content=log_content,
                log_type=log_type,
            )
            tool = self.tools.get("log_analysis")
            result = await tool.execute(input_data)

            return {
                "analysis_type": "log_analysis",
                "success": result.success,
                "content": log_content,
                "content_excerpt": log_content[:1000],
                "iocs": result.data.get("iocs", {}),
                "patterns": result.data.get("patterns", []),
                "anomalies": result.data.get("anomalies", []),
                "summary": result.data.get("summary", ""),
            }

        # Fallback: 基础分析
        return {
            "analysis_type": "log_analysis",
            "success": True,
            "content": log_content,
            "content_excerpt": log_content[:1000],
            "line_count": len(log_content.split("\n")),
            "basic_patterns": self._extract_basic_patterns(log_content),
        }

    async def _analyze_traffic(self, params: dict[str, Any]) -> dict[str, Any]:
        """分析网络流量"""
        pcap_path = params.get("pcap_path", "")

        if self.tools and self.tools.get("pcap_analysis"):
            from app.tools.pcap_tool import PcapToolInput

            input_data = PcapToolInput(
                trace_id=params.get("trace_id", ""),
                tenant_id=params.get("tenant_id", "default"),
                pcap_path=pcap_path,
            )
            tool = self.tools.get("pcap_analysis")
            result = await tool.execute(input_data)

            return {
                "analysis_type": "traffic_analysis",
                "success": result.success,
                "flows": result.data.get("flows", []),
                "dns_queries": result.data.get("dns", {}),
                "protocols": result.data.get("protocols", {}),
                "anomalies": result.data.get("anomalies", []),
                "external_ips": result.data.get("external_ips_for_lookup", []),
                "domains": result.data.get("domains_for_lookup", []),
            }

        return {"analysis_type": "traffic_analysis", "success": False, "error": "pcap_analysis tool not available"}

    async def _detect_anomalies(self, params: dict[str, Any]) -> dict[str, Any]:
        """检测异常行为"""
        data = params.get("data", {})
        context = params.get("context", {})

        anomalies = []

        # 检测高频连接
        if "connection_count" in data and data["connection_count"] > 1000:
            anomalies.append({
                "type": "high_frequency_connection",
                "severity": "medium",
                "detail": f"连接数异常高: {data['connection_count']}",
            })

        # 检测异常端口
        suspicious_ports = {4444, 5555, 6666, 7777, 8888, 9999}
        if "ports" in data:
            found = set(data["ports"]) & suspicious_ports
            if found:
                anomalies.append({
                    "type": "suspicious_port",
                    "severity": "high",
                    "detail": f"发现可疑端口: {found}",
                })

        # 检测DNS隧道
        if "dns_queries" in data:
            long_domains = [q for q in data["dns_queries"] if len(q) > 50]
            if long_domains:
                anomalies.append({
                    "type": "possible_dns_tunnel",
                    "severity": "high",
                    "detail": f"发现 {len(long_domains)} 个超长域名",
                })

        return {
            "analysis_type": "anomaly_detection",
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "risk_level": "high" if any(a["severity"] == "high" for a in anomalies) else "medium" if anomalies else "low",
        }

    async def _extract_iocs(self, params: dict[str, Any]) -> dict[str, Any]:
        """提取IoC指标"""
        content = params.get("content", "")

        import re

        # 提取IP地址
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = list(set(re.findall(ip_pattern, content)))

        # 提取域名
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = list(set(re.findall(domain_pattern, content)))

        # 提取哈希
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'

        hashes = {
            "md5": list(set(re.findall(md5_pattern, content))),
            "sha1": list(set(re.findall(sha1_pattern, content))),
            "sha256": list(set(re.findall(sha256_pattern, content))),
        }

        # 提取URL
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        urls = list(set(re.findall(url_pattern, content)))

        return {
            "analysis_type": "ioc_extraction",
            "iocs": {
                "ips": ips,
                "domains": domains,
                "hashes": hashes,
                "urls": urls,
            },
            "total_count": len(ips) + len(domains) + sum(len(v) for v in hashes.values()) + len(urls),
        }

    async def _analyze_attack_vector(self, params: dict[str, Any]) -> dict[str, Any]:
        """分析攻击向量"""
        evidence = params.get("evidence", {})

        # 分析攻击路径
        attack_vectors = []

        if "suspicious_ips" in evidence:
            attack_vectors.append({
                "type": "network_intrusion",
                "indicators": evidence["suspicious_ips"],
                "confidence": 0.7,
            })

        if "malicious_hashes" in evidence:
            attack_vectors.append({
                "type": "malware_delivery",
                "indicators": evidence["malicious_hashes"],
                "confidence": 0.8,
            })

        if "anomalous_logins" in evidence:
            attack_vectors.append({
                "type": "credential_abuse",
                "indicators": evidence["anomalous_logins"],
                "confidence": 0.6,
            })

        return {
            "analysis_type": "attack_vector",
            "attack_vectors": attack_vectors,
            "primary_vector": attack_vectors[0] if attack_vectors else None,
            "mitigation_suggestions": self._generate_mitigations(attack_vectors),
        }

    async def _risk_analysis(self, params: dict[str, Any]) -> dict[str, Any]:
        """风险分析"""
        vulnerabilities = params.get("vulnerabilities", [])
        assets = params.get("assets", [])

        # 计算风险分数
        risk_scores = []
        for vuln in vulnerabilities:
            cvss = vuln.get("cvss_score", 0)
            exposure = vuln.get("exposure", "low")
            asset_criticality = vuln.get("asset_criticality", "low")

            exposure_multiplier = {"high": 1.5, "medium": 1.0, "low": 0.5}.get(exposure, 0.5)
            criticality_multiplier = {"critical": 2.0, "high": 1.5, "medium": 1.0, "low": 0.5}.get(asset_criticality, 0.5)

            risk_score = cvss * exposure_multiplier * criticality_multiplier
            risk_scores.append({
                "vulnerability": vuln.get("id", ""),
                "risk_score": round(risk_score, 2),
                "priority": "critical" if risk_score >= 15 else "high" if risk_score >= 10 else "medium" if risk_score >= 5 else "low",
            })

        return {
            "analysis_type": "risk_assessment",
            "risk_scores": sorted(risk_scores, key=lambda x: x["risk_score"], reverse=True),
            "overall_risk": self._calculate_overall_risk(risk_scores),
            "recommendations": self._generate_risk_recommendations(risk_scores),
        }

    async def _behavior_analysis(self, params: dict[str, Any]) -> dict[str, Any]:
        """行为分析"""
        behaviors = params.get("behaviors", [])

        patterns = {
            "lateral_movement": False,
            "data_exfiltration": False,
            "persistence": False,
            "privilege_escalation": False,
            "command_and_control": False,
        }

        for behavior in behaviors:
            behavior_type = behavior.get("type", "")
            if behavior_type in patterns:
                patterns[behavior_type] = True

        return {
            "analysis_type": "behavior_analysis",
            "detected_patterns": {k: v for k, v in patterns.items() if v},
            "attack_stage": self._determine_attack_stage(patterns),
            "threat_level": "critical" if sum(patterns.values()) >= 3 else "high" if sum(patterns.values()) >= 2 else "medium",
        }

    async def _analyze_attack_surface(self, params: dict[str, Any]) -> dict[str, Any]:
        """Assess the exposed attack surface from execution results."""
        open_ports = params.get("open_ports", params.get("ports", []))
        services = params.get("services", {})
        vulnerabilities = params.get("vulnerabilities", [])

        if isinstance(services, dict):
            exposed_service_count = len(services)
            exposed_services = [{"port": port, "service": service} for port, service in services.items()]
        elif isinstance(services, list):
            exposed_service_count = len(services)
            exposed_services = services
        else:
            exposed_service_count = 0
            exposed_services = []

        if isinstance(open_ports, list):
            open_port_count = len(open_ports)
        elif isinstance(open_ports, dict):
            open_port_count = len(open_ports)
        elif open_ports:
            open_port_count = 1
        else:
            open_port_count = 0

        if isinstance(vulnerabilities, list):
            vulnerability_count = len(vulnerabilities)
        elif isinstance(vulnerabilities, dict):
            vulnerability_count = len(vulnerabilities)
        elif vulnerabilities:
            vulnerability_count = 1
        else:
            vulnerability_count = 0

        risk_score = min(10, open_port_count // 2 + exposed_service_count + vulnerability_count)
        if risk_score >= 8:
            risk_level = "critical"
        elif risk_score >= 5:
            risk_level = "high"
        elif risk_score >= 3:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "analysis_type": "attack_surface_analysis",
            "open_ports": open_ports,
            "services": services,
            "exposed_services": exposed_services,
            "vulnerabilities": vulnerabilities,
            "open_port_count": open_port_count,
            "exposed_service_count": exposed_service_count,
            "vulnerability_count": vulnerability_count,
            "risk_level": risk_level,
            "summary": f"暴露端口 {open_port_count} 个，服务 {exposed_service_count} 个，漏洞 {vulnerability_count} 个",
        }

    async def _pattern_recognition(self, params: dict[str, Any]) -> dict[str, Any]:
        """模式识别"""
        data_points = params.get("data_points", [])

        patterns = []
        # 简单的模式识别
        if len(data_points) > 10:
            # 检测周期性
            timestamps = [dp.get("timestamp") for dp in data_points if "timestamp" in dp]
            if timestamps:
                patterns.append({"type": "temporal", "description": "时间序列模式"})

        return {
            "analysis_type": "pattern_recognition",
            "patterns": patterns,
            "pattern_count": len(patterns),
        }

    async def _threat_correlation(self, params: dict[str, Any]) -> dict[str, Any]:
        """????"""
        iocs = params.get("iocs", [])
        context = params.get("context", {})

        def collect_values(value: Any) -> list[Any]:
            if value is None:
                return []
            if isinstance(value, dict):
                collected: list[Any] = []
                for nested in value.values():
                    collected.extend(collect_values(nested))
                return collected
            if isinstance(value, (list, tuple, set)):
                collected: list[Any] = []
                for nested in value:
                    collected.extend(collect_values(nested))
                return collected
            return [value]

        normalized_iocs = collect_values(iocs)

        correlations = []
        for ioc in normalized_iocs:
            # ????
            if self.tools and self.tools.get("ioc_lookup"):
                from app.tools.ioc_tool import IoCInput

                input_data = IoCInput(
                    trace_id=params.get("trace_id", ""),
                    tenant_id=params.get("tenant_id", "default"),
                    value=ioc,
                )
                tool = self.tools.get("ioc_lookup")
                result = await tool.execute(input_data)

                if result.success:
                    correlations.append({
                        "ioc": ioc,
                        "threat_score": result.data.get("threat_score", 0),
                        "sources": result.data.get("sources", []),
                    })
            else:
                text = str(ioc).lower()
                threat_score = 0.1
                if any(token in text for token in ("malware", "c2", "command", "attack", "phish")):
                    threat_score = 0.8
                elif any(token in text for token in ("sus", "suspicious", "anomaly", "ioc")):
                    threat_score = 0.5
                correlations.append({
                    "ioc": ioc,
                    "threat_score": threat_score,
                    "sources": [],
                    "status": "heuristic",
                })

        return {
            "analysis_type": "threat_correlation",
            "context": context,
            "normalized_iocs": normalized_iocs,
            "correlations": correlations,
            "threat_level": self._assess_threat_level(correlations),
        }

    async def _analyze_task_description(self, params: dict[str, Any]) -> dict[str, Any]:
        """分析任务描述"""
        description = params.get("description", "")

        return {
            "analysis_type": "task_analysis",
            "description": description,
            "keywords": description.split()[:10],
            "estimated_complexity": "medium",
        }

    async def _generic_analysis(self, task: TaskRequest) -> dict[str, Any]:
        """通用分析"""
        return {
            "analysis_type": "generic",
            "task_type": task.task_type,
            "parameters": task.parameters,
            "status": "analyzed",
        }

    def _extract_basic_patterns(self, content: str) -> list[str]:
        """提取基础模式"""
        patterns = []
        if "error" in content.lower():
            patterns.append("error_detected")
        if "failed" in content.lower():
            patterns.append("failure_detected")
        if "unauthorized" in content.lower():
            patterns.append("auth_issue")
        return patterns

    def _generate_mitigations(self, vectors: list[dict]) -> list[str]:
        """生成缓解建议"""
        mitigations = []
        for vector in vectors:
            if vector["type"] == "network_intrusion":
                mitigations.append("封锁可疑IP，检查防火墙规则")
            elif vector["type"] == "malware_delivery":
                mitigations.append("隔离受感染主机，运行反病毒扫描")
            elif vector["type"] == "credential_abuse":
                mitigations.append("强制密码重置，启用多因素认证")
        return mitigations

    def _calculate_overall_risk(self, scores: list[dict]) -> str:
        """计算整体风险"""
        if not scores:
            return "low"
        max_score = max(s["risk_score"] for s in scores)
        if max_score >= 15:
            return "critical"
        if max_score >= 10:
            return "high"
        if max_score >= 5:
            return "medium"
        return "low"

    def _generate_risk_recommendations(self, scores: list[dict]) -> list[str]:
        """生成风险建议"""
        recommendations = []
        critical = [s for s in scores if s["priority"] == "critical"]
        if critical:
            recommendations.append(f"立即处理 {len(critical)} 个关键风险")
        high = [s for s in scores if s["priority"] == "high"]
        if high:
            recommendations.append(f"优先处理 {len(high)} 个高风险项")
        return recommendations

    def _determine_attack_stage(self, patterns: dict) -> str:
        """确定攻击阶段"""
        if patterns.get("command_and_control"):
            return "c2_established"
        if patterns.get("data_exfiltration"):
            return "exfiltration"
        if patterns.get("lateral_movement"):
            return "lateral_movement"
        if patterns.get("privilege_escalation"):
            return "privilege_escalation"
        if patterns.get("persistence"):
            return "persistence"
        return "initial_access"

    def _assess_threat_level(self, correlations: list[dict]) -> str:
        """评估威胁等级"""
        if not correlations:
            return "unknown"
        max_score = max(c.get("threat_score", 0) for c in correlations)
        if max_score >= 80:
            return "critical"
        if max_score >= 60:
            return "high"
        if max_score >= 40:
            return "medium"
        return "low"
