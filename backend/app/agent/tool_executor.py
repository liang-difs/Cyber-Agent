"""Tool Executor — delegates to Tool Registry.

Kept for backward compatibility with verify.py.
"""

from app.tools.registry import ToolRegistry
from app.tools.echo_tool import echo_tool
from app.tools.cve_tool import cve_tool
from app.tools.cve_catalog_tool import cve_catalog_tool
from app.tools.ioc_tool import ioc_tool
from app.tools.ip_tool import ip_tool
from app.tools.rag_tool import rag_tool
from app.tools.web_search_tool import web_search_tool
from app.tools.pcap_tool import pcap_tool
from app.tools.nmap_scan_tool import NmapScanTool
from app.tools.vuln_scan_tool import VulnScanTool
from app.tools.dir_scan_tool import DirScanTool
from app.tools.log_analysis_tool import LogAnalysisTool
from app.tools.hash_lookup_tool import HashLookupTool
from app.tools.encoding_tool import EncodingTool
from app.tools.archive_tool import archive_tool
from app.tools.api_doc_parser_tool import api_doc_parser_tool
from app.tools.config_parser_tool import config_parser_tool
from app.tools.binary_analysis_tool import binary_analysis_tool
from app.tools.task_planner_tool import task_planner_tool
from app.tools.rule_match_tool import rule_match_tool
from app.tools.knowledge_graph_tool import knowledge_graph_tool
from app.tools.response_action_tool import response_action_tool
from app.tools.threat_intel_tool import threat_intel_tool

# Global registry instance
tool_registry = ToolRegistry()
tool_registry.register(echo_tool)
tool_registry.register(cve_tool)
tool_registry.register(cve_catalog_tool)
tool_registry.register(ioc_tool)
tool_registry.register(ip_tool)
tool_registry.register(rag_tool)
tool_registry.register(web_search_tool)
tool_registry.register(pcap_tool)
tool_registry.register(NmapScanTool())
tool_registry.register(VulnScanTool())
tool_registry.register(DirScanTool())
tool_registry.register(LogAnalysisTool())
tool_registry.register(HashLookupTool())
tool_registry.register(EncodingTool())
tool_registry.register(archive_tool)
tool_registry.register(api_doc_parser_tool)
tool_registry.register(config_parser_tool)
tool_registry.register(binary_analysis_tool)
tool_registry.register(task_planner_tool)
tool_registry.register(rule_match_tool)
tool_registry.register(knowledge_graph_tool)
tool_registry.register(response_action_tool)
tool_registry.register(threat_intel_tool)
