"""
FastAPI 入口 — Phase 4: Advanced Features.

链路: FastAPI → JWT Auth → RBAC → Audit Middleware → WebSocket → ReAct Agent
     → LLM Router → Tool Registry → Celery Tasks → Sanitizer Pipeline
     → Attack Chain / Correlation / Report Generation
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.verify import router as verify_router
from app.api.auth import router as auth_router
from app.api.chat import router as chat_router
from app.api.cve import router as cve_router
from app.api.tasks import router as tasks_router
from app.api.analysis import router as analysis_router
from app.api.reports import router as reports_router
from app.api.audit import router as audit_router
from app.api.alerts import router as alerts_router
from app.api.assets import router as assets_router
from app.api.dashboard import router as dashboard_router
from app.api.ioc import router as ioc_router
from app.api.monitoring import router as monitoring_router
from app.api.users import router as users_router
from app.api.decision_trace import router as decision_trace_router
from app.api.multi_agent import router as multi_agent_router
from app.api.rules import router as rules_router
from app.api.response_actions import router as response_actions_router
from app.api.events import router as events_router
from app.agent.context import context_manager
from app.core.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    import asyncio
    import logging

    logger = logging.getLogger(__name__)

    await context_manager.connect()

    settings = get_settings()
    if settings.auth_dev_fallback_enabled:
        logger.warning(
            "AUTH_DEV_FALLBACK_ENABLED is enabled. Disable it for production after init_admin.",
        )
    if not settings.jwt_secret:
        logger.warning(
            "JWT_SECRET is empty — tokens are insecure. "
            "Set JWT_SECRET in .env for production."
        )

    # Initialize database tables (dev convenience)
    try:
        from app.models.base import init_db
        await init_db()
        logger.info("Database tables initialized")
    except Exception as e:
        logger.warning("Database init skipped: %s (PostgreSQL not available)", e)

    # Background: import CVE data into RAG BM25 index
    async def _import_cves():
        try:
            from app.rag.bm25_search import bm25_instance
            from app.rag.importer import load_corpus_cves, index_cves_to_bm25

            if bm25_instance.count == 0:
                logger.info("RAG index empty, loading CVEs from corpus...")
                cves = load_corpus_cves(max_items=5000)
                if cves:
                    index_cves_to_bm25(cves, bm25_instance)
                    logger.info("Loaded %d CVEs into RAG BM25 index", len(cves))
                else:
                    logger.warning("No corpus CVE data found, RAG will work with empty index")
        except Exception as e:
            logger.warning("CVE import failed: %s (RAG will work with empty index)", e)

    # Background: periodic CVE sync (every 24h)
    async def _cve_sync_loop():
        import asyncio as _asyncio
        await _asyncio.sleep(300)  # Wait 5 min after startup before first sync
        while True:
            try:
                from app.rag.bm25_search import bm25_instance
                from app.rag.importer import sync_cves
                from app.core.config import get_settings
                settings = get_settings()
                count = await sync_cves(bm25_instance, api_key=settings.nvd_api_key, since_hours=24)
                if count:
                    logger.info("CVE sync completed: %d CVEs updated", count)
            except Exception as e:
                logger.warning("CVE sync failed: %s", e)
            await _asyncio.sleep(86400)  # 24 hours

    asyncio.create_task(_import_cves())
    asyncio.create_task(_cve_sync_loop())

    yield
    # Shutdown
    try:
        from app.models.base import close_db
        await close_db()
    except Exception:
        pass
    await context_manager.disconnect()


app = FastAPI(
    title="CyberSec Agent",
    description="网络安全智能分析平台 — ReAct Agent + DeepSeek API + 攻击链溯源 + 关联分析",
    version="0.5.0",
    lifespan=lifespan,
)

# CORS
_cors_origins = [o.strip() for o in get_settings().cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Audit middleware (Phase 4)
try:
    from app.middleware.audit import AuditMiddleware
    app.add_middleware(AuditMiddleware)
except Exception:
    pass  # Graceful if DB not available

# Routers
app.include_router(verify_router)
app.include_router(auth_router)
app.include_router(chat_router)
app.include_router(cve_router)
app.include_router(tasks_router)
app.include_router(analysis_router)
app.include_router(reports_router)
app.include_router(audit_router)
app.include_router(alerts_router)
app.include_router(assets_router)
app.include_router(dashboard_router)
app.include_router(ioc_router)
app.include_router(monitoring_router)
app.include_router(users_router)
app.include_router(decision_trace_router)
app.include_router(multi_agent_router)
app.include_router(rules_router)
app.include_router(response_actions_router)
app.include_router(events_router)


@app.get("/")
async def root():
    return {
        "project": "CyberSec Agent",
        "phase": "Phase 4",
        "version": "0.9.0",
        "features": [
            "JWT Authentication + RBAC (admin/analyst/viewer)",
            "ReAct Agent (Thought → Action → Observation)",
            "WebSocket Streaming Chat",
            "Tool Registry (19 tools: echo, cve, cve_catalog, ioc, ip, rag, web_search, pcap, nmap, vuln_scan, dir_scan, log_analysis, hash_lookup, encoding, archive, api_doc_parser, config_parser, binary_analysis, task_planner)",
            "Context Compression",
            "5-Level JSON Parser",
            "RAG Retrieval (ChromaDB + BM25 + RRF)",
            "CVE Lookup (NVD API 2.0)",
            "IoC Lookup (OTX + VirusTotal)",
            "IP Threat Analysis (GeoIP + AbuseIPDB)",
            "Celery 4-Level Priority Queue",
            "Pcap Analysis (tshark + Sanitizer Pipeline)",
            "Alert Triage (ATT&CK Mapping)",
            "PostgreSQL + SQLAlchemy Models",
            "Attack Chain Tracing (MITRE ATT&CK progression)",
            "Correlation Analysis (IP clusters, rule bursts, cross-target)",
            "Incident Report Generation (Markdown)",
            "Audit Logging Middleware",
            "Health Monitoring (PostgreSQL, Redis, ES, Celery)",
            "Archive Analysis (ZIP/RAR/7Z/TAR)",
            "API Documentation Parser (Swagger/OpenAPI/Postman)",
            "Config File Parser (JSON/YAML/XML/CSV/ENV/INI)",
            "Binary Analysis (ELF/PE/Mach-O/Java Class)",
            "Task Planner Engine (Auto-generate execution plans)",
            "Decision Trace & Explainability (推理链追踪、决策回放、审计报告导出)",
            "Multi-Agent Collaboration (Coordinator + Planner + Analyzer + Responder + Executor)",
        ],
        "endpoints": {
            "auth_login": "POST /api/v1/auth/login",
            "agent_chat": "WS /api/v1/agent/chat?token=<jwt>",
            "task_status": "GET /api/v1/tasks/{task_id}",
            "alert_triage": "POST /api/v1/tasks/alert-triage",
            "pcap_analysis": "POST /api/v1/tasks/pcap-analysis",
            "attack_chains": "POST /api/v1/analysis/attack-chains",
            "correlate": "POST /api/v1/analysis/correlate",
            "generate_report": "POST /api/v1/reports/generate",
            "audit_logs": "GET /api/v1/audit/logs",
            "health": "GET /health",
            "health_detailed": "GET /health/detailed",
            "verify_health": "GET /verify/health",
            "verify_chain": "POST /verify/chain",
            "multi_agent_tasks": "POST /api/v1/multi-agent/tasks",
            "multi_agent_agents": "GET /api/v1/multi-agent/agents",
            "multi_agent_status": "GET /api/v1/multi-agent/status",
        },
    }
