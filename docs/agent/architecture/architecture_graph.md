# Architecture Graph

> 系统模块依赖关系图。Agent 对图结构比长文档更敏感。

## 系统架构总览

```mermaid
graph TD
    subgraph Frontend
        UI[Web UI]
    end

    subgraph API Layer
        REST[REST API]
        WS[WebSocket]
    end

    subgraph Agent Core
        Agent[Agent Engine]
        ReAct[ReAct Loop]
        ContextMgr[Context Manager]
        ToolRegistry[Tool Registry]
    end

    subgraph Tools
        IOC[IOC Lookup]
        CVE[CVE Analysis]
        PCAP[PCAP Analysis]
        ThreatIntel[Threat Intel]
    end

    subgraph AI Layer
        Router[LLM Router]
        PromptMgr[Prompt Manager]
        RAG[RAG Engine]
    end

    subgraph Storage
        PG[(PostgreSQL)]
        Redis[(Redis)]
        Chroma[(ChromaDB)]
        ES[(Elasticsearch)]
    end

    subgraph Task Layer
        Dispatcher[Task Dispatcher]
        Celery[Celery Workers]
    end

    subgraph External
        ClaudeAPI[Claude API]
        LocalLLM[Local LLM]
        ThreatIntelAPI[Threat Intel API]
    end

    UI --> REST
    UI --> WS
    REST --> Agent
    WS --> Agent

    Agent --> ReAct
    Agent --> ContextMgr
    Agent --> ToolRegistry

    ToolRegistry --> IOC
    ToolRegistry --> CVE
    ToolRegistry --> PCAP

    IOC --> Redis
    IOC --> ThreatIntelAPI
    CVE --> ES
    PCAP --> PG

    ReAct --> Router
    Router --> PromptMgr
    Router --> ClaudeAPI
    Router --> LocalLLM

    Agent --> RAG
    RAG --> Chroma
    RAG --> ES

    Agent --> Dispatcher
    Dispatcher --> Celery
    Celery --> Redis
```

## 模块依赖矩阵

| 模块 | 依赖 | 被依赖 |
|------|------|--------|
| Agent Engine | ToolRegistry, ContextMgr, Router, Dispatcher | REST, WS |
| LLM Router | PromptMgr, ClaudeAPI, LocalLLM | Agent, ReAct |
| Tool Registry | IOC, CVE, PCAP | Agent |
| Context Manager | Redis | Agent, ReAct |
| RAG Engine | Chroma, ES | Agent |
| Task Dispatcher | Celery, Redis | Agent |
| Prompt Manager | (文件系统) | Router |

## 数据流

### 用户查询 → Agent 响应

```
User → REST/WS → Agent → ReAct Loop:
  → Think (LLM Router → Claude API)
  → Act (Tool Registry → Tool 执行)
  → Observe (结果结构化)
  → (循环直到完成)
→ Response → User
```

### 异步任务流

```
Agent → Task Dispatcher → Redis Queue → Celery Worker → Tool 执行 → 结果回写
```
