# CyberSec Agent

网络安全智能分析平台 — 基于 LLM 驱动的 ReAct Agent，集成攻击链溯源、关联分析、威胁情报查询。

## 功能

- **态势总览** — 告警统计卡片 + 严重等级饼图 + 近 14 天趋势图 + 最近告警/CVE 表格 + 服务健康状态
- **AI 对话** — ReAct Agent (Thought → Action → Observation)，WebSocket 流式输出，截断自动续写，会话按用户隔离
- **CVE 搜索** — NVD API + BM25 本地索引，支持 KEV 过滤
- **IoC 查询** — VirusTotal / OTX AlienVault / AbuseIPDB 多源聚合，支持批量查询（最多 50 个）+ CSV 导出
- **IP 威胁分析** — GeoIP + AbuseIPDB 信誉评分
- **PCAP 分析** — tshark 解析 + 8 类异常检测（暴力破解/C2 信标/端口扫描/DNS 隧道/Beacon/可疑端口/TLS 降级/数据外泄）+ 自动告警生成 + 路径白名单安全校验
- **告警管理** — ATT&CK TTP 映射（15 条规则精确映射）+ 真阳性/可疑/误报判决 + 4 级置信度标签 + 人工复核操作（确认真阳性/标记误报/关闭）
- **攻击链溯源** — MITRE ATT&CK 战术序列化 + 进展评分 + 方向提示
- **关联分析** — IP 聚类、规则爆发、跨目标、时间异常
- **资产管理** — CMDB 资产 CRUD（主机/服务器/网络设备/应用），按 IP/名称/负责人检索
- **报告生成** — Markdown + HTML 导出（可打印 PDF），支持 PCAP 富化 + 异常汇总 + 恶意软件家族识别（15 个）+ 应用协议上下文
- **数据脱敏** — PCAP 分析前自动脱敏（邮箱/信用卡/SSN/凭据/私网 IP），仅协议元数据送入 LLM
- **用户管理** — 管理员 CRUD 用户（创建/修改角色/停用/删除），角色：admin/analyst/viewer
- **多租户隔离** — RAG 知识库按 tenant_id 隔离，会话按 user_id 隔离
- **审计日志** — 全 API 请求记录，管理员可查
- **系统监控** — PostgreSQL / Redis / ES / Celery / LLM 健康检查

## 知识库

| 知识库 | 条数 | 说明 |
|---|---|---|
| NVD CVE | 44,165 | 含 CVSS、KEV 状态、PoC 标记 |
| MITRE ATT&CK | 2,077 | STIX 2.1，含子技术 |
| Sigma 规则 | 49,848 | 含检测逻辑注释 |
| CISA KEV | 1,583 | 已知在野利用漏洞 |
| JA3 指纹 | 157 | 恶意软件 TLS 特征 |
| 威胁情报 | ~190,000 | 多源聚合 |
| **总计** | **288,267** | BGE-M3 向量索引 + BM25 混合检索 (RRF 融合) |

## 技术栈

| 层 | 技术 |
|---|---|
| Frontend | React 18 + TypeScript + Ant Design 5 + Zustand + Vite |
| Backend | Python 3.12 + FastAPI + WebSocket |
| Agent | 自研 ReAct (无 LangChain) + LiteLLM Router + 熔断器 |
| RAG | ChromaDB + BM25 + BGE-M3 嵌入 + RRF 融合 |
| Tasks | Celery 4 级优先队列 (Redis broker) |
| DB | PostgreSQL 16 + SQLAlchemy async + Alembic |
| Infra | Docker Compose (PostgreSQL, Redis, MinIO, Elasticsearch) |

## 快速开始

### 环境要求

- Python 3.11+（推荐 3.12）
- Node.js 20+
- Docker & Docker Compose（可选，用于容器化部署）

### Windows 一键启动

如果你希望先把前后端在本机跑起来，直接执行仓库根目录下的脚本：

```powershell
.\start-services.bat
```

或者在 PowerShell 里直接运行：

```powershell
.\scripts\start-dev.ps1
```

脚本会自动：

- 优先创建 `backend/.venv`，如果当前 Python 环境无法初始化虚拟环境，会自动回退到 `py -3.12`
- 安装后端和前端依赖
- 启动后端 FastAPI 服务
- 启动前端 Vite 开发服务
- 使用 PostgreSQL 初始化开发数据库
- 自动写入默认管理员 `admin / admin123`

启动后访问：

- 前端: http://localhost:3000
- 后端: http://localhost:8000

日志位置：

- `backend/data/runtime/logs/backend.out.log`
- `backend/data/runtime/logs/backend.err.log`
- `backend/data/runtime/logs/frontend.out.log`
- `backend/data/runtime/logs/frontend.err.log`

### 1. 启动基础设施

```bash
cd infra
docker compose up -d
```

### 2. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env，按下方"环境变量"章节配置
```

### 3. 启动后端

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 4. 启动前端

```bash
cd frontend
npm install
npm run dev
```

访问 http://localhost:3000，使用 `admin` / `admin123` 登录（开发模式）。

### 5. 初始化管理员

```bash
PYTHONPATH=backend python -m app.scripts.init_admin --username admin --password your-password
```

## 环境变量

| 变量 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `JWT_SECRET` | 必填 | — | JWT 签名密钥，长度 >= 32 字符，随机生成 |
| `APP_ENV` | 必填 | `development` | `production` / `development` |
| `AUTH_DEV_FALLBACK_ENABLED` | 生产必须为 `false` | 自动（非生产= true） | 开发回退账号开关 |
| `CORS_ORIGINS` | 建议配置 | `http://localhost:3000` | 允许的前端源，逗号分隔 |
| `DEEPSEEK_API_KEY` | API 模式必填 | — | DeepSeek API 密钥 |
| `LLM_MODEL` | 建议配置 | `deepseek-v4-flash` | LLM 模型标识 |
| `LLM_TIMEOUT` | 可选 | `30` | LLM 请求超时（秒） |
| `DATABASE_URL` | 建议配置 | `postgresql+asyncpg://cybersec:cybersec_pass@localhost:5432/cybersec` | PostgreSQL 连接串 |
| `REDIS_URL` | 建议配置 | `redis://localhost:6379/0` | Redis 连接串 |
| `VT_API_KEY` | 可选 | — | VirusTotal API（IoC 查询） |
| `OTX_API_KEY` | 可选 | — | AlienVault OTX（威胁情报） |
| `AbuseIPDB_API_KEY` | 可选 | — | AbuseIPDB（IP 信誉） |
| `NVD_API_KEY` | 可选 | — | NVD API（CVE 同步） |

## 生产部署安全检查

部署前必须完成：

- [ ] `APP_ENV=production`
- [ ] `AUTH_DEV_FALLBACK_ENABLED=false`
- [ ] `JWT_SECRET` 长度 >= 32 字符且随机生成
- [ ] 初始化管理员账号并修改默认密码
- [ ] PostgreSQL / Redis 修改默认密码
- [ ] `CORS_ORIGINS` 限定为实际前端域名
- [ ] 确认 PCAP 脱敏管道已启用（默认启用）

## LLM 后端切换

系统通过 LiteLLM 统一路由，切换 LLM 后端只需修改环境变量，无需改代码：

```bash
# 当前：DeepSeek API
LLM_MODEL=deepseek-v4-flash
DEEPSEEK_API_KEY=sk-xxx

# 切换到 Claude
LLM_MODEL=claude-sonnet-4-6
ANTHROPIC_API_KEY=sk-ant-xxx
```

兼容说明：
- `LLM_API_KEY` 也会被识别为 OpenAI 兼容服务的 API key。
- `LLM_PROVIDER` 可选，用于显式声明 provider；不填时会根据模型名自动推断。
- 前端监控页提供“LLM 后端切换”按钮，当前仅管理员可用，切换的是运行时路由，不会自动改写 `.env`。
- 如果希望服务重启后仍默认使用某个后端，请直接修改 `.env` 里的 `LLM_MODEL` / `LLM_BASE_URL` / API key。

重启服务即生效。

### 本地模型部署 (vLLM + Qwen3-14B)

**硬件要求：** 2x RTX 3090 (24GB each) 或更高

```bash
# 方式 1: 直接启动
bash scripts/start_vllm.sh

# 方式 2: Docker Compose
cd infra
docker compose -f docker-compose.local-llm.yml up -d
```

vLLM 启动后（约 2-3 分钟加载模型），设置环境变量切换：

```bash
LLM_MODEL=qwen3-14b
LLM_BASE_URL=http://localhost:8001/v1
OPENAI_API_KEY=EMPTY
```

如果本地卡在 warmup 或提示显存不足，可以先降低并发启动参数：
```bash
export VLLM_MAX_NUM_SEQS=64
export VLLM_GPU_UTIL=0.85
```

切回 API 模式只需注释掉 `LLM_BASE_URL` 并重启。

## Docker 部署

```bash
cd infra
docker compose up -d --build
```

服务地址：
- 前端: http://localhost:80
- 后端 API: http://localhost:8000
- PostgreSQL: localhost:5432
- Redis: localhost:6379
- MinIO Console: http://localhost:9001
- Elasticsearch: http://localhost:9200

## 已知限制

- PCAP 文件上传上限：2GB
- IoC 批量查询：单次最多 20 个指标
- RAG 检索：Top-K=4，超长 Observation 自动截断至 2000 token
- 会话历史：每 4 轮自动压缩，最大上下文约 32,768 token
- Agent 最大工具调用次数：每会话 4 次

## 测试

```bash
# 全量测试（314+ cases）
PYTHONPATH=backend pytest tests/ -q

# 分模块运行
pytest tests/test_pcap_analysis.py -v    # PCAP 分析（31 cases）
pytest tests/test_rag.py -v              # RAG 检索
pytest tests/test_react_agent.py -v      # Agent 核心
pytest tests/test_alert_assessment.py -v # 告警研判
pytest tests/test_analysis_api.py -v     # 分析 API

# 前端类型检查
cd frontend && npx tsc --noEmit

# 前端构建
cd frontend && npm run build
```

## 项目结构

```
Agent/
  backend/
    app/
      agent/          # ReAct Agent、上下文管理、JSON 解析
      api/            # FastAPI 路由 (auth, chat, cve, tasks, ...)
      core/           # 配置、安全、Redis 客户端
      governance/     # 工具协议 (ToolInput/ToolResult)
      llm/            # LiteLLM Router + 熔断器
      middleware/      # 审计日志中间件
      models/         # SQLAlchemy ORM 模型
      rag/            # RAG 管线 (ChromaDB + BM25 + RRF)
      rbac/           # 角色权限控制
      reports/        # Markdown 报告生成
      sanitizer/      # PII 脱敏管线
      tasks/          # Celery 异步任务
      tools/          # 可插拔工具实现
    alembic/          # 数据库迁移
  frontend/
    src/
      api/            # Axios HTTP 客户端
      components/     # 共享组件 (ErrorBoundary, ResponseCards, ...)
      hooks/          # WebSocket、任务轮询 hooks
      pages/          # 页面组件 (Chat, CveSearch, PcapAnalysis, ...)
      stores/         # Zustand 状态管理
      types/          # TypeScript 类型定义
  corpus/             # 安全知识库 (CVE, ATT&CK, Sigma, RFC, ...)
  docs/               # 架构文档、治理规范、运维手册
  infra/              # Docker Compose 基础设施
  tests/              # 后端测试 (314+ cases)
```

## API 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/auth/login` | JWT 登录 |
| WS | `/api/v1/agent/chat?token=<jwt>` | Agent 对话 (流式) |
| GET | `/api/v1/agent/sessions` | 会话列表 |
| GET | `/api/v1/cve/list` | CVE 搜索 |
| GET | `/api/v1/cve/{cve_id}` | CVE 详情 |
| GET | `/api/v1/alerts` | 告警列表 |
| POST | `/api/v1/tasks/alert-triage` | 告警分类 |
| POST | `/api/v1/tasks/pcap-upload` | PCAP 上传分析 |
| POST | `/api/v1/analysis/attack-chains` | 攻击链分析 |
| POST | `/api/v1/analysis/correlate` | 关联分析 |
| POST | `/api/v1/reports/generate` | 生成报告 |
| GET | `/api/v1/audit/logs` | 审计日志 |
| GET | `/health/detailed` | 系统健康检查 |

## 角色权限

| 角色 | 权限 |
|---|---|
| admin | 全部权限 |
| analyst | 对话、工具查询、任务提交、告警分类、报告生成 |
| viewer | 只读 (对话、查询、查看告警/报告) |

## 版本状态

当前版本：v0.9.0（Phase 4 — 功能完善与质量加固）

| 阶段 | 状态 | 说明 |
|---|---|---|
| Phase 0-3 | 已完成 | 基础设施 + Agent 核心 + 工具 + RAG + 前端 |
| Phase 4 | 已完成 | 安全加固 + 报告质量优化 + 仪表盘 + 用户管理 |
| Phase 5 | 规划中 | 外部情报集成与监控面板 |

**关键指标：**
- 后端测试：314+ 个全部通过
- API 端点：14 个路由模块
- 工具：19 个注册工具
- 前端页面：17 个
- 知识库：288,267 条（CVE + ATT&CK + Sigma + KEV + JA3 + 威胁情报）
