# CyberSec Agent 改进计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use compose:subagent (recommended) or compose:execute to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 分析 CyberSec Agent 项目的不足之处，制定详细的改进计划，涵盖代码质量、架构优化、性能提升、测试覆盖、安全加固和文档完善。

**Architecture:** 采用分阶段改进策略，优先处理高影响、低风险的改进项，逐步推进架构优化和性能提升。

**Tech Stack:** Python 3.12 + FastAPI (backend), React 18 + TypeScript (frontend), PostgreSQL 16 + Redis 7, ChromaDB + BM25 (RAG)

---

## 改进分析维度

### S1: 代码质量分析
- Python 代码规范 (PEP 8, 类型注解)
- TypeScript 代码规范 (strict mode, ESLint)
- 函数复杂度 (圈复杂度)
- 重复代码检测
- 依赖管理

### S2: 架构分析
- ReAct Agent 设计模式
- 多智能体协同架构
- RAG 管线架构
- 数据库设计
- API 设计

### S3: 性能分析
- RAG 检索性能
- 知识图谱查询性能
- WebSocket 实时通信
- 数据库查询优化
- 并发处理能力

### S4: 测试覆盖分析
- 单元测试覆盖率
- 集成测试覆盖
- 端到端测试
- 测试质量评估

### S5: 安全分析
- 认证授权机制
- API 安全
- 数据脱敏
- Prompt 注入防御
- 依赖漏洞

### S6: 文档分析
- API 文档完整性
- 架构文档
- 部署文档
- 开发者文档

---

## Task 1: 代码质量扫描与分析

**Covers:** S1

**Files:**
- Create: `docs/compose/analysis/code-quality-report.md`
- Create: `scripts/code-quality-check.py`

- [ ] **Step 1: 创建代码质量检查脚本**

```python
#!/usr/bin/env python3
"""代码质量扫描工具"""

import ast
import subprocess
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class CodeIssue:
    file: str
    line: int
    severity: str  # error, warning, info
    message: str
    rule: str

class CodeQualityScanner:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.issues: List[CodeIssue] = []
    
    def scan_python_files(self) -> List[CodeIssue]:
        """扫描 Python 文件"""
        for py_file in self.project_root.rglob("*.py"):
            if ".venv" in str(py_file) or "node_modules" in str(py_file):
                continue
            self._check_python_file(py_file)
        return self.issues
    
    def _check_python_file(self, file_path: Path):
        """检查单个 Python 文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            # 检查函数长度
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_length = node.end_lineno - node.lineno
                    if func_length > 50:
                        self.issues.append(CodeIssue(
                            file=str(file_path),
                            line=node.lineno,
                            severity="warning",
                            message=f"函数 {node.name} 长度 {func_length} 行，超过 50 行限制",
                            rule="function-length"
                        ))
        except Exception as e:
            self.issues.append(CodeIssue(
                file=str(file_path),
                line=0,
                severity="error",
                message=f"解析错误: {str(e)}",
                rule="parse-error"
            ))
    
    def generate_report(self) -> Dict:
        """生成报告"""
        return {
            "total_issues": len(self.issues),
            "by_severity": {
                "error": len([i for i in self.issues if i.severity == "error"]),
                "warning": len([i for i in self.issues if i.severity == "warning"]),
                "info": len([i for i in self.issues if i.severity == "info"]),
            },
            "issues": [
                {
                    "file": i.file,
                    "line": i.line,
                    "severity": i.severity,
                    "message": i.message,
                    "rule": i.rule
                }
                for i in self.issues
            ]
        }

if __name__ == "__main__":
    scanner = CodeQualityScanner(Path("D:\\Desktop\\Agent"))
    scanner.scan_python_files()
    report = scanner.generate_report()
    print(json.dumps(report, indent=2, ensure_ascii=False))
```

- [ ] **Step 2: 运行代码质量检查**

Run: `python scripts/code-quality-check.py > docs/compose/analysis/code-quality-report.json`
Expected: JSON report with issues grouped by severity

- [ ] **Step 3: 分析报告并生成 Markdown 文档**

```markdown
# 代码质量分析报告

## 概览
- 扫描文件数: X
- 发现问题数: Y
- 错误: A, 警告: B, 信息: C

## 主要问题

### 1. 函数复杂度
- 发现 N 个函数超过 50 行限制
- 建议: 拆分为更小的函数

### 2. 类型注解
- M 个函数缺少类型注解
- 建议: 添加完整的类型注解

### 3. 重复代码
- 检测到 K 处重复代码
- 建议: 提取公共函数
```

- [ ] **Step 4: 提交代码**

```bash
git add scripts/code-quality-check.py docs/compose/analysis/
git commit -m "docs: 添加代码质量分析报告"
```

---

## Task 2: 架构优化方案

**Covers:** S2

**Files:**
- Create: `docs/compose/analysis/architecture-review.md`
- Create: `docs/compose/plans/architecture-optimization.md`

- [ ] **Step 1: 分析现有架构**

Review the following files:
- `backend/app/agent/react.py` - ReAct Agent 核心
- `backend/app/multi_agent/coordinator.py` - 多智能体协调
- `backend/app/rag/pipeline.py` - RAG 管线
- `backend/app/knowledge_graph/graph.py` - 知识图谱

- [ ] **Step 2: 识别架构问题**

```markdown
# 架构问题清单

## 1. ReAct Agent 问题
- 问题: 上下文压缩策略单一
- 影响: 长对话性能下降
- 建议: 实现分层压缩策略

## 2. 多智能体协同问题
- 问题: 缺乏任务依赖管理
- 影响: 并行执行效率低
- 建议: 实现 DAG 任务调度

## 3. RAG 管线问题
- 问题: 向量检索与关键词检索融合简单
- 影响: 检索质量不稳定
- 建议: 实现自适应融合权重

## 4. 知识图谱问题
- 问题: 内存图数据库限制
- 影响: 数据规模受限
- 建议: 迁移到 Neo4j 或类似图数据库
```

- [ ] **Step 3: 制定优化方案**

```markdown
# 架构优化方案

## Phase 1: 短期优化 (1-2 周)
1. 实现上下文分层压缩
2. 优化 RAG 融合算法
3. 添加性能监控

## Phase 2: 中期优化 (1-2 月)
1. 实现 DAG 任务调度
2. 优化知识图谱查询
3. 添加缓存层

## Phase 3: 长期优化 (3-6 月)
1. 迁移到专业图数据库
2. 实现分布式 Agent
3. 添加自动化测试
```

- [ ] **Step 4: 提交文档**

```bash
git add docs/compose/analysis/architecture-review.md docs/compose/plans/architecture-optimization.md
git commit -m "docs: 添加架构优化方案"
```

---

## Task 3: 性能优化方案

**Covers:** S3

**Files:**
- Create: `docs/compose/analysis/performance-review.md`
- Create: `docs/compose/plans/performance-optimization.md`

- [ ] **Step 1: 性能基准测试**

```python
#!/usr/bin/env python3
"""性能基准测试工具"""

import time
import asyncio
from typing import Callable, Any

class PerformanceBenchmark:
    def __init__(self):
        self.results = []
    
    async def measure(self, name: str, func: Callable, *args, **kwargs) -> Any:
        """测量函数执行时间"""
        start = time.perf_counter()
        result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        
        self.results.append({
            "name": name,
            "elapsed": elapsed,
            "status": "success"
        })
        return result
    
    def generate_report(self):
        return {
            "total_tests": len(self.results),
            "total_time": sum(r["elapsed"] for r in self.results),
            "results": self.results
        }
```

- [ ] **Step 2: 识别性能瓶颈**

```markdown
# 性能瓶颈分析

## 1. RAG 检索
- 问题: 向量检索延迟高
- 原因: ChromaDB 查询未优化
- 建议: 添加索引、优化查询参数

## 2. 知识图谱
- 问题: BFS 遍历慢
- 原因: 内存图数据库无索引
- 建议: 添加图索引

## 3. WebSocket
- 问题: 并发连接数受限
- 原因: 单线程处理
- 建议: 使用多进程 + 负载均衡

## 4. 数据库
- 问题: 查询慢
- 原因: 缺少索引
- 建议: 添加复合索引
```

- [ ] **Step 3: 制定优化方案**

```markdown
# 性能优化方案

## 立即可做
1. 添加数据库索引
2. 优化 RAG 查询参数
3. 添加 Redis 缓存

## 短期 (1-2 周)
1. 实现查询结果缓存
2. 优化 WebSocket 连接管理
3. 添加性能监控

## 中期 (1-2 月)
1. 实现异步任务队列优化
2. 添加连接池
3. 实现查询结果分页
```

- [ ] **Step 4: 提交文档**

```bash
git add docs/compose/analysis/performance-review.md docs/compose/plans/performance-optimization.md
git commit -m "docs: 添加性能优化方案"
```

---

## Task 4: 测试覆盖改进

**Covers:** S4

**Files:**
- Create: `docs/compose/analysis/test-coverage-report.md`
- Create: `tests/conftest.py` (if not exists)
- Create: `tests/test_coverage.py`

- [ ] **Step 1: 分析现有测试**

```bash
# 运行测试覆盖率
cd D:\Desktop\Agent\backend
PYTHONPATH=. pytest tests/ --cov=app --cov-report=html --cov-report=json
```

- [ ] **Step 2: 识别测试缺口**

```markdown
# 测试覆盖分析

## 当前覆盖率
- 语句覆盖率: X%
- 分支覆盖率: Y%
- 函数覆盖率: Z%

## 缺失测试
1. Agent 核心逻辑测试
2. 多智能体协同测试
3. RAG 管线测试
4. 知识图谱测试
5. API 端点测试

## 建议
1. 添加单元测试
2. 添加集成测试
3. 添加端到端测试
```

- [ ] **Step 3: 添加缺失测试**

```python
# tests/test_agent_core.py
import pytest
from app.agent.react import ReActAgent

class TestReActAgent:
    def test_agent_initialization(self):
        """测试 Agent 初始化"""
        agent = ReActAgent()
        assert agent is not None
    
    def test_agent_reasoning(self):
        """测试 Agent 推理"""
        agent = ReActAgent()
        # 测试推理逻辑
        pass
    
    def test_agent_tool_execution(self):
        """测试 Agent 工具执行"""
        agent = ReActAgent()
        # 测试工具执行
        pass
```

- [ ] **Step 4: 提交测试**

```bash
git add tests/
git commit -m "test: 添加 Agent 核心测试"
```

---

## Task 5: 安全加固

**Covers:** S5

**Files:**
- Create: `docs/compose/analysis/security-review.md`
- Create: `docs/compose/plans/security-hardening.md`
- Modify: `backend/app/core/security.py`

- [ ] **Step 1: 安全审计**

```markdown
# 安全审计报告

## 1. 认证授权
- 问题: JWT 密钥硬编码风险
- 建议: 使用环境变量

## 2. API 安全
- 问题: 缺少请求速率限制
- 建议: 添加 rate limiting

## 3. 数据脱敏
- 问题: 日志可能包含敏感信息
- 建议: 增强脱敏规则

## 4. Prompt 注入
- 问题: 用户输入未完全过滤
- 建议: 添加输入验证

## 5. 依赖漏洞
- 问题: 部分依赖版本过旧
- 建议: 更新依赖
```

- [ ] **Step 2: 实施安全加固**

```python
# backend/app/core/security.py
from functools import wraps
from typing import Callable
import time
from collections import defaultdict

class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
    
    def is_allowed(self, key: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        
        # 清理过期请求
        self.requests[key] = [t for t in self.requests[key] if t > window_start]
        
        if len(self.requests[key]) >= self.max_requests:
            return False
        
        self.requests[key].append(now)
        return True

def rate_limit(max_requests: int = 100, window_seconds: int = 60):
    """速率限制装饰器"""
    limiter = RateLimiter(max_requests, window_seconds)
    
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            key = f"{func.__module__}.{func.__name__}"
            if not limiter.is_allowed(key):
                raise Exception("Rate limit exceeded")
            return await func(*args, **kwargs)
        return wrapper
    return decorator
```

- [ ] **Step 3: 提交安全加固**

```bash
git add backend/app/core/security.py docs/compose/
git commit -m "security: 添加速率限制和安全审计报告"
```

---

## Task 6: 文档完善

**Covers:** S6

**Files:**
- Create: `docs/compose/analysis/documentation-review.md`
- Create: `docs/api/openapi.yaml`
- Create: `docs/developer/getting-started.md`

- [ ] **Step 1: 文档审计**

```markdown
# 文档审计报告

## 现有文档
- README.md: 完整
- PROJECT_SUMMARY.md: 完整
- API 文档: 缺失
- 开发者文档: 缺失
- 部署文档: 部分

## 缺失文档
1. OpenAPI 规范
2. 开发者指南
3. 架构设计文档
4. 贡献指南
```

- [ ] **Step 2: 生成 OpenAPI 规范**

```bash
cd D:\Desktop\Agent\backend
PYTHONPATH=. python -c "
from app.main import app
import json
from fastapi.openapi.utils import get_openapi

openapi = get_openapi(
    title='CyberSec Agent API',
    version='0.9.0',
    routes=app.routes
)
with open('../docs/api/openapi.yaml', 'w') as f:
    import yaml
    yaml.dump(openapi, f)
"
```

- [ ] **Step 3: 创建开发者指南**

```markdown
# CyberSec Agent 开发者指南

## 快速开始

### 环境要求
- Python 3.12+
- Node.js 20+
- PostgreSQL 16+
- Redis 7+

### 开发环境搭建
1. 克隆仓库
2. 安装后端依赖
3. 安装前端依赖
4. 配置环境变量
5. 启动服务

### 代码规范
- Python: PEP 8 + Black
- TypeScript: ESLint + Prettier
- 提交规范: Conventional Commits
```

- [ ] **Step 4: 提交文档**

```bash
git add docs/
git commit -m "docs: 添加 API 文档和开发者指南"
```

---

## Task 7: 依赖更新与安全扫描

**Covers:** S5

**Files:**
- Modify: `backend/requirements.txt`
- Modify: `frontend/package.json`
- Create: `docs/compose/analysis/dependency-audit.md`

- [ ] **Step 1: 依赖审计**

```bash
# Python 依赖审计
cd D:\Desktop\Agent\backend
pip-audit

# npm 依赖审计
cd D:\Desktop\Agent\frontend
npm audit
```

- [ ] **Step 2: 更新依赖**

```bash
# 更新 Python 依赖
pip install --upgrade pip
pip-compile requirements.in

# 更新 npm 依赖
npm update
npm audit fix
```

- [ ] **Step 3: 生成依赖报告**

```markdown
# 依赖审计报告

## Python 依赖
- 总数: X
- 过期: Y
- 漏洞: Z

## npm 依赖
- 总数: A
- 过期: B
- 漏洞: C

## 建议
1. 更新过期依赖
2. 修复安全漏洞
3. 添加依赖锁定
```

- [ ] **Step 4: 提交更新**

```bash
git add backend/requirements.txt frontend/package.json docs/compose/
git commit -m "chore: 更新依赖并添加审计报告"
```

---

## 执行计划

### Phase 1: 立即可做 (本周)
1. Task 1: 代码质量扫描
2. Task 4: 测试覆盖分析
3. Task 7: 依赖更新

### Phase 2: 短期优化 (1-2 周)
1. Task 2: 架构优化方案
2. Task 3: 性能优化方案
3. Task 5: 安全加固

### Phase 3: 中期优化 (1-2 月)
1. Task 6: 文档完善
2. 实施架构优化
3. 实施性能优化

---

## 验证标准

### 代码质量
- [ ] 代码规范检查通过
- [ ] 类型注解完整
- [ ] 无重复代码

### 架构
- [ ] 架构文档完整
- [ ] 设计模式清晰
- [ ] 可扩展性良好

### 性能
- [ ] 响应时间 < 200ms
- [ ] 并发支持 > 100
- [ ] 内存使用稳定

### 测试
- [ ] 覆盖率 > 80%
- [ ] 所有测试通过
- [ ] 无关键路径未测试

### 安全
- [ ] 无高危漏洞
- [ ] 认证机制完善
- [ ] 输入验证完整

### 文档
- [ ] API 文档完整
- [ ] 开发者指南完整
- [ ] 部署文档完整