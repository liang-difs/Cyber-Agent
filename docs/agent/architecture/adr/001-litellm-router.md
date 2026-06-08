# ADR-001: LiteLLM Router

## Status
Accepted

## Context
系统需要支持多种 LLM 后端（Claude API、OpenAI-compatible 后端），并且需要在运行时动态切换。直接调用各 Provider SDK 会导致：
- 代码散落在各处
- 切换模型需要改多处代码
- 无法统一管理 API Key 和限流

## Decision
使用 LiteLLM 作为统一路由层，提供 OpenAI-compatible interface。

所有 LLM 调用必须经过 `llm/router.py`，禁止直接调用 Provider SDK。

## Consequences

### 正面
- 统一接口，切换模型零改动
- 内置限流、重试、fallback
- 支持 prompt caching

### 负面
- 引入额外依赖
- LiteLLM 版本升级可能引入兼容性问题
- 部分 Provider 特有功能可能被屏蔽

### 约束
- 所有 Tool 禁止直接调用 Provider SDK
- 新增 LLM Provider 只需在 Router 中配置
- Prompt Caching 策略在 Router 层统一管理
