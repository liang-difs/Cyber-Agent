# Prompt Governance

> Prompt 分层治理。防止 Prompt 漂移和污染。

## 目录结构

```
prompts/
├── system/          # 系统级 Prompt（Agent 人格、全局约束）
├── react/           # ReAct 循环 Prompt
├── tools/           # Tool Calling Prompt（每个 Tool 一个）
└── rag/             # RAG 检索和生成 Prompt
```

## 命名规范

```
{category}_{name}_v{version}.md
```

示例：
- `system_base_v1.md`
- `tool_ioc_lookup_v1.md`
- `react_loop_v2.md`
- `rag_retrieval_v1.md`

## 每个 Prompt 文件必须包含

```markdown
# Prompt: {名称}

## 元信息
- **版本**: v1
- **状态**: draft / testing / stable / deprecated
- **作者**: agent/human
- **创建日期**: YYYY-MM-DD
- **最后修改**: YYYY-MM-DD
- **适用模型**: claude-opus-4-7 / qwen-xxx / all

## Prompt 正文
...

## 变更日志
- v1: 初始版本
```

## 分层原则

### system/ — 系统级
- Agent 身份定义
- 全局行为约束
- 输出格式规范
- **变更影响：所有行为** → 必须全量回归测试

### react/ — 推理循环
- ReAct 框架 Prompt
- 思考-行动-观察循环
- **变更影响：推理质量** → 必须测试推理路径

### tools/ — 工具调用
- 每个 Tool 的调用说明
- 输入输出格式定义
- **变更影响：单个 Tool** → 测试该 Tool 成功率

### rag/ — 检索增强
- 检索策略 Prompt
- 上下文注入 Prompt
- 答案生成 Prompt
- **变更影响：RAG 质量** → 测试检索命中率

## 禁止事项

- 禁止在代码中硬编码 Prompt
- 禁止跨层复用 Prompt
- 禁止修改 stable 状态的 Prompt（必须先创建新版本）
- 禁止 Prompt 中包含业务逻辑
