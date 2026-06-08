# Architectural Lessons

> 长期工程记忆：架构决策的经验教训。避免重复犯错。

## 格式

```markdown
### AL-XXX: 标题
- **日期**: YYYY-MM-DD
- **背景**: 当时在做什么
- **决策**: 做了什么选择
- **结果**: 好的/坏的结果
- **教训**: 下次应该怎么做
```

## 记录

### AL-001: 治理先行原则
- **日期**: 2026-05-27
- **背景**: 项目初始化阶段，讨论是否先写代码还是先建治理
- **决策**: 先建立完整的工程治理体系（11 层、43 个文件）
- **结果**: 待验证
- **教训**: AI Agent 项目必须先建立治理框架，否则 Agent 从第 3 天开始失忆、漂移、重复犯错

### AL-002: Tool Schema 版本化是第一优先级
- **日期**: 2026-05-27
- **背景**: 设计 Tool Protocol 时，发现 Schema 漂移是 AI 项目最大风险
- **决策**: 所有 Tool Schema 必须版本化，不兼容变更必须 bump major version
- **结果**: 待验证
- **教训**: Tool Schema 隐式漂移会导致 Prompt 不同步，系统隐性坏掉，且难以调试

### AL-003: Python 版本兼容性
- **日期**: 2026-05-27
- **背景**: verify.py 使用 `str | None` 语法，Python 3.9 不支持
- **决策**: 使用 `Optional[str]` 替代，保持兼容性
- **结果**: 修复后服务正常启动
- **教训**: 写代码时必须考虑目标 Python 版本，优先使用 `Optional[]` 而非 `X | None`

### AL-004: DeepSeek API 兼容性
- **日期**: 2026-05-27
- **背景**: 验证 Runtime 主链路时，DeepSeek API 有两个特殊要求
- **决策**: 在 Router 层统一处理
- **结果**: 主链路验证通过
- **教训**: (1) DeepSeek tool_calls 必须包含 `"type": "function"` 字段；(2) DeepSeek thinking 模式要求回传 `reasoning_content`；(3) tool_call_id 必须精确匹配，不能用 trace_id 替代

### AL-005: LiteLLM model 名称需要 provider 前缀
- **日期**: 2026-05-27
- **背景**: `deepseek-v4-flash` 不被 LiteLLM 识别，需要 `deepseek/deepseek-v4-flash`
- **决策**: Router 层自动补全 provider 前缀
- **结果**: 正常路由
- **教训**: LiteLLM 要求 `{provider}/{model}` 格式，Router 应自动处理

### AL-006: 运行时治理不可缺失
- **日期**: 2026-05-27
- **背景**: 初始设计只有静态治理（coding_rules）和结构治理（architecture），缺少运行时行为约束
- **决策**: 新增 runtime_governance.md，定义 Agent Allowed Actions、Forbidden Behaviors、High-Risk Operations
- **结果**: 待验证
- **教训**: 没有运行时护栏的 Agent 会"顺手优化"，导致系统漂移
