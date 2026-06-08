# Prompt Debugging Playbook

> Prompt 问题排查手册。

## 常见问题

### 问题 1: JSON 输出不合法

**现象**: Tool Calling 返回的 JSON 无法 parse

**排查步骤**:
1. 检查 Prompt 中是否有未转义的特殊字符
2. 检查 Prompt 是否要求 JSON 但未指定格式
3. 查看原始输出，定位 parse 失败位置
4. 运行 `tests/ai_runtime/prompt_regression/`

**解决方案**:
- 在 Prompt 中明确指定 JSON Schema
- 添加 "必须返回合法 JSON" 约束
- 考虑使用 structured output 而非自由文本

### 问题 2: Tool 选择错误

**现象**: Agent 选择了错误的 Tool

**排查步骤**:
1. 检查 Tool 描述是否清晰
2. 检查是否有多个 Tool 描述过于相似
3. 查看 ReAct 推理过程中的 Think 步骤

**解决方案**:
- 优化 Tool 描述的区分度
- 在 Prompt 中添加 Tool 选择指导
- 考虑合并功能相似的 Tool

### 问题 3: 行为退化

**现象**: Prompt 修改后，某些场景表现变差

**排查步骤**:
1. 对比修改前后的 Prompt diff
2. 运行全量回归测试
3. 定位具体退化的测试用例

**解决方案**:
- 回退 Prompt 到 stable 版本
- 逐步引入修改，定位引入退化的变更
- 参考 `memory/prompt_failures.md`

## 调试工具

- `tests/ai_runtime/prompt_regression/` — 回归测试
- `memory/prompt_failures.md` — 历史失败案例
- `governance/prompt_lifecycle.md` — 版本管理
