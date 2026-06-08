# Prompt Regression Test Strategy

## 测试目标

验证 Prompt 修改不会导致 JSON 输出错误率提升或行为退化。

## 测试用例

### TC-001: JSON 合法率测试
- **方法**: 修改 Prompt 后，执行 100 次 Tool Calling
- **通过标准**: JSON parse success rate >= 98%
- **基线**: 修改前的 JSON 合法率

### TC-002: 输出结构一致性测试
- **方法**: 相同输入，对比修改前后的输出结构
- **通过标准**: 字段名、类型、嵌套结构一致

### TC-003: Tool 选择准确率测试
- **方法**: 给定查询，验证 Agent 是否选择正确的 Tool
- **通过标准**: Tool 选择准确率 >= 95%

### TC-004: 响应质量评分测试
- **方法**: 使用标准问题集，人工/Auto 评分
- **通过标准**: 平均分不低于基线

## 回归流程

1. 记录当前 Prompt 版本和测试基线
2. 修改 Prompt（进入 draft 状态）
3. 运行全部回归测试
4. 对比结果：
   - 全部通过 → 进入 testing 状态
   - 任何退化 → 回退 Prompt

## 测试数据

使用 `tests/fixtures/prompt_regression/` 中的标准问题集。
