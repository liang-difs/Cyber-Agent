# Context Regression Test Strategy

## 测试目标

验证 Agent 在多轮对话后不会遗忘早期关键信息。

## 测试用例

### TC-001: 12 轮对话记忆测试
- **方法**: 进行 12 轮对话，第 1 轮提供关键信息
- **通过标准**: 第 12 轮仍能正确引用第 1 轮的信息

### TC-002: Context 压缩后记忆测试
- **方法**: 触发 Context 压缩（超过 token 限制）
- **通过标准**: 压缩后仍保留关键实体和结论

### TC-003: 长 Tool 输出记忆测试
- **方法**: Tool 返回大量数据（> 2000 tokens）
- **通过标准**: 后续轮次能正确引用 Tool 输出中的关键数据

### TC-004: 多 Tool 交叉引用测试
- **方法**: 轮次 1 调用 Tool A，轮次 3 调用 Tool B，轮次 5 需要交叉引用
- **通过标准**: 正确关联两个 Tool 的结果

## 评估方法

```python
def test_context_recall(conversation, turn_to_check, expected_info):
    """验证特定轮次是否仍记得早期信息"""
    response = conversation.get_response_at_turn(turn_to_check)
    assert expected_info in response, f"遗忘: {expected_info}"
```

## 通过标准

- 12 轮记忆保持率 >= 95%
- 压缩后关键信息保留率 >= 90%
