# Tool Contract Template

> 所有 Tool 必须按此模板定义契约。与 tool_protocol.md 配合使用。

## Tool: `{tool_name}`

### 元信息
- **版本**: v1
- **状态**: draft / stable / deprecated
- **Schema 版本**: v1
- **作者**: agent/human

### 功能描述
简要描述 Tool 的功能。

### Input Schema (JSON Schema)

```json
{
  "name": "tool_name",
  "description": "工具描述",
  "version": "v1",
  "parameters": {
    "type": "object",
    "properties": {
      "param1": {
        "type": "string",
        "description": "参数描述",
        "enum": ["option1", "option2"]
      },
      "param2": {
        "type": "integer",
        "description": "参数描述",
        "default": 10
      }
    },
    "required": ["param1"]
  }
}
```

### Input Model (Pydantic)

```python
class ToolNameInput(ToolInput):
    param1: str
    param2: int = 10
```

### Output Model (ToolResult)

```python
# 使用标准 ToolResult，data 字段结构如下：
{
    "field1": "value1",
    "field2": 123
}
```

### 成功响应示例

```json
{
  "success": true,
  "tool_name": "tool_name",
  "tool_version": "v1",
  "data": {
    "field1": "value1",
    "field2": 123
  },
  "error": null,
  "confidence": 0.95,
  "evidence_source": ["source1", "source2"],
  "trace_id": "uuid",
  "execution_time_ms": 150
}
```

### 错误响应示例

```json
{
  "success": false,
  "tool_name": "tool_name",
  "tool_version": "v1",
  "data": {},
  "error": "错误描述",
  "confidence": 0.0,
  "evidence_source": [],
  "trace_id": "uuid",
  "execution_time_ms": 50
}
```

### 超时处理
- 默认超时: 30s
- 超时后返回标准错误 ToolResult

### 依赖
- 外部服务: xxx
- 内部模块: xxx

### 变更日志
- v1: 初始版本
