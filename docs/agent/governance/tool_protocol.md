# Tool Protocol

> 统一 Tool Schema。所有 Tool 必须遵守此协议。

## Tool Schema 版本化

每个 Tool 必须声明 schema 版本：

```json
{
  "tool": "ioc_lookup",
  "version": "v1",
  "schema_version": "v1"
}
```

版本变更规则：
- `v1` → `v2`：不兼容变更（字段改名、类型变更）
- `v1.1`：兼容新增（新增可选字段）

## ToolInput 基类

```python
from pydantic import BaseModel, Field
from typing import Optional
import uuid

class ToolInput(BaseModel):
    """所有 Tool 输入必须继承此类"""
    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="请求追踪 ID")
    tenant_id: str = Field(..., description="租户 ID，不可为空")
    timeout: int = Field(default=30, ge=1, le=300, description="超时秒数")
    tool_version: str = Field(default="v1", description="Tool Schema 版本")
```

## ToolResult 基类

```python
from pydantic import BaseModel, Field
from typing import Optional, Any

class ToolResult(BaseModel):
    """所有 Tool 输出必须使用此类"""
    success: bool = Field(..., description="是否执行成功")
    tool_name: str = Field(..., description="Tool 名称")
    tool_version: str = Field(..., description="Tool Schema 版本")
    data: dict[str, Any] = Field(default_factory=dict, description="返回数据")
    error: Optional[str] = Field(default=None, description="错误信息")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="结果置信度 0.0-1.0")
    evidence_source: list[str] = Field(default_factory=list, description="数据来源列表")
    trace_id: str = Field(..., description="请求追踪 ID，与 ToolInput.trace_id 对应")
    execution_time_ms: int = Field(default=0, ge=0, description="执行耗时毫秒")
```

## Tool 注册规范

每个 Tool 必须提供：

1. **Tool Schema**（JSON Schema 格式）— 供 LLM function calling 使用
2. **Input Model**（Pydantic）— 继承 ToolInput
3. **Output Model**（Pydantic）— 使用 ToolResult
4. **实现代码** — 遵循 coding_rules.md

## Tool Schema 示例

```json
{
  "name": "ioc_lookup",
  "description": "查询 IOC (Indicator of Compromise) 信息",
  "version": "v1",
  "parameters": {
    "type": "object",
    "properties": {
      "type": {
        "type": "string",
        "enum": ["ip", "domain", "hash", "url"],
        "description": "IOC 类型"
      },
      "value": {
        "type": "string",
        "description": "IOC 值"
      }
    },
    "required": ["type", "value"]
  }
}
```

## 禁止事项

- 禁止 Tool 返回自由文本（必须返回 ToolResult）
- 禁止绕过 ToolInput 直接传参
- 禁止在 Tool 内部直接调用 LLM
- 禁止 Tool 直接操作数据库（必须走 Repository）
- 禁止未版本化的 Schema 变更
