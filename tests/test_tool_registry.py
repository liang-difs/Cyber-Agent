"""Tests for Tool Registry."""

import pytest

from app.tools.registry import ToolRegistry
from app.governance.tool_protocol import ToolInput, ToolResult


class DummyTool:
    name = "dummy"
    version = "v1"

    def get_schema(self):
        return {
            "type": "function",
            "function": {
                "name": "dummy",
                "description": "A dummy tool",
                "parameters": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                },
            },
        }

    async def execute(self, input_data: ToolInput) -> ToolResult:
        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data={"value": getattr(input_data, "value", "ok")},
            trace_id=input_data.trace_id,
        )


@pytest.fixture
def registry():
    return ToolRegistry()


def test_register_and_get(registry):
    tool = DummyTool()
    registry.register(tool)
    assert registry.get("dummy") is tool


def test_get_nonexistent(registry):
    assert registry.get("nope") is None


def test_get_schemas(registry):
    registry.register(DummyTool())
    schemas = registry.get_schemas()
    assert len(schemas) == 1
    assert schemas[0]["function"]["name"] == "dummy"


def test_list_tools(registry):
    registry.register(DummyTool())
    names = registry.list_names()
    assert "dummy" in names


def test_double_register_raises(registry):
    registry.register(DummyTool())
    with pytest.raises(ValueError):
        registry.register(DummyTool())


import asyncio


def test_execute_with_custom_input(registry):
    """Registry should use the tool's own input class, not EchoInput."""
    from app.governance.tool_protocol import ToolInput

    class CustomInput(ToolInput):
        value: str

    class CustomTool:
        name = "custom"
        version = "v1"
        input_class = CustomInput

        def get_schema(self):
            return {
                "type": "function",
                "function": {
                    "name": "custom",
                    "description": "Custom tool",
                    "parameters": {
                        "type": "object",
                        "properties": {"value": {"type": "string"}},
                        "required": ["value"],
                    },
                },
            }

        async def execute(self, input_data):
            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data={"got": input_data.value},
                trace_id=input_data.trace_id,
            )

    registry.register(CustomTool())
    result = asyncio.run(registry.execute("custom", {"value": "test"}, "trace-1"))
    assert result["success"] is True
    assert result["data"]["got"] == "test"
