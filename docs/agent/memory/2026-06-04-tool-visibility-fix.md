# 2026-06-04: 工具可见性修复

## 问题描述

19个工具全部注册到ToolRegistry，但Agent系统提示词(SYSTEM_PROMPT)中只列出了14个工具，导致5个工具"注册但不可见"，Agent无法主动调用。

## 影响的工具

| 工具 | 功能 | 状态 |
|------|------|------|
| archive | 压缩包分析（ZIP/RAR/7Z/TAR） | 已修复 |
| api_doc_parser | API文档解析（Swagger/OpenAPI/Postman） | 已修复 |
| config_parser | 配置文件解析（JSON/YAML/XML/CSV/ENV/INI） | 已修复 |
| binary_analysis | 二进制分析（ELF/PE/Mach-O/Java Class） | 已修复 |
| task_planner | 任务规划引擎 | 已修复 |

## 修改内容

### 1. backend/app/agent/react.py
- 在SYSTEM_PROMPT的工具列表中添加了5个工具的描述
- 每个工具包含：名称、功能说明、输入参数、使用场景、可串联的其他工具

### 2. frontend/src/pages/Chat/index.tsx
- 更新TOOL_LABELS映射，添加了所有19个工具的中文标签
- 确保前端界面能正确显示工具名称

### 3. backend/app/tools/registry.py
- 在ARGUMENT_ALIASES中添加了5个新工具的参数别名映射
- 帮助LLM在发送错误参数名时自动修正

## 验证结果

- tests/test_tool_registry.py: 6 passed
- tests/test_react_agent.py: 12 passed
- 所有现有测试未受影响

## 工具使用方式

修复后，Agent可以自动识别并调用以下场景：

1. **压缩包分析**: "分析这个zip文件" / "解压并检查这个压缩包"
2. **API文档解析**: "解析这个Swagger文档" / "分析这个API接口"
3. **配置文件解析**: "检查这个配置文件的安全性" / "提取敏感信息"
4. **二进制分析**: "分析这个PE文件" / "检查这个ELF二进制"
5. **任务规划**: "帮我规划渗透测试步骤" / "生成应急响应计划"

## 相关文件

- `backend/app/agent/react.py` - SYSTEM_PROMPT定义
- `backend/app/tools/registry.py` - 工具注册和参数别名
- `frontend/src/pages/Chat/index.tsx` - 前端工具标签
- `backend/app/agent/tool_executor.py` - 工具注册执行器
