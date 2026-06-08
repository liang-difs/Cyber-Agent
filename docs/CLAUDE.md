# CyberSec Agent Rules

开始工作前必须阅读：

- runtime/AGENT_CONTEXT.md
- governance/coding_rules.md
- governance/tool_protocol.md
- runtime/PROJECT_STATE.json

禁止：
- 未授权重构
- 跨阶段开发
- 修改 ADR
- 修改 stable prompt
- 新增未批准依赖

所有 Tool：
- 必须版本化
- 必须结构化输出
- 必须返回 confidence
- 必须包含 evidence_source

所有 Prompt：
- 必须版本号
- 禁止 inline prompt
- 禁止业务代码中硬编码 prompt