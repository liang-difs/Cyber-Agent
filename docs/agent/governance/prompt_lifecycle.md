# Prompt Lifecycle

> 定义 Prompt 从创建到废弃的完整生命周期。

## 状态流转

```
draft → testing → stable → deprecated
  ↑        |
  └────────┘  (测试失败回退)
```

### draft
- 刚创建，尚未测试
- 可以自由修改
- 不允许在生产环境使用

### testing
- 正在进行回归测试
- 修改需要记录变更原因
- 可以在测试环境使用

### stable
- 通过所有回归测试
- **禁止直接修改**
- 修改必须：创建新版本 → 新版本走 draft → testing → stable
- 旧版本在新版本 stable 后标记 deprecated

### deprecated
- 已被新版本替代
- 保留用于回滚
- 不允许在新代码中使用

## 版本升级流程

1. 创建新版本文件 `{name}_v{n+1}.md`，状态为 draft
2. 修改 Prompt 内容
3. 运行 Prompt 回归测试
4. 测试通过 → 状态改为 testing
5. 集成测试通过 → 状态改为 stable
6. 旧版本状态改为 deprecated

## 回归测试要求

| Prompt 类型 | 必须测试 |
|------------|---------|
| system/ | 全量 Tool Calling 成功率 |
| react/ | 推理路径正确性、Observation 遗忘率 |
| tools/ | 单 Tool 成功率、JSON 合法率 |
| rag/ | 检索命中率、答案质量 |

## 版本记录

每个 Prompt 文件的 `## 变更日志` 部分必须记录所有版本变更。
