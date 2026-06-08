# 2026-06-05: 模块关联修复与事件驱动管线

## 修复内容

### 1. ActionManager Bug 修复

**问题**: `auto_respond()` 方法引用 `self.config`，但 `__init__` 中未初始化

**修复**:
- `backend/app/response/action_manager.py` - 添加 `self.config` 初始化
- 添加默认配置 `DEFAULT_CONFIG`

### 2. 多智能体框架修复

**问题**: Coordinator 创建时未传入 `tool_registry` 和 `llm_router`

**修复**:
- `backend/app/api/multi_agent.py` - 传入真实的 tool_registry 和 llm_router
- 注册子 Agent (Analyzer, Executor, Responder, Planner)
- 注册到消息总线

### 3. 告警事件驱动管线

**新增模块**:
- `backend/app/events/__init__.py` - 事件模块初始化
- `backend/app/events/alert_pipeline.py` - 告警事件驱动管线
- `backend/app/api/events.py` - 事件API端点

**管线功能**:
1. 规则引擎匹配 - 自动匹配Sigma规则
2. 知识图谱更新 - 自动提取IoC注入图谱
3. 响应动作执行 - 高危告警自动响应
4. 多智能体分析 - 关键告警触发协同分析

### 4. 告警处理流程集成

**修改文件**:
- `backend/app/tasks/alert_triage.py` - 告警处理完成后触发管线

## 数据流（修复后）

```
外部数据 --> Celery Task --> PostgreSQL Alert 表
                                    |
                                    v
                            告警事件管线 (自动触发)
                                    |
                    +---------------+---------------+
                    v               v               v
              规则引擎匹配     知识图谱注入      响应动作执行
                    |               |               |
                    v               v               v
              命中规则 -->     IoC提取 -->     阻断/隔离/通知
                                              (高危告警)
```

## 新增API端点

```
GET  /api/v1/events/pipeline/stats      # 管线统计
POST /api/v1/events/pipeline/enable     # 启用管线
POST /api/v1/events/pipeline/disable    # 禁用管线
POST /api/v1/events/pipeline/test       # 测试管线
GET  /api/v1/events/pipeline/connections # 连接状态
```

## 测试结果

- 所有模块导入测试通过
- ActionManager 配置初始化正常
- 告警管线处理测试成功
- 响应动作自动执行成功（3个动作）

## 模块连通性（修复后）

| 连接 | 状态 |
|------|:----:|
| 告警 → 规则引擎 | ✅ 已打通 |
| 告警 → 知识图谱 | ✅ 已打通 |
| 告警 → 响应动作 | ✅ 已打通 |
| 告警 → 多智能体 | ✅ 已打通（关键告警） |
| 多智能体 → 工具 | ✅ 已修复 |
| 多智能体 → LLM | ✅ 已修复 |

## 下一步

1. 测试完整的端到端流程
2. 添加更多Sigma规则
3. 完善知识图谱实体提取
4. 优化响应动作策略
