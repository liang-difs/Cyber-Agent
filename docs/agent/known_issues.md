# Known Issues

> 已知问题追踪。所有 Agent 在发现新问题时必须更新此文件。

## 格式

```markdown
### KI-XXX: 标题
- **状态**: open / investigating / resolved
- **优先级**: P0 / P1 / P2 / P3
- **发现日期**: YYYY-MM-DD
- **发现者**: agent/human
- **描述**: 问题描述
- **影响**: 影响范围
- **临时方案**: 如有
- **根因**: 分析后填写
- **解决方案**: 解决后填写
```

## 当前问题

### KI-001: 生产级用户体系仍需关闭开发回退
- **状态**: investigating
- **优先级**: P1
- **发现日期**: 2026-05-29
- **发现者**: agent
- **描述**: 登录已改为优先查询 PostgreSQL `users` 表，并提供 `app.scripts.init_admin` 初始化管理员；为了兼容本地演示和现有测试，仍保留 `AUTH_DEV_FALLBACK_ENABLED` 控制的开发默认用户。
- **影响**: 如果生产环境未关闭开发回退，仍可能暴露默认账号风险。
- **临时方案**: 生产部署先运行 `python -m app.scripts.init_admin --username admin --password '<strong-password>'`，再设置 `AUTH_DEV_FALLBACK_ENABLED=false`。
- **根因**: 需要兼容当前开发/测试环境没有预置用户表数据的情况。
- **解决方案**: 增加部署文档/环境校验，在生产配置中强制关闭开发回退。

### KI-003: 前端 vendor chunk 仍偏大
- **状态**: open
- **优先级**: P2
- **发现日期**: 2026-05-29
- **发现者**: agent
- **描述**: 前端已完成路由懒加载和 vendor 拆分，但 `vendor-antd` 与 `vendor-charts` 仍接近 1MB 级别。
- **影响**: 访问首次需要相关页面时仍会下载较大的 UI/图表依赖。
- **临时方案**: 当前这些 chunk 已按页面懒加载，不再集中进入单一主包。
- **根因**: Ant Design 与 ECharts 依赖体积较大，当前页面广泛使用完整组件集。
- **解决方案**: 后续按页面进一步组件级懒加载，或评估更轻量图表/表格方案。

### KI-007: 前端零测试覆盖
- **状态**: open
- **优先级**: P1
- **发现日期**: 2026-06-01
- **发现者**: agent
- **描述**: 前端无任何测试文件。Playwright 已安装但未配置测试脚本。
- **影响**: 前端回归风险高，重构信心不足。
- **临时方案**: 手动验证。
- **根因**: 前期开发优先功能交付，未建立测试体系。
- **解决方案**: 补充核心组件和页面的 Playwright E2E 测试。

### KI-008: react.py run/run_streaming 逻辑重复
- **状态**: open
- **优先级**: P2
- **发现日期**: 2026-06-01
- **发现者**: agent
- **描述**: ReAct Agent 的 `run()` 和 `run_streaming()` 共享约 80% 相同逻辑。
- **影响**: 修改一处需同步修改两处，维护成本高。
- **临时方案**: 无。
- **根因**: 流式模式需要增量 JSON 提取，导致主循环逻辑分叉。
- **解决方案**: 提取共享逻辑到基方法，流式模式作为 overlay。

### KI-014: 端口扫描检测误判 DNS 服务器
- **状态**: resolved
- **优先级**: P1
- **发现日期**: 2026-06-01
- **发现者**: human
- **描述**: Google DNS (8.8.8.8/8.8.4.4) 的 DNS 响应被误判为端口扫描。
- **影响**: 研判报告将正常 DNS 流量标记为高危端口扫描。
- **根因**: `_detect_port_scan` 统计"源 IP → 不同目标端口数"，DNS 响应（源端口 53 → 客户端随机端口）恰好命中此模式。
- **解决方案**: 排除已知 DNS 服务器 + 源端口 53 的 IP。

### KI-015: 仪表盘告警趋势查询 SQL 兼容性
- **状态**: resolved
- **优先级**: P0
- **发现日期**: 2026-06-01
- **发现者**: human

### KI-016: PCAP 工具缺失 get_settings 导致会话报错
- **状态**: resolved
- **优先级**: P1
- **发现日期**: 2026-06-01
- **发现者**: agent
- **描述**: Agent 会话在执行 PCAP 分析时，`app.tools.pcap_tool` 内部调用 `_query_ip_reputations()` 触发 `NameError: get_settings is not defined`。
- **影响**: PCAP 分析会在异常富化阶段直接失败，用户无法拿到完整研判结果。
- **根因**: `pcap_tool.py` 使用了 `get_settings()`，但文件顶部未导入该函数。
- **解决方案**: 在 `backend/app/tools/pcap_tool.py` 顶部显式导入 `from app.core.config import get_settings`，并补充回归测试覆盖异常富化路径。

### KI-017: 本地 LLM 配置别名不统一
- **状态**: resolved
- **优先级**: P1
- **发现日期**: 2026-06-02
- **发现者**: agent
- **描述**: LLM 配置文档中同时出现 `LLM_API_KEY` 与 `OPENAI_API_KEY`，但 Router 只依赖后者，导致按旧文档配置时兼容服务可能无法正确启动。
- **影响**: 旧版 OpenAI-compatible 配置在某些环境下表现为“已经切换但仍无法连通”。
- **根因**: `Settings` 和 Router 没有统一兼容别名，配置入口与运行时读取不一致。
- **解决方案**: `Settings` 统一支持 `OPENAI_API_KEY` / `LLM_API_KEY` / `ANTHROPIC_API_KEY`，Router 显式解析 provider、base_url 和 api_key，并增加回归测试。

### KI-018: LLM 切换接口路径未适配生产代理
- **状态**: resolved
- **优先级**: P1
- **发现日期**: 2026-06-02
- **发现者**: agent
- **描述**: 前端 LLM 切换按钮调用 `/llm/models` 与 `/llm/switch`，在生产 nginx 仅代理 `/api/` 的情况下会落入 SPA fallback，导致前端把 HTML 误判成接口失败。
- **影响**: 监控页与会话页的模型切换按钮在生产环境切换失败，状态也无法正确刷新。
- **根因**: 监控接口仍暴露在根路径，未统一进入 `/api/v1` 路由。
- **解决方案**: 前端改为通过 `/api/v1/llm/...` 的统一 client 调用，后端保留旧路径兼容别名，并为切换接口增加管理员权限控制。
- **描述**: 仪表盘不显示告警数据，实际有 4000+ 条告警。
- **影响**: 态势总览页告警区域空白。
- **根因**: `func.make_interval(days=14)` 在 SQLAlchemy 中不兼容，异常被 try/except 吞掉返回空数据。
- **解决方案**: 改用 Python `datetime.timedelta` 计算截止日期。

### KI-016: PCAP 上传路径白名单不完整
- **状态**: resolved
- **优先级**: P0
- **发现日期**: 2026-06-01
- **发现者**: human
- **描述**: 上传的 PCAP 文件分析失败，提示"路径不在允许的目录范围内"。
- **影响**: 所有通过前端上传的 PCAP 文件无法分析。
- **根因**: 文件保存到 `backend/data/uploads/` 但白名单只有 `Agent/data/` 和 `/tmp`。
- **解决方案**: 白名单新增 `backend/data/` 目录。

### KI-017: IoC 批量查询 asyncio import 错误
- **状态**: resolved
- **优先级**: P0
- **发现日期**: 2026-06-01
- **发现者**: human
- **描述**: IoC 批量查询报错 `UnboundLocalError: local variable 'asyncio' referenced before assignment`。
- **影响**: IoC 批量查询功能完全不可用。
- **根因**: `asyncio` 在函数体后半段才 import，但前面已用 `asyncio.Semaphore`。
- **解决方案**: `import asyncio` 移到文件顶部。

---

## 已解决

### KI-006: Agent 会话回复不是真正流式输出
- **状态**: resolved
- **优先级**: P1
- **发现日期**: 2026-05-29
- **根因**: ReAct prompt 强制 LLM 输出 JSON，旧版 run_streaming 只有在完整 JSON 解析后才提取 final_answer。
- **解决方案**: 新增未闭合 JSON 字符串前缀提取逻辑，实时发送 answer_token。

### KI-004: Celery worker 未注册 PCAP/告警任务
- **状态**: resolved
- **优先级**: P1
- **发现日期**: 2026-05-29
- **根因**: celery_app 只依赖 autodiscover。
- **解决方案**: 显式 include/import alert_triage 与 pcap_analysis。

### KI-005: PCAP 解析产生复合 IP 与 1970 时间
- **状态**: resolved
- **优先级**: P1
- **发现日期**: 2026-05-29
- **根因**: tshark fields 输出未指定 occurrence 策略。
- **解决方案**: tshark 增加 `-E occurrence=f`；相对时间戳标记 time_basis=relative。

### KI-002: LLM Router 状态尚未暴露到监控
- **状态**: resolved
- **优先级**: P1
- **发现日期**: 2026-05-29
- **解决方案**: `/health/detailed` 已增加 `checks.llm`。

### KI-009: PCAP 报告告警置信度全为 0%
- **状态**: resolved
- **优先级**: P0
- **发现日期**: 2026-06-01
- **根因**: `confidence or 0.0` 在 confidence 恰好为 0 时回退。
- **解决方案**: 改为显式 None 检查 + DB 为空时从 pcap_result 构建虚拟告警。

### KI-010: TLS downgrade 告警泛滥
- **状态**: resolved
- **优先级**: P0
- **发现日期**: 2026-06-01
- **根因**: 聚合 key 仅为 tls_ver。
- **解决方案**: key 改为 (tls_ver, src_ip)，TLS_MIN_COUNT=10，总量 >=50 全局汇总。

### KI-011: ATT&CK 映射不准确
- **状态**: resolved
- **优先级**: P1
- **发现日期**: 2026-06-01
- **根因**: TACTIC_MAP 使用通用关键词匹配，缺少 pcap 规则精确映射。
- **解决方案**: suspicious_port→TA0011/T1571, tls_downgrade→TA0005/T1600。

### KI-012: IoC 列表混入合法 IP 和本地主机名
- **状态**: resolved
- **优先级**: P1
- **发现日期**: 2026-06-01
- **根因**: 无白名单过滤机制。
- **解决方案**: IP 白名单 + multicast 过滤 + 非 FQDN 过滤。

### KI-013: brute_force 误标 C2 信标流量
- **状态**: resolved
- **优先级**: P1
- **发现日期**: 2026-06-01
- **根因**: 检测器未区分单目标暴力破解和多目标信标模式。
- **解决方案**: >=3 目标同端口 → c2_beacon (critical)，否则 brute_force (high)。
