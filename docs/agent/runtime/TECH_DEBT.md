# Technical Debt Tracker

> 记录所有已知技术债。每项必须有：描述、影响、优先级、创建日期。

## 格式

```markdown
### TD-XXX: 标题
- **优先级**: P0 / P1 / P2
- **影响**: 简述影响范围
- **创建日期**: YYYY-MM-DD
- **描述**: 详细说明
- **预计工作量**: S / M / L
```

## 当前技术债

### TD-001: 前端零测试覆盖
- **优先级**: P1
- **影响**: 前端回归风险高，重构信心不足
- **创建日期**: 2026-06-01
- **描述**: 前端无任何测试文件。Playwright 已安装但未配置。CI 中仅有 tsc 类型检查。
- **预计工作量**: L

### TD-002: react.py run/run_streaming 逻辑重复
- **优先级**: P2
- **影响**: 维护成本高，修改一处需同步修改两处
- **创建日期**: 2026-06-01
- **描述**: ReAct Agent 的 `run()` 和 `run_streaming()` 共享约 80% 相同逻辑（dedup、tool call limits、web search guardrails、CVE catalog fallback）。
- **预计工作量**: M

### TD-003: 前端 IoC/IP 卡片工具函数重复
- **优先级**: P2
- **影响**: 代码冗余
- **创建日期**: 2026-06-01
- **描述**: `parseNumericScore` 和 `getScoreColor` 在 IocCard.tsx 和 IpCard.tsx 中完全重复。severity 颜色映射已提取到 constants/severity.ts，但这两个函数未提取。
- **预计工作量**: S

### TD-004: HTTP 明文敏感数据检测器未实现
- **优先级**: P3
- **影响**: 无法检测 HTTP 明文传输中的凭据泄露
- **创建日期**: 2026-06-01
- **描述**: 需要应用层解析 HTTP POST body 中的 password/token/auth 字段，误报率高，需独立排期。
- **预计工作量**: M

### TD-005: IP 信誉未接入 PCAP 告警置信度计算
- **优先级**: P2
- **影响**: PCAP 告警置信度未利用已查询的 IP 信誉数据
- **创建日期**: 2026-06-01
- **描述**: `_build_pcap_alert_fields` 函数签名已更新支持 `ip_reputation` 参数，但调用方尚未传递 IP 信誉数据。
- **预计工作量**: S

### TD-006: 资产管理未与告警研判联动
- **优先级**: P2
- **影响**: 告警研判缺少资产上下文（关键性、负责人、部门）
- **创建日期**: 2026-06-01
- **描述**: Asset 模型和 CRUD API 已建，但告警研判时未查询关联资产信息注入到 assessment 中。
- **预计工作量**: S

### TD-007: Celery 4 级优先队列未实现
- **优先级**: P2
- **影响**: 大任务可能阻塞紧急任务
- **创建日期**: 2026-06-01
- **描述**: 执行文档设计了 critical/high/default/low 四级队列，当前只有 alert_triage 和 pcap_analysis 两个 task，未按优先级分离队列。
- **预计工作量**: S

---

## 已解决

（已完成的技术债移至此处存档）
