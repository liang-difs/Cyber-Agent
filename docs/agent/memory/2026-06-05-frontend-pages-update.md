# 2026-06-05: 前端页面更新

## 更新内容

为Phase 5新增的功能创建了专用前端页面。

## 新增页面

### 1. 多智能体管理页面 (`/multi-agent`)
- **文件**: `frontend/src/pages/MultiAgent/index.tsx`
- **功能**:
  - 显示Agent统计信息（总数、空闲、忙碌、平均负载）
  - Agent列表（ID、角色、状态、负载、能力）
  - 角色分布和系统能力展示
  - 创建多智能体任务（应急响应、渗透测试、威胁狩猎等）

### 2. 规则引擎管理页面 (`/rules`)
- **文件**: `frontend/src/pages/RuleEngine/index.tsx`
- **功能**:
  - 规则统计（总数、Sigma/YARA分布）
  - 规则列表（按Sigma/YARA分类）
  - 按级别和标签分布
  - 规则匹配功能（日志/文件/数据匹配）

### 3. 知识图谱查看页面 (`/knowledge-graph`)
- **文件**: `frontend/src/pages/KnowledgeGraph/index.tsx`
- **功能**:
  - 图谱统计（实体总数、关系总数）
  - 实体列表和搜索
  - 实体详情（属性、关联实体）
  - 实体类型和关系类型分布

### 4. 响应动作管理页面 (`/response-actions`)
- **文件**: `frontend/src/pages/ResponseActions/index.tsx`
- **功能**:
  - 动作统计（总执行次数、成功/失败次数、成功率）
  - 执行历史列表
  - 按动作类型分布
  - 执行新动作（阻断IP、隔离主机、通知等）

## 路由配置更新

**App.tsx**:
- 添加新页面的lazy import
- 添加路由配置

**AppLayout**:
- 添加新图标导入
- 更新ROLE_MENU权限配置
- 添加菜单项

## 菜单结构

```
态势总览
智能对话
CVE 数据库
IoC 批量查询
────────────
PCAP 分析
资产管理
告警管理
攻击链分析
报告生成
────────────
多智能体        ← 新增
规则引擎        ← 新增
知识图谱        ← 新增
响应动作        ← 新增
────────────
审计日志
系统监控
用户管理
```

## 权限配置

| 页面 | viewer | analyst | admin |
|------|:------:|:-------:|:-----:|
| 多智能体 | ✓ | ✓ | ✓ |
| 规则引擎 | ✓ | ✓ | ✓ |
| 知识图谱 | ✓ | ✓ | ✓ |
| 响应动作 | ✗ | ✓ | ✓ |

## 相关文件

- `frontend/src/pages/MultiAgent/index.tsx`
- `frontend/src/pages/RuleEngine/index.tsx`
- `frontend/src/pages/KnowledgeGraph/index.tsx`
- `frontend/src/pages/ResponseActions/index.tsx`
- `frontend/src/App.tsx`
- `frontend/src/components/AppLayout/index.tsx`
