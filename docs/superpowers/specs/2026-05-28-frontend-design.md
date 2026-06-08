# CyberSec Agent Phase 2 前端设计文档

> **日期:** 2026-05-28
> **阶段:** Phase 2 — 基础功能模块前端
> **技术栈:** React 18 + TypeScript + Vite + Ant Design 5 + ECharts + Zustand

## 1. 概述

Phase 2 前端为 CyberSec Agent 提供 Web 界面，包含三个核心页面：

1. **聊天界面** — 与 ReAct Agent 实时对话，展示工具调用进度
2. **CVE 搜索页** — CVE 数据库查询、筛选、统计图表
3. **登录页** — JWT 认证

### 1.1 设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| 构建工具 | Vite | 启动快、HMR 好、TypeScript 原生支持 |
| UI 框架 | Ant Design 5 | 主题切换开箱即用（ConfigProvider + algorithm） |
| 状态管理 | Zustand | 轻量、TypeScript 友好、适合中小型应用 |
| HTTP 客户端 | axios | 拦截器方便注入 JWT |
| 路由 | React Router 6 | 文件式组织，v6 API 简洁 |
| 图表 | ECharts | 功能丰富，Ant Design 风格兼容 |
| 部署 | Vite dev server + proxy | 开发时独立运行，proxy 转发 API 到 FastAPI |

## 2. 项目结构

```
frontend/
├── index.html
├── package.json
├── tsconfig.json
├── vite.config.ts
├── src/
│   ├── main.tsx                  # 入口：ConfigProvider + Router + Zustand Provider
│   ├── App.tsx                   # 路由配置
│   │
│   ├── api/
│   │   ├── client.ts             # axios 实例 + JWT 拦截器 + baseURL
│   │   └── auth.ts               # login() / getCurrentUser()
│   │
│   ├── hooks/
│   │   ├── useWebSocket.ts       # WebSocket 连接管理 + 事件解析
│   │   └── useTheme.ts           # 主题切换 hook (light/dark)
│   │
│   ├── stores/
│   │   ├── auth.ts               # JWT token + 用户信息 + login/logout
│   │   └── chat.ts               # 会话列表 + 当前会话 + 消息历史
│   │
│   ├── pages/
│   │   ├── Login/
│   │   │   └── index.tsx         # 登录表单
│   │   ├── Chat/
│   │   │   ├── index.tsx         # 聊天页主布局
│   │   │   ├── SessionList.tsx   # 左侧会话列表
│   │   │   ├── MessageList.tsx   # 消息区域
│   │   │   ├── MessageInput.tsx  # 底部输入框
│   │   │   └── ToolProgress.tsx  # 工具调用进度卡片
│   │   └── CveSearch/
│   │       ├── index.tsx         # CVE 搜索页主布局
│   │       ├── SearchBar.tsx     # 搜索框 + 筛选
│   │       ├── CveTable.tsx      # CVE 列表表格
│   │       ├── CveDetail.tsx     # CVE 详情抽屉
│   │       └── StatsPanel.tsx    # 统计图表面板
│   │
│   ├── components/
│   │   ├── AppLayout/
│   │   │   └── index.tsx         # Ant Design Layout + Sider + 菜单
│   │   ├── ChatMessage/
│   │   │   └── index.tsx         # 消息气泡组件
│   │   ├── ThemeToggle/
│   │   │   └── index.tsx         # 亮/暗主题切换按钮
│   │   └── LlmStatus/
│   │       └── index.tsx         # LLM 状态指示器 (provider + model)
│   │
│   └── types/
│       └── api.ts                # 后端 API 类型定义
│
├── public/
│   └── favicon.ico
└── .env.development              # VITE_API_BASE_URL=http://localhost:8000
```

## 3. 页面设计

### 3.1 登录页 (`/login`)

- Ant Design Form：用户名 + 密码 + 登录按钮
- 调用 `POST /api/v1/auth/login`
- 成功后 JWT 存入 Zustand store（持久化到 localStorage）
- 自动跳转到 `/chat`
- 错误提示：Ant Design message 组件

### 3.2 聊天页 (`/chat`)

**布局：** 左右分栏

**左侧 — 会话列表 (SessionList)**
- 新建会话按钮
- 会话列表（显示最近消息预览 + 时间）
- 点击切换会话
- 当前会话高亮

**右侧 — 聊天区域**
- **顶部**：当前会话标题 + LLM 状态指示器
- **消息区域 (MessageList)**：
  - 用户消息：右对齐，蓝色气泡
  - AI 回复：左对齐，灰色气泡
  - AI 回复上方：**工具调用进度卡片 (ToolProgress)**
    - 每个工具调用显示为一行：工具图标 + 工具名 + 状态 + 耗时
    - 状态：`running`（蓝色旋转）/ `success`（绿色勾）/ `failed`（红色叉）
    - 多个工具调用时垂直排列
    - 可折叠/展开
  - 底部显示 token 统计（done 事件后）
- **底部输入框 (MessageInput)**：
  - TextArea + 发送按钮
  - Enter 发送，Shift+Enter 换行
  - 发送时禁用输入，等待 done 事件后恢复

**WebSocket 事件处理：**
```
llm_backend → 更新 LLM 状态指示器
tool_call   → 添加工具进度卡片（running 状态）
tool_result → 更新工具进度卡片（success/failed）
token       → 追加到 AI 消息内容
done        → 显示 token 统计，恢复输入框
error       → 显示错误提示
```

### 3.3 CVE 搜索页 (`/cve`)

**布局：** 上下结构

**顶部 — 搜索区域 (SearchBar)**
- 搜索框：支持 CVE-ID（如 CVE-2024-3400）和关键词
- 严重程度筛选：下拉多选（CRITICAL / HIGH / MEDIUM / LOW）
- 搜索按钮

**中部 — 结果表格 (CveTable)**
- Ant Design Table，列：
  - CVE ID（链接样式，点击打开详情）
  - 严重程度（Tag 颜色：CRITICAL=红, HIGH=橙, MEDIUM=黄, LOW=蓝）
  - CVSS 分数（进度条样式）
  - 发布日期
  - 摘要（截断，hover 显示完整）
- 分页
- 排序：默认按 CVSS 分数降序

**右侧 — 统计面板 (StatsPanel)**
- 严重程度分布饼图（ECharts）
- 最近 CVE 时间线（最近 10 条）
- 总数统计

**详情抽屉 (CveDetail)**
- 点击表格行，右侧滑出 Drawer
- 显示：完整描述、CVSS 评分详情、受影响产品、参考链接

**数据来源：**
- CVE 搜索通过 Agent 的 `rag_search` 工具查询
- CVE 列表需要后端新增 HTTP API（当前只有 RAG 搜索，无列表接口）
- 统计数据需要后端新增统计 API

## 4. API 集成

### 4.1 现有 API（直接使用）

| 用途 | 方法 | 端点 |
|------|------|------|
| 登录 | POST | `/api/v1/auth/login` |
| 聊天 | WS | `/api/v1/agent/chat?token=<jwt>` |
| 健康检查 | GET | `/health` |

### 4.2 需要新增的 API

| 用途 | 方法 | 端点 | 说明 |
|------|------|------|------|
| CVE 列表 | GET | `/api/v1/cve/list` | 分页、筛选、排序 |
| CVE 详情 | GET | `/api/v1/cve/{cve_id}` | 单个 CVE 详情 |
| CVE 统计 | GET | `/api/v1/cve/stats` | 严重程度分布、总数 |

这些 API 需要在后端新增，作为 Phase 2 前端的一部分。

**数据源说明：** BM25 索引是内存存储，服务器重启后重新从 NVD 导入。CVE 列表/统计 API 直接读取 BM25 内存数据。这意味着：
- 服务器重启后需要等待导入完成才能查询
- 列表数据量取决于启动时导入的 `max_results`（当前 200 条）
- 不需要额外的持久化存储

## 5. 状态管理

### 5.1 Auth Store (`stores/auth.ts`)

```typescript
interface AuthState {
  token: string | null;
  user: {
    sub: string;       // user ID
    role: string;       // admin / user
    tenant_id: string;
  } | null;
  isAuthenticated: boolean;

  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  loadFromStorage: () => void;  // 启动时从 localStorage 恢复
}
```

### 5.2 Chat Store (`stores/chat.ts`)

```typescript
interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
  toolCalls?: ToolCallInfo[];
  tokenCount?: number;
}

interface ToolCallInfo {
  tool: string;
  status: 'running' | 'success' | 'failed';
  startTime: number;
  endTime?: number;
}

interface Session {
  id: string;
  title: string;          // 首条消息摘要
  lastMessage: string;
  updatedAt: number;
}

interface ChatState {
  sessions: Session[];
  currentSessionId: string | null;
  messages: Message[];

  addMessage: (msg: Message) => void;
  updateLastMessage: (content: string) => void;  // 追加 token
  addToolCall: (toolCall: ToolCallInfo) => void;
  updateToolCall: (tool: string, status: string) => void;
  setCurrentSession: (id: string) => void;
  createSession: () => string;
}
```

## 6. 主题系统

### 6.1 实现

- Ant Design 5 `ConfigProvider` 包裹整个应用
- `theme.algorithm` 切换：`defaultAlgorithm` (亮) / `darkAlgorithm` (暗)
- 自定义 token：主色调 `#1677ff`（Ant Design 默认蓝）
- 安全语义色：`success` = `#52c41a`, `warning` = `#faad14`, `error` = `#ff4d4f`

### 6.2 useTheme Hook

```typescript
function useTheme() {
  const [isDark, setIsDark] = useState(() => {
    return localStorage.getItem('theme') === 'dark';
  });

  const toggleTheme = () => {
    const next = !isDark;
    setIsDark(next);
    localStorage.setItem('theme', next ? 'dark' : 'light');
  };

  const algorithm = isDark ? darkAlgorithm : defaultAlgorithm;

  return { isDark, toggleTheme, algorithm };
}
```

### 6.3 暗色主题额外样式

- 背景色：`#141414`（Ant Design 暗色默认）
- 侧边栏：`#1f1f1f`
- 代码/日志区域：`#0d0d0d`，等宽字体
- 消息气泡暗色适配

## 7. WebSocket 集成

### 7.1 useWebSocket Hook

```typescript
function useWebSocket(token: string) {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<WSEvent[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  // 连接管理
  const connect = () => { /* 建立连接 */ };
  const disconnect = () => { /* 断开连接 */ };
  const sendMessage = (content: string, sessionId?: string) => {
    wsRef.current?.send(JSON.stringify({
      type: 'chat',
      content,
      session_id: sessionId,
    }));
  };

  // 事件处理
  const onMessage = (event: MessageEvent) => {
    const data = JSON.parse(event.data) as WSEvent;
    setEvents(prev => [...prev, data]);
  };

  // 自动重连
  useEffect(() => {
    connect();
    return disconnect;
  }, [token]);

  return { connected, sendMessage, events, clearEvents: () => setEvents([]) };
}
```

### 7.2 事件类型定义

```typescript
type WSEvent =
  | { type: 'llm_backend'; provider: string; model: string }
  | { type: 'tool_call'; tool: string; status: 'running' }
  | { type: 'tool_result'; tool: string; success: boolean }
  | { type: 'token'; content: string }
  | { type: 'done'; session_id: string; total_tokens: number }
  | { type: 'error'; code: string; message: string }
```

## 8. 路由设计

```typescript
// App.tsx
<Routes>
  <Route path="/login" element={<Login />} />
  <Route element={<ProtectedRoute />}>    {/* 鉴权守卫 */}
    <Route element={<AppLayout />}>       {/* 侧边栏布局 */}
      <Route path="/chat" element={<Chat />} />
      <Route path="/cve" element={<CveSearch />} />
    </Route>
  </Route>
  <Route path="*" element={<Navigate to="/chat" />} />
</Routes>
```

- `ProtectedRoute`：检查 JWT 是否存在且未过期，未登录跳转 `/login`
- `AppLayout`：Ant Design Layout + Sider + Outlet

## 9. 后端新增 API 设计

### 9.1 CVE 列表

```
GET /api/v1/cve/list?page=1&page_size=20&severity=HIGH&keyword=remote

Response:
{
  "items": [
    {
      "cve_id": "CVE-2024-3400",
      "description": "...",
      "cvss_score": 10.0,
      "severity": "CRITICAL",
      "published": "2024-04-12T..."
    }
  ],
  "total": 200,
  "page": 1,
  "page_size": 20
}
```

### 9.2 CVE 详情

```
GET /api/v1/cve/CVE-2024-3400

Response:
{
  "cve_id": "CVE-2024-3400",
  "description": "...",
  "cvss_score": 10.0,
  "severity": "CRITICAL",
  "published": "2024-04-12T...",
  "affected_products": [...],
  "references": [...]
}
```

### 9.3 CVE 统计

```
GET /api/v1/cve/stats

Response:
{
  "total": 200,
  "by_severity": {
    "CRITICAL": 15,
    "HIGH": 45,
    "MEDIUM": 80,
    "LOW": 60
  },
  "recent": [
    {"cve_id": "CVE-2024-3400", "severity": "CRITICAL", "published": "..."}
  ]
}
```

## 10. 依赖清单

```json
{
  "dependencies": {
    "react": "^18.3.0",
    "react-dom": "^18.3.0",
    "react-router-dom": "^6.26.0",
    "antd": "^5.20.0",
    "@ant-design/icons": "^5.4.0",
    "axios": "^1.7.0",
    "zustand": "^4.5.0",
    "echarts": "^5.5.0",
    "echarts-for-react": "^3.0.0",
    "dayjs": "^1.11.0"
  },
  "devDependencies": {
    "typescript": "^5.5.0",
    "vite": "^5.4.0",
    "@vitejs/plugin-react": "^4.3.0",
    "@types/react": "^18.3.0",
    "@types/react-dom": "^18.3.0"
  }
}
```

## 11. Vite 配置

```typescript
// vite.config.ts
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/api/v1/agent/chat': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
});
```

## 12. 实现范围

### Phase 2 前端 MVP

- [x] 登录页（JWT 认证）
- [x] 聊天界面（WebSocket 实时对话）
- [x] 工具调用进度展示
- [x] CVE 搜索页（搜索 + 列表 + 详情 + 统计）
- [x] 亮/暗主题切换
- [x] 响应式布局（基本适配）

### 不在范围内

- 用户注册（Phase 1 使用内存用户）
- IoC/IP 查询独立页面（通过聊天界面使用）
- 关系图谱（AntV G6，后续阶段）
- 导出功能
- 多语言支持
