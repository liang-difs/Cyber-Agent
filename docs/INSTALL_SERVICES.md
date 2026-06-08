# 本地服务安装指南

## 1. 安装 PostgreSQL

### 方式一：使用 Winget（推荐）
```powershell
winget install PostgreSQL.PostgreSQL.17
```

### 方式二：手动下载安装
1. 访问 https://www.postgresql.org/download/windows/
2. 下载 PostgreSQL 17 安装程序
3. 运行安装程序，设置密码为 `cybersec_pass`
4. 端口保持默认 5432

### 安装后配置

1. **添加到 PATH**（如果未自动添加）：
```powershell
# 默认安装路径
$env:PATH += ";C:\Program Files\PostgreSQL\17\bin"
```

2. **创建数据库和用户**：
```powershell
# 打开 PowerShell，连接到 PostgreSQL
psql -U postgres

# 在 psql 命令行中执行：
CREATE USER cybersec WITH PASSWORD 'cybersec_pass';
CREATE DATABASE cybersec OWNER cybersec;
GRANT ALL PRIVILEGES ON DATABASE cybersec TO cybersec;
\q
```

3. **验证连接**：
```powershell
psql -U cybersec -d cybersec -h localhost
```

---

## 2. 安装 Redis

### 方式一：使用 Winget
```powershell
winget install Redis.Redis
```

### 方式二：使用 Memurai（Redis 兼容）
```powershell
winget install Memurai.MemuraiDeveloper
```

### 方式三：手动安装
1. 访问 https://github.com/microsoftarchive/releases/tags/win-3.0.504
2. 下载 Redis-x64-3.0.504.msi
3. 运行安装程序

### 安装后配置

1. **启动 Redis 服务**：
```powershell
# 如果使用 MSI 安装，服务会自动启动
# 手动启动：
redis-server

# 或作为 Windows 服务：
net start Redis
```

2. **验证 Redis**：
```powershell
redis-cli ping
# 应该返回 PONG
```

---

## 3. 更新环境变量

编辑项目根目录的 `.env` 文件：

```env
# 数据库配置
DATABASE_URL=postgresql+asyncpg://cybersec:cybersec_pass@localhost:5432/cybersec

# Redis 配置
REDIS_URL=redis://localhost:6379/0

# 其他配置保持不变
APP_ENV=development
AUTH_DEV_FALLBACK_ENABLED=true
JWT_SECRET=cybersec-local-dev-secret-20260603
CORS_ORIGINS=http://localhost:3000
```

---

## 4. 初始化数据库

```powershell
cd d:\Desktop\Agent\backend

# 初始化数据库表
python -m app.scripts.init_admin --username admin --password admin123 --role admin
```

---

## 5. 启动服务

### 启动 PostgreSQL（如果未作为服务运行）
```powershell
# 检查服务状态
Get-Service postgresql*

# 启动服务
Start-Service postgresql-x64-17
```

### 启动 Redis（如果未作为服务运行）
```powershell
# 检查服务状态
Get-Service Redis

# 启动服务
Start-Service Redis
```

### 启动后端
```powershell
cd d:\Desktop\Agent\backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 启动前端（新终端）
```powershell
cd d:\Desktop\Agent\frontend
npm run dev
```

---

## 6. 验证服务

### 检查 PostgreSQL
```powershell
psql -U cybersec -d cybersec -h localhost -c "SELECT version();"
```

### 检查 Redis
```powershell
redis-cli info server | findstr redis_version
```

### 检查后端
```powershell
curl http://localhost:8000/health
```

---

## 故障排除

### PostgreSQL 连接失败
1. 检查服务是否运行：`Get-Service postgresql*`
2. 检查端口是否监听：`netstat -an | findstr 5432`
3. 检查 pg_hba.conf 是否允许本地连接

### Redis 连接失败
1. 检查服务是否运行：`Get-Service Redis`
2. 检查端口是否监听：`netstat -an | findstr 6379`

### 数据库表不存在
```powershell
cd d:\Desktop\Agent\backend
python -c "from app.models.base import init_db; import asyncio; asyncio.run(init_db())"
```
