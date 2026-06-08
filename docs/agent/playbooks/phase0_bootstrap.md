# Phase 0 Bootstrap Playbook

> Phase 0 初始化操作手册。

## 目标
验证 LiteLLM Router + Claude API 连通性。

## 步骤

### 1. 环境准备
```bash
# 启动基础设施
docker compose up -d

# 验证 PostgreSQL
docker exec -it postgres psql -U postgres -c "SELECT 1"

# 验证 Redis
docker exec -it redis redis-cli ping
```

### 2. LiteLLM Router 配置
```bash
# 安装 LiteLLM
pip install litellm

# 配置 API Key
export ANTHROPIC_API_KEY=xxx

# 验证 Router
python -c "from litellm import completion; print('OK')"
```

### 3. Claude API 连通性验证
```bash
# 最小调用测试
python -c "
import litellm
response = litellm.completion(
    model='claude-opus-4-7',
    messages=[{'role': 'user', 'content': 'Say hello'}]
)
print(response.choices[0].message.content)
"
```

### 4. 更新状态
- 更新 `PROJECT_STATE.json`
- 记录验证结果到 `known_issues.md`

## 验证清单

- [ ] PostgreSQL 可连接
- [ ] Redis 可连接
- [ ] LiteLLM 安装成功
- [ ] Claude API 可调用
- [ ] Router fallback 配置正确
