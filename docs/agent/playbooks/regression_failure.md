# Regression Failure Playbook

> 回归测试失败时的处理手册。

## 处理流程

### 1. 确认失败范围
```bash
# 运行全部回归测试
pytest tests/ai_runtime/ -v --tb=short

# 确认哪些测试失败
pytest tests/ai_runtime/ -v --tb=short | grep FAILED
```

### 2. 定位变更
```bash
# 查看最近的变更
git log --oneline -10
git diff HEAD~1

# 检查 Prompt 变更
git diff HEAD~1 -- prompts/

# 检查 Tool Schema 变更
git diff HEAD~1 -- contracts/tool/
```

### 3. 分析根因

| 失败类型 | 可能原因 | 处理方式 |
|---------|---------|---------|
| JSON parse 失败 | Prompt 变更 | 回退 Prompt |
| Tool 选择错误 | Tool 描述变更 | 回退描述 |
| Context 遗忘 | Context 策略变更 | 回退策略 |
| Hallucination | Prompt 约束减弱 | 加强约束 |

### 4. 决策

- **回退**: 如果变更非必要，直接回退
- **修复**: 如果变更必要，修复 Prompt/代码后重新测试
- **标记**: 如果是已知的可接受退化，标记到 `known_issues.md`

### 5. 记录

将本次回归失败记录到 `memory/prompt_failures.md` 或 `memory/failed_attempts.md`。

## 预防

- 所有 Prompt 变更必须先跑回归测试
- 使用 `governance/prompt_lifecycle.md` 管理版本
- 定期运行全量回归测试
