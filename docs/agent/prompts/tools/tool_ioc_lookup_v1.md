# Prompt: IOC Lookup Tool

## 元信息
- **版本**: v1
- **状态**: draft
- **作者**: chief_architect_agent
- **创建日期**: 2026-05-27
- **最后修改**: 2026-05-27
- **适用模型**: all

## Prompt 正文

### 工具名称
ioc_lookup

### 功能描述
查询 IOC (Indicator of Compromise) 信息，包括 IP、域名、哈希、URL 的威胁情报。

### 调用条件
当用户询问以下内容时调用：
- 某个 IP 是否恶意
- 某个域名是否安全
- 某个文件哈希的威胁信息
- 某个 URL 是否为钓鱼链接

### 输入参数
```json
{
  "type": "ip | domain | hash | url",
  "value": "具体的 IOC 值"
}
```

### 输出解读
```json
{
  "score": 0-100,        // 威胁评分，越高越危险
  "sources": [],          // 情报来源
  "tags": [],             // 标签（如 malware, phishing）
  "first_seen": "date",   // 首次发现时间
  "last_seen": "date"     // 最后发现时间
}
```

### 结果解读指导
- score >= 80: 高危，建议阻断
- score 50-79: 中危，建议监控
- score < 50: 低危或无威胁

## 变更日志
- v1: 初始版本
