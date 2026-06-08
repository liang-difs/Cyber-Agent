# WebSocket Contract Template

> 所有 WebSocket 消息必须按此模板定义契约。

## WebSocket 连接

### 连接地址
```
ws://localhost:8000/ws/{tenant_id}?token={jwt_token}
```

### 认证
连接时通过 query parameter 传递 JWT token。

## 消息格式

### 通用结构

```json
{
  "type": "message_type",
  "payload": {},
  "trace_id": "uuid",
  "timestamp": "ISO8601"
}
```

### Client → Server 消息类型

#### `{type}` — 消息类型说明

```json
{
  "type": "xxx",
  "payload": {
    "field1": "string"
  },
  "trace_id": "uuid"
}
```

### Server → Client 消息类型

#### `{type}` — 消息类型说明

```json
{
  "type": "xxx",
  "payload": {
    "field1": "string"
  },
  "trace_id": "uuid",
  "timestamp": "ISO8601"
}
```

## 错误消息

```json
{
  "type": "error",
  "payload": {
    "code": "error_code",
    "message": "错误描述"
  },
  "trace_id": "uuid",
  "timestamp": "ISO8601"
}
```

## 心跳

Client 每 30s 发送：
```json
{ "type": "ping" }
```

Server 回复：
```json
{ "type": "pong" }
```

## 变更日志
- v1: 初始版本
