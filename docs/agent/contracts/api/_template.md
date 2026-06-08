# API Contract Template

> 所有 API 接口必须按此模板定义契约。

## 接口: `{METHOD} {path}`

### 元信息
- **版本**: v1
- **状态**: draft / stable / deprecated
- **认证**: required / optional / none
- **限流**: X req/min

### Request

#### Headers
```
Authorization: Bearer {jwt_token}
Content-Type: application/json
X-Tenant-ID: {tenant_id}
```

#### Body
```json
{
  "field1": "string (required)",
  "field2": 123
}
```

#### Path Parameters
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|

#### Query Parameters
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|

### Response

#### 200 OK
```json
{
  "code": 200,
  "data": {},
  "message": "success"
}
```

#### 400 Bad Request
```json
{
  "code": 400,
  "error": "validation_error",
  "message": "字段 xxx 不能为空"
}
```

#### 401 Unauthorized
```json
{
  "code": 401,
  "error": "unauthorized",
  "message": "Invalid token"
}
```

#### 500 Internal Server Error
```json
{
  "code": 500,
  "error": "internal_error",
  "message": "Internal server error"
}
```

### 示例

#### curl
```bash
curl -X POST http://localhost:8000/api/v1/xxx \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{"field1": "value"}'
```

### 变更日志
- v1: 初始版本
