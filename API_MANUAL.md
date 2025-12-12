# Helm Proxy API 手册

## 基础信息

- **Base URL**: `http://localhost:8443`
- **Content-Type**: `application/json`
- **认证**: 当前版本无需认证（生产环境建议配置）

## 通用响应格式

### 成功响应

```json
{
  "success": true,
  "data": { ... }
}
```

### 错误响应

```json
{
  "success": false,
  "error": {
    "code": "error_code",
    "message": "错误描述",
    "details": "详细错误信息"
  }
}
```

## 1. 系统健康检查

### 1.1 健康检查

**GET** `/health`

检查服务健康状态

**响应**:
```json
{
  "status": "OK"
}
```

### 1.2 就绪检查

**GET** `/ready`

检查服务是否就绪

**响应**:
```json
{
  "status": "Ready"
}
```

### 1.3 系统信息

**GET** `/admin/system/info`

获取系统信息

**响应**:
```json
{
  "success": true,
  "data": {
    "version": "v1.0.0",
    "kubernetes_version": "v1.20.0",
    "helm_version": "v3.12.0"
  }
}
```

## 2. 应用管理 (Rancher 兼容 API)

### 2.1 安装应用

**POST** `/v3/projects/{projectId}/app`

安装 Helm 应用

**路径参数**:
- `projectId`: 项目 ID（格式：`clusterId:projectId` 或 `projectId`）

**请求体**:
```json
{
  "name": "podinfo",                    // 应用名称（必需）
  "projectId": "test-ns",               // 项目 ID（必需）
  "targetNamespace": "podinfo-ns",      // 目标命名空间（必需）
  "externalId": "catalog://?catalog=myrepo&template=podinfo&version=6.5.4", // 外部 ID（必需）
  "type": "app",                        // 类型（必需）
  "prune": false,                       // 是否清理
  "timeout": 300,                       // 超时时间（秒）
  "wait": false,                        // 是否等待完成
  "answers": {                          // 应用配置参数
    "service.nodePort": "31130",
    "path": "/podinfo",
    "image.pullPolicy": "Always",
    "adminPassword": "JRyyds@2025>>",
    "dm.dmRootPassword": "JRyyds@2025>>"
  },
  "valuesYaml": ""                      // 自定义 YAML 配置
}
```

**响应**:
```json
{
  "success": true,
  "data": {
    "id": "test-ns:podinfo",
    "baseType": "app",
    "type": "app",
    "name": "podinfo",
    "state": "installing",
    "targetNamespace": "podinfo-ns",
    "externalId": "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
    "projectId": "test-ns",
    "created": "2025-12-12T17:00:00Z",
    "transitioning": "yes",
    "transitioningMessage": "Installing application asynchronously",
    "actionLinks": {
      "rollback": "/v3/project/test-ns/apps/test-ns:podinfo?action=rollback",
      "upgrade": "/v3/project/test-ns/apps/test-ns:podinfo?action=upgrade"
    }
  }
}
```

### 2.2 查询应用状态

**GET** `/v3/projects/{projectId}/app/{name}?targetNamespace={namespace}`

查询应用状态

**路径参数**:
- `projectId`: 项目 ID
- `name`: 应用名称

**查询参数**:
- `targetNamespace`: 目标命名空间（必需）

**响应**:
```json
{
  "success": true,
  "data": {
    "id": "test-ns:podinfo",
    "baseType": "app",
    "type": "app",
    "name": "podinfo",
    "state": "active",
    "targetNamespace": "podinfo-ns",
    "externalId": "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
    "projectId": "test-ns",
    "created": "2025-12-12T17:00:00Z",
    "transitioning": "no",
    "actionLinks": {
      "rollback": "/v3/project/test-ns/apps/test-ns:podinfo?action=rollback",
      "upgrade": "/v3/project/test-ns/apps/test-ns:podinfo?action=upgrade"
    }
  }
}
```

### 2.3 列出应用

**GET** `/v3/projects/{projectId}/app`

列出项目下的所有应用

**路径参数**:
- `projectId`: 项目 ID

**响应**:
```json
{
  "success": true,
  "data": [
    {
      "id": "test-ns:podinfo",
      "name": "podinfo",
      "state": "active",
      "targetNamespace": "podinfo-ns"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 10,
    "total": 1,
    "total_page": 1
  }
}
```

### 2.4 升级应用

**POST** `/v3/projects/{projectId}/app/{name}?action=upgrade`

升级应用

**路径参数**:
- `projectId`: 项目 ID
- `name`: 应用名称

**请求体**:
```json
{
  "answers": {
    "image.tag": "6.5.5"
  },
  "externalId": "catalog://?catalog=myrepo&template=podinfo&version=6.5.5"
}
```

### 2.5 回滚应用

**POST** `/v3/projects/{projectId}/app/{name}?action=rollback`

回滚应用

**路径参数**:
- `projectId`: 项目 ID
- `name`: 应用名称

### 2.6 删除应用

**DELETE** `/v3/projects/{projectId}/app/{name}`

删除应用

**路径参数**:
- `projectId`: 项目 ID
- `name`: 应用名称

**查询参数**:
- `targetNamespace`: 目标命名空间（可选）

## 3. 应用管理 (生产 API)

### 3.1 安装应用 (V1)

**POST** `/v1/apps`

使用 V1 API 安装应用

**请求体**:
```json
{
  "name": "podinfo",
  "namespace": "podinfo-ns",
  "chart": "myrepo/podinfo",
  "version": "6.5.4",
  "values": {
    "service": {
      "type": "ClusterIP",
      "nodePort": 31130
    }
  }
}
```

### 3.2 查询应用详情 (V1)

**GET** `/v1/apps/{name}?namespace={namespace}`

查询 V1 应用详情

### 3.3 列出应用 (V1)

**GET** `/v1/apps?namespace={namespace}`

列出 V1 应用

### 3.4 更新应用 (V1)

**PUT** `/v1/apps/{name}`

更新 V1 应用

### 3.5 删除应用 (V1)

**DELETE** `/v1/apps/{name}?namespace={namespace}`

删除 V1 应用

### 3.6 应用操作

**POST** `/v1/apps/{name}/actions/{action}`

对应用执行操作

**支持的 action**:
- `upgrade`: 升级
- `rollback`: 回滚
- `restart`: 重启
- `pause`: 暂停
- `resume`: 恢复

## 4. 仓库管理

### 4.1 列出仓库

**GET** `/v1/repos`

列出所有 Helm 仓库

**响应**:
```json
{
  "success": true,
  "data": [
    {
      "name": "myrepo",
      "url": "http://172.30.1.13:18091/repository/helm",
      "status": "active",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### 4.2 添加仓库

**POST** `/v1/repos`

添加 Helm 仓库

**请求体**:
```json
{
  "name": "myrepo",
  "url": "http://repo-url",
  "username": "admin",
  "password": "password"
}
```

### 4.3 更新仓库

**PUT** `/v1/repos/{name}`

更新仓库配置

### 4.4 删除仓库

**DELETE** `/v1/repos/{name}`

删除仓库

### 4.5 刷新仓库

**POST** `/v1/repos/{name}/refresh`

刷新仓库索引

## 5. 监控与指标

### 5.1 应用指标

**GET** `/v1/monitor/apps/{name}/metrics?namespace={namespace}`

获取应用指标

**响应**:
```json
{
  "success": true,
  "data": {
    "cpu_usage": "100m",
    "memory_usage": "128Mi",
    "replicas": 1,
    "ready_replicas": 1
  }
}
```

### 5.2 系统指标

**GET** `/v1/monitor/system`

获取系统指标

### 5.3 健康状态

**GET** `/v1/monitor/health`

获取系统健康状态

## 6. 管理员接口

### 6.1 获取配置

**GET** `/admin/config`

获取当前配置（不包含敏感信息）

### 6.2 更新配置

**PUT** `/admin/config`

更新配置

### 6.3 用户管理

**GET** `/admin/users` - 列出用户
**GET** `/admin/users/{id}` - 获取用户详情
**POST** `/admin/users` - 创建用户
**PUT** `/admin/users/{id}` - 更新用户
**DELETE** `/admin/users/{id}` - 删除用户

### 6.4 系统日志

**GET** `/admin/system/logs`

获取系统日志

### 6.5 重启系统

**POST** `/admin/system/restart`

重启服务

## 错误码说明

| 错误码 | HTTP状态码 | 描述 |
|--------|------------|------|
| `not_found` | 404 | 资源不存在 |
| `bad_request` | 400 | 请求参数错误 |
| `unauthorized` | 401 | 未认证 |
| `forbidden` | 403 | 权限不足 |
| `internal_server_error` | 500 | 内部服务器错误 |
| `validation_failed` | 400 | 验证失败 |
| `deployment_failed` | 500 | 部署失败 |

## 状态码说明

| 状态 | 描述 |
|------|------|
| `installing` | 安装中 |
| `active` | 运行正常 |
| `upgrading` | 升级中 |
| `removing` | 删除中 |
| `removed` | 已删除 |
| `error` | 错误状态 |

## 使用示例

### 示例 1: 安装 podinfo 应用

```bash
curl -X POST http://localhost:8443/v3/projects/test-ns/app \
  -H "Content-Type: application/json" \
  -d '{
    "name": "podinfo",
    "projectId": "test-ns",
    "targetNamespace": "podinfo-ns",
    "externalId": "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
    "type": "app",
    "answers": {
      "service.nodePort": "31130",
      "path": "/podinfo"
    }
  }'
```

### 示例 2: 查询应用状态

```bash
curl "http://localhost:8443/v3/projects/test-ns/app/podinfo?targetNamespace=podinfo-ns"
```

### 示例 3: 升级应用

```bash
curl -X POST "http://localhost:8443/v3/projects/test-ns/app/podinfo?action=upgrade" \
  -H "Content-Type: application/json" \
  -d '{
    "answers": {
      "image.tag": "6.5.5"
    }
  }'
```

## 注意事项

1. **状态准确性**: 当前版本的状态查询基于 Helm Release 状态，不检查 Pod 实际运行状态
2. **异步操作**: 大部分部署操作是异步的，需要轮询状态接口确认结果
3. **权限要求**: 确保 ServiceAccount 有足够的 Kubernetes 权限
4. **仓库认证**: 私有仓库需要配置正确的用户名和密码
5. **镜像拉取**: 私有镜像仓库需要配置 imagePullSecrets

## 版本兼容性

- API v3: Rancher 兼容格式
- API v1: 简化格式
- 建议使用 API v3 以获得完整功能

## 限制

- 单次部署超时时间默认 300 秒
- 最大并发部署数量受 Kubernetes 集群限制
- 状态查询频率建议不超过每秒 10 次