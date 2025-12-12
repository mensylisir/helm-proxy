# Helm Proxy 使用手册

## 概述

Helm Proxy 是一个基于 Helm 3 的 Kubernetes 应用部署代理服务，提供 RESTful API 接口，支持 Rancher 兼容的 API 格式。

## 功能特性

- ✅ 支持 Helm 3 完整功能
- ✅ Rancher 兼容 API
- ✅ 私有 Helm 仓库支持
- ✅ 镜像仓库认证
- ✅ 异步部署
- ✅ 完整的部署状态追踪
- ✅ Kubernetes 原生部署

## 快速开始

### 1. 环境准备

确保 Kubernetes 集群可访问，并配置 kubeconfig：

```bash
export KUBECONFIG=~/.kube/config
```

### 2. 启动服务

#### 直接运行（开发/测试）

```bash
export KUBECONFIG=~/.kube/config
export HELM_USERNAME="your-username"
export HELM_PASSWORD="your-password"
export HELM_REPOS="myrepo=http://your-helm-repo-url"
./helm-proxy -port 8443 -log-level info &
```

#### Kubernetes 部署

```bash
# 构建镜像
docker build -t helm-proxy:latest .

# 部署到集群
kubectl apply -f deploy.yaml
```

### 3. 验证安装

```bash
curl http://localhost:8443/health
# 返回: {"status":"OK"}
```

## 配置说明

### 环境变量

| 变量名 | 必需 | 描述 | 示例 |
|--------|------|------|------|
| `KUBECONFIG` | 是 | Kubernetes 配置文件路径 | `~/.kube/config` |
| `HELM_REPOS` | 是 | Helm 仓库配置 | `myrepo=http://repo-url,bitnami=https://charts.bitnami.com/bitnami` |
| `HELM_USERNAME` | 否 | 私有仓库用户名 | `admin` |
| `HELM_PASSWORD` | 否 | 私有仓库密码 | `password123` |
| `HELM_DRIVER` | 否 | Helm 存储驱动 | `secret` (默认) |
| `PORT` | 否 | 服务端口 | `8443` (默认) |
| `LOG_LEVEL` | 否 | 日志级别 | `info` |

### Helm 仓库配置

#### 私有仓库

```bash
export HELM_REPOS="myrepo=http://172.30.1.13:18091/repository/helm"
export HELM_USERNAME="admin"
export HELM_PASSWORD="Def@u1tpwd"
```

#### 公共仓库

```bash
export HELM_REPOS="bitnami=https://charts.bitnami.com/bitnami,stable=https://charts.helm.sh/stable"
```

#### 多仓库配置

```bash
export HELM_REPOS="myrepo=http://repo1-url,bitnami=http://repo2-url,stable=https://charts.helm.sh/stable"
```

## 核心概念

### 项目 ID (Project ID)

格式：`clusterId:projectId` 或 `projectId`

```bash
# 完整格式
c-7k5bm:p-lkjnx

# 简化格式
test-ns
```

### 外部 ID (External ID)

格式：`catalog://?catalog={仓库名}&template={应用名}&version={版本}`

```bash
# 示例
catalog://?catalog=myrepo&template=podinfo&version=6.5.4
```

### 命名空间 (Namespace)

目标部署的 Kubernetes 命名空间

```bash
# 示例
podinfo-ns
```

## 常用操作

### 1. 安装应用

```bash
curl -X POST http://localhost:8443/v3/projects/test-ns/app \
  -H "Content-Type: application/json" \
  -d '{
    "prune": false,
    "timeout": 300,
    "wait": false,
    "type": "app",
    "name": "podinfo",
    "answers": {
      "service.nodePort": "31130",
      "path": "/podinfo",
      "image.pullPolicy": "Always"
    },
    "targetNamespace": "podinfo-ns",
    "externalId": "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
    "projectId": "test-ns",
    "valuesYaml": ""
  }'
```

### 2. 查询应用状态

```bash
curl "http://localhost:8443/v3/projects/test-ns/app/podinfo?targetNamespace=podinfo-ns"
```

### 3. 升级应用

```bash
curl -X POST "http://localhost:8443/v3/projects/test-ns/app/podinfo?action=upgrade" \
  -H "Content-Type: application/json" \
  -d '{
    "answers": {
      "image.tag": "6.5.5"
    },
    "externalId": "catalog://?catalog=myrepo&template=podinfo&version=6.5.5"
  }'
```

### 4. 删除应用

```bash
curl -X DELETE "http://localhost:8443/v3/projects/test-ns/app/podinfo"
```

## 状态说明

### 应用状态

| 状态 | 描述 |
|------|------|
| `installing` | 安装中 |
| `active` | 运行正常 |
| `upgrading` | 升级中 |
| `failed` | 失败 |
| `removing` | 删除中 |
| `removed` | 已删除 |

### 重要说明

**状态准确性警告**：

当前版本的状态查询基于 Helm Release 状态，不检查 Pod 实际运行状态。

- `active` 状态表示 Helm Release 部署成功，但不保证 Pod 正常运行
- Pod 可能处于 `ImagePullBackOff`、`CrashLoopBackOff` 等状态
- 建议结合 `kubectl` 命令查询 Pod 状态

```bash
kubectl get pods -n <namespace>
```

## 故障排除

### 1. 镜像拉取失败

**错误**：`ImagePullBackOff`

**原因**：
- 私有镜像仓库未配置认证
- 镜像地址错误
- 网络访问限制

**解决**：

1. 检查镜像地址是否正确
2. 配置 imagePullSecrets
3. 使用公共镜像

### 2. Helm 仓库访问失败

**错误**：`401 Unauthorized`

**解决**：

```bash
export HELM_USERNAME="正确用户名"
export HELM_PASSWORD="正确密码"
```

### 3. Kubernetes 连接失败

**错误**：`failed to get action config`

**解决**：

```bash
# 检查 kubeconfig
kubectl config view

# 设置环境变量
export KUBECONFIG=~/.kube/config
```

### 4. 权限不足

**错误**：`error: You must be logged in to the server`

**解决**：

确保 ServiceAccount 有足够权限：

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: helm-proxy-admin-binding
roleRef:
  kind: ClusterRole
  name: cluster-admin
```

## 最佳实践

### 1. 环境隔离

- 开发环境：使用独立命名空间
- 生产环境：严格权限控制

### 2. 仓库管理

- 定期更新仓库索引
- 使用版本锁定
- 私有仓库配置认证

### 3. 监控

- 监控应用部署状态
- 定期检查 Pod 运行状态
- 设置告警

### 4. 安全

- 不要在代码中硬编码密码
- 使用 Secret 管理敏感信息
- 限制 ServiceAccount 权限

## API 参考

详细 API 文档请参考：[API_MANUAL.md](./API_MANUAL.md)

## 版本信息

- 当前版本：v1.0.0
- Helm 版本：3.x
- Kubernetes 版本：1.20+

## 技术支持

如遇问题，请检查：
1. 服务日志：`kubectl logs -l app=helm-proxy`
2. 集群状态：`kubectl get nodes`
3. 权限配置：`kubectl auth can-i --list`

## 更新日志

### v1.0.0
- 初始版本发布
- 支持基本 Helm 操作
- Rancher 兼容 API
- 私有仓库支持