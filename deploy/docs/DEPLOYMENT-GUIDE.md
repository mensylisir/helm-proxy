# 🚀 部署指南

## 📋 目录

- [自动部署](#自动部署)
- [手动部署](#手动部署)
- [验证部署](#验证部署)
- [常见问题](#常见问题)

---

## 自动部署（推荐）

### 前提条件

确保已经：
1. 生成 JWT 密钥：`openssl rand -base64 32`
2. 修改了 `deploy/k8s/deploy-production-offline.yaml` 中的凭据（第 41-43 行）

### 部署步骤

**第一步：进入部署目录**
```bash
cd deploy
```

**第二步：执行部署**
```bash
./scripts/deploy-offline.sh deploy
```

**第三步：查看部署状态**
```bash
./scripts/deploy-offline.sh status
```

**第四步：查看日志（如果需要）**
```bash
./scripts/deploy-offline.sh logs
```

### 脚本详细说明

脚本 `deploy-offline.sh` 会自动执行以下操作：

1. **检查前置条件**
   - 检查 kubectl 是否安装
   - 检查是否连接到 Kubernetes 集群
   - 检查内部镜像仓库可访问性

2. **创建命名空间**
   - 创建 `helm-proxy-system` 命名空间

3. **部署应用**
   - 应用 `deploy/k8s/deploy-production-offline.yaml` 文件中的所有资源：
     - Secret（凭据）
     - ConfigMap（配置）
     - ServiceAccount（权限）
     - ClusterRoleBinding（RBAC）
     - Deployment（应用）
     - Service（服务）
     - HPA（自动扩缩容）
     - PodDisruptionBudget（最小可用实例）

4. **等待部署完成**
   - 等待 Deployment 就绪（超时时间：600 秒）

5. **验证部署**
   - 检查 Pod 状态
   - 检查 Service
   - 检查健康检查端点
   - 验证内部仓库配置

6. **显示部署信息**
   - 显示所有资源状态
   - 显示服务地址
   - 显示查看日志命令
   - 显示进入 Pod 命令

### 脚本支持的命令

```bash
# 部署到离线生产环境（默认）
./scripts/deploy-offline.sh deploy

# 清理部署
./scripts/deploy-offline.sh cleanup

# 查看部署状态
./scripts/deploy-offline.sh status

# 查看日志
./scripts/deploy-offline.sh logs

# 查看帮助
./scripts/deploy-offline.sh help
```

### 预期输出

部署成功时，应该看到类似输出：

```
[INFO] 开始部署 Helm Proxy 到离线生产环境...
[INFO] 检查前置条件（离线环境）...
[INFO] 前置条件检查完成
[INFO] 创建命名空间 helm-proxy-system...
[INFO] 命名空间创建完成
[INFO] 部署 Helm Proxy 到离线生产环境...
[INFO] 部署完成
[INFO] 等待部署就绪...
deployment "helm-proxy" successfully rolled out
[INFO] 部署就绪
[INFO] 验证部署状态（离线模式）...
[INFO] 健康检查通过
[INFO] 部署验证完成（离线模式）
[INFO] 部署信息（离线环境）：

[INFO] 服务地址：
NAME           TYPE        CLUSTER-IP      PORT(S)    AGE
helm-proxy     ClusterIP   10.233.x.x      8443/TCP   30s

[INFO] 查看日志：
kubectl logs -f deployment/helm-proxy -n helm-proxy-system

[INFO] 进入 Pod：
kubectl exec -it deployment/helm-proxy -n helm-proxy-system -- /bin/sh

[INFO] 离线环境部署成功！
```

### 如果部署失败

如果看到错误信息，请参考 [常见问题](#常见问题) 章节。

---

## 手动部署（了解原理）

### 步骤 1：生成 JWT 密钥

```bash
openssl rand -base64 32
```

**示例输出**：
```
qI1ovofr7dPaAsWZc93V8AxthAa2P1WyJ20lr9vkLFo=
```

### 步骤 2：创建命名空间

```bash
kubectl create namespace helm-proxy-system
```

**作用**：独立命名空间，便于管理

### 步骤 3：设置用户名和密码

#### 文件位置
文件路径：`deploy/k8s/deploy-production-offline.yaml`

#### 找到配置位置
打开文件后，找到第 32-43 行，内容如下：

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: helm-proxy-credentials
  namespace: helm-proxy-system
  labels:
    app: helm-proxy
type: Opaque
stringData:
  jwt-secret: "CHANGE_ME_TO_256_BIT_SECRET_KEY_IN_PRODUCTION_OFFLINE"
  helm-username: "admin"
  helm-password: "Def@u1tpwd"
```

#### 修改步骤

**第一步：生成 JWT 密钥**
```bash
openssl rand -base64 32
```
复制输出的密钥（例如：`qI1ovofr7dPaAsWZc93V8AxthAa2P1WyJ20lr9vkLFo=`）

**第二步：修改文件**
编辑第 41-43 行，修改为：

```yaml
stringData:
  jwt-secret: "qI1ovofr7dPaAsWZc93V8AxthAa2P1WyJ20lr9vkLFo="  # 替换为你的 JWT 密钥
  helm-username: "admin"           # 替换为你的用户名
  helm-password: "Def@u1tpwd"      # 替换为你的密码
```

#### 字段说明

| 字段名 | 是否必填 | 说明 | 示例 |
|--------|---------|------|------|
| `jwt-secret` | ✅ 必填 | JWT 认证密钥，用于 API 认证 | `openssl rand -base64 32` 生成 |
| `helm-username` | ❌ 可选 | Helm 仓库用户名（如果仓库需要认证） | `admin` |
| `helm-password` | ❌ 可选 | Helm 仓库密码（如果仓库需要认证） | `your-password` |

#### 使用无密码仓库

如果你的 myrepo 仓库不需要认证，可以这样设置：

```yaml
stringData:
  jwt-secret: "qI1ovofr7dPaAsWZc93V8AxthAa2P1WyJ20lr9vkLFo="
  # 不设置 helm-username 和 helm-password
```

或设置为空字符串：

```yaml
stringData:
  jwt-secret: "qI1ovofr7dPaAsWZc93V8AxthAa2P1WyJ20lr9vkLFo="
  helm-username: ""
  helm-password: ""
```

#### 修改后验证

修改完成后，保存文件。然后执行：

```bash
# 应用配置（包含 Secret）
kubectl apply -f deploy/k8s/deploy-production-offline.yaml -n helm-proxy-system

# 验证 Secret 是否创建成功
kubectl get secret helm-proxy-credentials -n helm-proxy-system -o yaml
```

应该看到类似输出：
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: helm-proxy-credentials
  namespace: helm-proxy-system
type: Opaque
data:
  jwt-secret: cUgxdm92ZmI3ZFBhQXNXWmM5M1Y4QXh0aEFhMlAxV3lKMjBscjl2a0xGbz0=
  helm-username: YWRtaW4=
  helm-password: RGVmQHVxMHRwZA==
```

注意：`data` 字段中的值是 base64 编码后的，这是正常的 Kubernetes Secret 格式。

### 步骤 4：创建 ConfigMap（配置）

在同一个文件中，找到 ConfigMap 部分：

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: helm-proxy-config
  namespace: helm-proxy-system
data:
  config.yaml: |
    server:
      port: "8443"

    helm:
      repos:
        myrepo: "http://registry.dev.rdev.tech:18091/repository/helm"

    security:
      auth:
        enabled: true
        jwtSecret: "CHANGE_ME_TO_256_BIT_SECRET_KEY_IN_PRODUCTION_OFFLINE"
        apiKeyEnabled: true
      rateLimit:
        enabled: true
        rate: 200
        burst: 400
```

**注意**：实际运行时会从 Secret 读取真实值，此处仅为配置示例

**应用 ConfigMap**：
```bash
kubectl apply -f deploy/k8s/deploy-production-offline.yaml -n helm-proxy-system
```

### 步骤 5：创建 ServiceAccount（权限）

找到 ServiceAccount 部分：

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: helm-proxy-sa
  namespace: helm-proxy-system
```

**应用 ServiceAccount**：
```bash
kubectl apply -f deploy/k8s/deploy-production-offline.yaml -n helm-proxy-system
```

### 步骤 6：创建 RBAC（权限控制）

找到 ClusterRoleBinding 部分：

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: helm-proxy-admin-binding
subjects:
- kind: ServiceAccount
  name: helm-proxy-sa
  namespace: helm-proxy-system
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

**作用**：给 helm-proxy-sa 授予 cluster-admin 权限，以便管理应用

**应用 RBAC**：
```bash
kubectl apply -f deploy/k8s/deploy-production-offline.yaml -n helm-proxy-system
```

### 步骤 7：创建 Deployment（应用）

找到 Deployment 部分：

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: helm-proxy
  namespace: helm-proxy-system
spec:
  replicas: 3  # ← 3 个副本
  selector:
    matchLabels:
      app: helm-proxy
  template:
    metadata:
      labels:
        app: helm-proxy
    spec:
      serviceAccountName: helm-proxy-sa  # ← 使用 ServiceAccount
      containers:
      - name: helm-proxy
        image: registry.dev.rdev.tech:18091/helm-proxy:latest  # ← 镜像地址
        ports:
        - containerPort: 8443
        env:
        # 从 Secret 读取环境变量
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: helm-proxy-credentials
              key: jwt-secret
        - name: HELM_USERNAME
          valueFrom:
            secretKeyRef:
              name: helm-proxy-credentials
              key: helm-username
        - name: HELM_PASSWORD
          valueFrom:
            secretKeyRef:
              name: helm-proxy-credentials
              key: helm-password
        # 从 ConfigMap 读取配置
        - name: CONFIG_FILE
          value: "/config/config.yaml"
        volumeMounts:
        - name: config-volume
          mountPath: /config
        resources:
          requests:
            memory: "1Gi"
            cpu: "1000m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /v1/monitor/health
            port: 8443
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /v1/monitor/health
            port: 8443
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config-volume
        configMap:
          name: helm-proxy-config
```

**应用 Deployment**：
```bash
kubectl apply -f deploy/k8s/deploy-production-offline.yaml -n helm-proxy-system
```

### 步骤 8：创建 Service（服务）

找到 Service 部分：

```yaml
apiVersion: v1
kind: Service
metadata:
  name: helm-proxy
  namespace: helm-proxy-system
spec:
  selector:
    app: helm-proxy  # ← 匹配 Deployment 的 Pod
  ports:
  - name: http
    port: 8443
    targetPort: 8443
    protocol: TCP
  type: ClusterIP  # ← 集群内访问
```

**应用 Service**：
```bash
kubectl apply -f deploy/k8s/deploy-production-offline.yaml -n helm-proxy-system
```

### 步骤 9：等待部署完成

```bash
kubectl rollout status deployment/helm-proxy -n helm-proxy-system --timeout=600s
```

**查看进度**：
```bash
kubectl get pods -n helm-proxy-system -l app=helm-proxy -w
```

### 步骤 10：创建 HPA（自动扩缩容）

找到 HPA 部分：

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: helm-proxy-hpa
  namespace: helm-proxy-system
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: helm-proxy  # ← 关联到 Deployment
  minReplicas: 3  # ← 最小 3 个副本
  maxReplicas: 10  # ← 最大 10 个副本
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70  # ← CPU 使用率超过 70% 时扩容
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80  # ← 内存使用率超过 80% 时扩容
```

**应用 HPA**：
```bash
kubectl apply -f deploy/k8s/deploy-production-offline.yaml -n helm-proxy-system
```

### 步骤 11：创建 PDB（最小可用实例）

找到 PodDisruptionBudget 部分：

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: helm-proxy-pdb
  namespace: helm-proxy-system
spec:
  minAvailable: 2  # ← 维护时至少保留 2 个实例
  selector:
    matchLabels:
      app: helm-proxy
```

**应用 PDB**：
```bash
kubectl apply -f deploy/k8s/deploy-production-offline.yaml -n helm-proxy-system
```

### 完整的手动部署命令

```bash
# 1. 创建命名空间
kubectl create namespace helm-proxy-system

# 2. 应用所有资源
kubectl apply -f deploy/k8s/deploy-production-offline.yaml -n helm-proxy-system

# 3. 等待部署完成
kubectl rollout status deployment/helm-proxy -n helm-proxy-system --timeout=600s

# 4. 查看状态
kubectl get all -n helm-proxy-system -l app=helm-proxy
```

---

## 验证部署

### 查看部署状态

```bash
kubectl get all -n helm-proxy-system -l app=helm-proxy
```

**预期输出**：
```
NAME                             READY   STATUS    RESTARTS   AGE
pod/helm-proxy-xxxxx             1/1     Running   0          30s
pod/helm-proxy-xxxxx             1/1     Running   0          30s
pod/helm-proxy-xxxxx             1/1     Running   0          30s

NAME                 TYPE        CLUSTER-IP     PORT(S)    AGE
service/helm-proxy   ClusterIP   10.233.x.x     8443/TCP   30s

NAME                        READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/helm-proxy   3/3     3            3           30s

NAME                                   DESIRED   CURRENT   READY   AGE
replicaset.apps/helm-proxy-xxxxx       3         3         3       30s
```

### 查看 HPA

```bash
kubectl get hpa -n helm-proxy-system
```

### 查看 PDB

```bash
kubectl get pdb -n helm-proxy-system
```

### 测试健康检查

```bash
kubectl exec -n helm-proxy-system deployment/helm-proxy -- curl -s http://localhost:8443/v1/monitor/health
```

**预期输出**：
```json
{
  "data": {
    "checks": {
      "database": "ok",
      "helm": "ok",
      "redis": "ok"
    },
    "status": "healthy"
  },
  "success": true
}
```

### 测试 Rancher API

```bash
# 获取服务地址
SERVICE_IP=$(kubectl get svc -n helm-proxy-system helm-proxy -o jsonpath='{.spec.clusterIP}')

# 部署应用
curl -X POST http://$SERVICE_IP:8443/v3/projects/default:p-test/app \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-app",
    "answers": {"service.nodePort": "31140"},
    "targetNamespace": "test-namespace",
    "externalId": "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
    "projectId": "default:p-test"
  }'
```

**预期输出**：
```json
{
  "data": {
    "id": "default:p-test:test-app",
    "name": "test-app",
    "state": "installing",
    ...
  },
  "success": true
}
```

### 测试 Helm 仓库

```bash
curl -s http://$SERVICE_IP:8443/v1/repos | jq .
```

**预期输出**：
```json
{
  "data": [
    {
      "name": "myrepo",
      "url": "http://registry.dev.rdev.tech:18091/repository/helm",
      "status": "active"
    }
  ],
  "success": true
}
```

---

## 常见问题

### 问题 1：镜像拉取失败

**现象**：
```
Failed to pull image "registry.dev.rdev.tech:18091/helm-proxy:latest"
```

**解决方案**：
```bash
# 检查镜像仓库
curl -I http://registry.dev.rdev.tech:18091/v2/

# 检查镜像是否存在
curl http://registry.dev.rdev.tech:18091/v2/helm-proxy/tags/list

# 如果镜像不存在，请先构建并推送到内部仓库
```

### 问题 2：Pod 无法启动

**现象**：
```
CrashLoopBackOff
```

**解决方案**：
```bash
# 查看 Pod 状态
kubectl describe pod -n helm-proxy-system <pod-name>

# 查看日志
kubectl logs -n helm-proxy-system <pod-name> --previous

# 检查 Secret 是否正确创建
kubectl get secret -n helm-proxy-system helm-proxy-credentials -o yaml
```

### 问题 3：JWT secret 未设置

**现象**：
```
JWT secret not set
```

**解决方案**：
```bash
# 生成并设置 JWT secret
JWT_SECRET=$(openssl rand -base64 32)
kubectl patch secret helm-proxy-credentials -n helm-proxy-system \
  --type='merge' -p="{\"stringData\":{\"jwt-secret\":\"$JWT_SECRET\"}}"

# 重启 Deployment
kubectl rollout restart deployment/helm-proxy -n helm-proxy-system
```

### 问题 4：Service 不可访问

**现象**：
```
curl: (7) Failed to connect
```

**解决方案**：
```bash
# 检查 Service
kubectl get svc -n helm-proxy-system helm-proxy

# 检查 Endpoints
kubectl get endpoints -n helm-proxy-system helm-proxy

# 进入 Pod 测试
kubectl exec -n helm-proxy-system deployment/helm-proxy -- curl -s http://localhost:8443/v1/monitor/health
```

### 问题 5：Helm 仓库访问失败

**现象**：
```
Error: failed to add repo
```

**解决方案**：
```bash
# 检查凭据
kubectl exec -n helm-proxy-system deployment/helm-proxy -- env | grep HELM_

# 检查仓库地址
kubectl exec -n helm-proxy-system deployment/helm-proxy -- helm repo list

# 手动测试仓库连接
kubectl exec -n helm-proxy-system deployment/helm-proxy -- curl -I http://registry.dev.rdev.tech:18091/repository/helm
```

---

## 清理部署

```bash
# 删除所有资源
kubectl delete -f deploy/k8s/deploy-production-offline.yaml -n helm-proxy-system

# 或使用脚本
cd deploy
./scripts/deploy-offline.sh cleanup
```

---

**文档更新时间**：2025-12-15
