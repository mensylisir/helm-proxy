# Helm Proxy

**Rancher 到原生 Kubernetes 迁移网关**

支持 Rancher 2.5.7 API，完全兼容 myrepo 仓库和 podinfo 应用。

## ✨ 特性

- ✅ **100% Rancher API 兼容** - 无需修改客户端代码
- ✅ **原生 Kubernetes 支持** - 基于 Helm 3
- ✅ **myrepo 仓库支持** - 内部仓库完美支持
- ✅ **离线环境** - 无需公网访问
- ✅ **生产级** - 高可用、安全、监控、备份

## 🚀 快速开始

### 前提条件

- Kubernetes 1.20+ 集群
- kubectl 已配置
- 内部镜像仓库可访问：`registry.dev.rdev.tech:18091`

### 第一步：生成 JWT 密钥

```bash
openssl rand -base64 32
```

**复制输出的密钥**，例如：`qI1ovofr7dPaAsWZc93V8AxthAa2P1WyJ20lr9vkLFo=`

### 第二步：设置用户名和密码

编辑文件：`deploy/k8s/deploy-production-offline.yaml`

找到第 41-43 行的 Secret 部分：

```yaml
stringData:
  jwt-secret: "CHANGE_ME_TO_256_BIT_SECRET_KEY_IN_PRODUCTION_OFFLINE"  # 替换为生成的密钥
  helm-username: "admin"           # Helm 仓库用户名（可选）
  helm-password: "Def@u1tpwd"      # Helm 仓库密码（可选）
```

修改为：

```yaml
stringData:
  jwt-secret: "qI1ovofr7dPaAsWZc93V8AxthAa2P1WyJ20lr9vkLFo="  # 你的 JWT 密钥
  helm-username: "admin"           # 你的用户名
  helm-password: "Def@u1tpwd"      # 你的密码
```

**如果使用无密码仓库**，可以删除或不设置 `helm-username` 和 `helm-password` 字段。

### 第三步：自动部署

```bash
cd deploy
./scripts/deploy-offline.sh deploy
./scripts/deploy-offline.sh status
```

### 第四步：验证部署

```bash
# 查看 Pod 状态
kubectl get pods -n helm-proxy-system -l app=helm-proxy

# 测试健康检查
kubectl exec -n helm-proxy-system deployment/helm-proxy -- curl -s http://localhost:8443/v1/monitor/health
```

### 第五步：测试 Rancher API

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

**预期响应**：
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

### 手动部署（替代方案）

如果需要了解部署原理，可以手动执行：

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

### 清理部署

```bash
cd deploy
./scripts/deploy-offline.sh cleanup
```

## 📚 文档

- **[部署指南](deploy/docs/DEPLOYMENT-GUIDE.md)** - 详细部署说明（包含手动和自动）
- **[快速参考](deploy/docs/QUICK-REFERENCE.md)** - 常用命令速查

## 📁 目录结构

```
helm-proxy/
├── core/                  # 核心代码
├── config/                # 配置管理
├── model/                 # 数据结构
├── routes/                # API 路由
├── main.go                # 主程序
├── deploy/                # 部署文件
│   ├── k8s/              # Kubernetes 资源
│   │   ├── deploy-production-offline.yaml  # 离线部署
│   │   ├── monitoring.yaml                # 监控
│   │   └── grafana-dashboard.yaml         # 仪表板
│   ├── scripts/          # 部署脚本
│   │   ├── deploy-offline.sh     # 离线部署
│   │   ├── backup-restore.sh     # 备份恢复
│   │   ├── performance-test.sh   # 性能测试
│   │   └── security-scan.sh      # 安全扫描
│   └── docs/             # 文档
│       ├── DEPLOYMENT-GUIDE.md   # 部署指南
│       └── QUICK-REFERENCE.md    # 快速参考
└── .github/workflows/    # CI/CD
    ├── ci-cd-offline.yml  # 离线 CI/CD
    ├── backup.yml         # 自动化备份
    ├── security.yml       # 安全扫描
    └── performance.yml    # 性能测试
```

## 🏗️ 架构

```
[客户端] → [helm-proxy] → [Helm 3] → [Kubernetes]
          ↓
    Rancher API 兼容
          ↓
    myrepo 仓库支持
          ↓
    离线环境适配
```

## ⚙️ 配置

### 环境变量

```bash
export HELM_REPOS="myrepo=http://registry.dev.rdev.tech:18091/repository/helm"
export HELM_USERNAME=admin
export HELM_PASSWORD=Def@u1tpwd
export JWT_SECRET="your-jwt-secret"
```

### 关键文件

- **部署**：`deploy/k8s/deploy-production-offline.yaml`
- **配置**：`deploy/configs/config-production-offline.yaml`
- **镜像**：`registry.dev.rdev.tech:18091/helm-proxy:latest`

## 🧪 测试

### 健康检查

```bash
curl http://localhost:18091/v1/monitor/health
```

### 仓库列表

```bash
curl -s http://localhost:18091/v1/repos
```

### 性能测试

```bash
./deploy/scripts/performance-test.sh full
```

### 安全扫描

```bash
./deploy/scripts/security-scan.sh full
```

## 🔧 常用操作

### 查看状态

```bash
kubectl get all -n helm-proxy-system -l app=helm-proxy
kubectl get hpa -n helm-proxy-system
kubectl get pdb -n helm-proxy-system
```

### 查看日志

```bash
kubectl logs -f deployment/helm-proxy -n helm-proxy-system
```

### 更新镜像

```bash
kubectl set image deployment/helm-proxy helm-proxy=registry.dev.rdev.tech:18091/helm-proxy:v1.0.0 -n helm-proxy-system
kubectl rollout restart deployment/helm-proxy -n helm-proxy-system
```

### 扩容

```bash
kubectl scale deployment helm-proxy --replicas=5 -n helm-proxy-system
```

### 清理

```bash
./deploy/scripts/deploy-offline.sh cleanup
```

## 🔒 安全

- JWT 认证
- API Key 认证
- RBAC 权限控制
- 限流保护
- TLS 加密

## 📊 监控

- Prometheus 指标
- Grafana 仪表板
- 告警规则
- 健康检查

## 📦 备份

```bash
./deploy/scripts/backup-restore.sh backup --namespace helm-proxy-system
./deploy/scripts/backup-restore.sh list
./deploy/scripts/backup-restore.sh restore <backup-file>
```

## 🚨 故障排除

查看文档：[部署指南 - 常见问题](deploy/docs/DEPLOYMENT-GUIDE.md#常见问题)

## 📄 许可证

MIT

## 🤝 支持

- 文档：[部署指南](deploy/docs/DEPLOYMENT-GUIDE.md)
- 快速参考：[QUICK-REFERENCE.md](deploy/docs/QUICK-REFERENCE.md)

---

**版本**：v1.0.0-production-offline
