# ⚡ 快速参考

## 🚀 快速部署

```bash
# 自动部署（推荐）
cd deploy
./scripts/deploy-offline.sh deploy
./scripts/deploy-offline.sh status
```

```bash
# 手动部署
kubectl create namespace helm-proxy-system
kubectl apply -f deploy/k8s/deploy-production-offline.yaml -n helm-proxy-system
kubectl rollout status deployment/helm-proxy -n helm-proxy-system --timeout=600s
```

## 🔑 生成 JWT 密钥

```bash
openssl rand -base64 32
```

## 📁 关键文件

```
deploy/
├── k8s/deploy-production-offline.yaml    # 部署文件（包含所有资源）
├── scripts/deploy-offline.sh            # 部署脚本
├── scripts/backup-restore.sh            # 备份脚本
├── scripts/performance-test.sh          # 性能测试
└── scripts/security-scan.sh             # 安全扫描
```

## 🔧 常用命令

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

### 进入 Pod
```bash
kubectl exec -it deployment/helm-proxy -n helm-proxy-system -- /bin/sh
```

### 更新镜像
```bash
kubectl set image deployment/helm-proxy helm-proxy=registry.dev.rdev.tech:18091/helm-proxy:v1.0.0 -n helm-proxy-system
kubectl rollout restart deployment/helm-proxy -n helm-proxy-system
```

### 修改 JWT secret
```bash
JWT_SECRET=$(openssl rand -base64 32)
kubectl patch secret helm-proxy-credentials -n helm-proxy-system \
  --type='merge' -p="{\"stringData\":{\"jwt-secret\":\"$JWT_SECRET\"}}"
kubectl rollout restart deployment/helm-proxy -n helm-proxy-system
```

### 修改 Helm 仓库凭据
```bash
kubectl patch secret helm-proxy-credentials -n helm-proxy-system \
  --type='merge' -p='{"stringData":{"helm-username":"new-username","helm-password":"new-password"}}'
kubectl rollout restart deployment/helm-proxy -n helm-proxy-system
```

### 扩容
```bash
kubectl scale deployment helm-proxy --replicas=5 -n helm-proxy-system
```

### 清理
```bash
./scripts/deploy-offline.sh cleanup
# 或
kubectl delete -f deploy/k8s/deploy-production-offline.yaml -n helm-proxy-system
```

## 🧪 测试 Rancher API

### 部署应用
```bash
curl -X POST http://localhost:18091/v3/projects/default:p-test/app \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-app",
    "answers": {"service.nodePort": "31140"},
    "targetNamespace": "test-namespace",
    "externalId": "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
    "projectId": "default:p-test"
  }'
```

### 查看应用列表
```bash
curl -s http://localhost:18091/v3/projects/default:p-test/app
```

### 删除应用
```bash
curl -X DELETE http://localhost:18091/v1/apps/test-app \
  -H "Content-Type: application/json" \
  -d '{"namespace":"test-namespace"}'
```

## 🔍 健康检查

```bash
curl http://localhost:18091/v1/monitor/health
curl http://localhost:18091/v1/monitor/metrics
curl -s http://localhost:18091/v1/repos
```

## 📦 备份与恢复

```bash
./scripts/backup-restore.sh backup --namespace helm-proxy-system
./scripts/backup-restore.sh list
./scripts/backup-restore.sh restore /backup/helm-proxy/config_20231215_020000.tar.gz
./scripts/backup-restore.sh health
```

## ⚡ 性能测试

```bash
./scripts/performance-test.sh health
./scripts/performance-test.sh api
./scripts/performance-test.sh full
```

## 🔒 安全扫描

```bash
./scripts/security-scan.sh init
./scripts/security-scan.sh rbac
./scripts/security-scan.sh secrets
./scripts/security-scan.sh full
```

## 🌐 监控配置

```bash
kubectl apply -f deploy/k8s/monitoring.yaml
kubectl apply -f deploy/k8s/grafana-dashboard.yaml
kubectl port-forward svc/kube-prometheus-stack-grafana 3000:80 -n monitoring
# 访问 http://localhost:3000
```

## 📋 环境变量

```bash
export HELM_REPOS="myrepo=http://registry.dev.rdev.tech:18091/repository/helm"
export HELM_USERNAME=admin
export HELM_PASSWORD=Def@u1tpwd
export JWT_SECRET="your-jwt-secret"
export MAX_CONCURRENT_DEPLOYS=20
export AUTH_ENABLED=true
export RATE_LIMIT_RATE=200
```

## 🚨 故障排除

### Pod 无法启动
```bash
kubectl describe pod <pod-name> -n helm-proxy-system
kubectl logs <pod-name> -n helm-proxy-system --previous
```

### 镜像拉取失败
```bash
curl -I http://registry.dev.rdev.tech:18091/v2/
docker pull registry.dev.rdev.tech:18091/helm-proxy:latest
```

### Rancher API 不可用
```bash
kubectl get svc -n helm-proxy-system helm-proxy
kubectl get endpoints -n helm-proxy-system helm-proxy
kubectl exec -n helm-proxy-system deployment/helm-proxy -- curl -s http://localhost:8443/v1/monitor/health
```

### 仓库访问失败
```bash
kubectl exec -n helm-proxy-system deployment/helm-proxy -- helm repo list
kubectl exec -n helm-proxy-system deployment/helm-proxy -- helm repo update
```

## 📞 帮助

```bash
./scripts/deploy-offline.sh help
./scripts/backup-restore.sh help
./scripts/performance-test.sh help
./scripts/security-scan.sh help
```

---

**最后更新**：2025-12-15
