#!/bin/bash
# 离线环境部署脚本 - Helm Proxy
# 专用于离线环境，仅使用内部资源

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 配置
NAMESPACE="helm-proxy-system"
IMAGE_TAG="latest"
INTERNAL_REGISTRY="registry.dev.rdev.tech:18091"

# 函数：打印信息
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查前置条件
check_prerequisites() {
    print_info "检查前置条件（离线环境）..."

    # 检查 kubectl
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl 未安装"
        exit 1
    fi

    # 检查集群连接
    if ! kubectl cluster-info &> /dev/null; then
        print_error "无法连接到 Kubernetes 集群"
        exit 1
    fi

    # 检查内部镜像仓库可访问性
    print_info "检查内部镜像仓库..."
    if ! curl -s -f "$INTERNAL_REGISTRY/v2/" > /dev/null; then
        print_warn "内部镜像仓库不可访问: $INTERNAL_REGISTRY"
    fi

    print_info "前置条件检查完成"
}

# 创建命名空间
create_namespace() {
    print_info "创建命名空间 $NAMESPACE..."
    kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
    print_info "命名空间创建完成"
}

# 部署应用（离线模式）
deploy_application() {
    print_info "部署 Helm Proxy 到离线生产环境..."

    # 使用离线专用配置
    kubectl apply -f ../k8s/deploy-production-offline.yaml

    print_info "部署完成"
}

# 等待部署就绪
wait_for_deployment() {
    print_info "等待部署就绪..."

    kubectl rollout status deployment/helm-proxy -n $NAMESPACE --timeout=600s

    print_info "部署就绪"
}

# 验证部署
verify_deployment() {
    print_info "验证部署状态（离线模式）..."

    # 检查 Pod 状态
    if ! kubectl get pods -n $NAMESPACE -l app=helm-proxy | grep -q Running; then
        print_error "Pod 未处于 Running 状态"
        kubectl get pods -n $NAMESPACE -l app=helm-proxy
        exit 1
    fi

    # 检查服务
    if ! kubectl get svc -n $NAMESPACE helm-proxy &> /dev/null; then
        print_error "Service 未创建"
        exit 1
    fi

    # 检查健康检查端点
    print_info "检查健康检查端点..."
    sleep 10
    for i in {1..3}; do
        if kubectl exec -n $NAMESPACE deployment/helm-proxy -- curl -k -s https://localhost:8443/v1/monitor/health > /dev/null; then
            print_info "健康检查通过"
            break
        else
            if [ $i -eq 3 ]; then
                print_error "健康检查失败"
                exit 1
            fi
            print_warn "健康检查失败，重试中... ($i/3)"
            sleep 10
        fi
    done

    # 验证内部仓库配置
    print_info "验证内部仓库配置..."
    kubectl exec -n $NAMESPACE deployment/helm-proxy -- helm repo list | grep -q "myrepo.*registry.dev.rdev.tech" || print_warn "内部仓库配置可能有问题"

    print_info "部署验证完成（离线模式）"
}

# 显示部署信息
show_deployment_info() {
    print_info "部署信息（离线环境）："
    echo ""
    kubectl get all -n $NAMESPACE -l app=helm-proxy
    echo ""
    print_info "服务地址："
    kubectl get svc -n $NAMESPACE helm-proxy -o wide
    echo ""
    print_info "内部镜像仓库：$INTERNAL_REGISTRY"
    print_info "Helm 仓库："
    kubectl exec -n $NAMESPACE deployment/helm-proxy -- helm repo list
    echo ""
    print_info "查看日志："
    echo "kubectl logs -f deployment/helm-proxy -n $NAMESPACE"
    echo ""
    print_info "进入 Pod："
    echo "kubectl exec -it deployment/helm-proxy -n $NAMESPACE -- /bin/sh"
}

# 清理函数
cleanup() {
    print_warn "清理离线部署..."
    kubectl delete -f ../k8s/deploy-production-offline.yaml --ignore-not-found=true
    kubectl delete namespace $NAMESPACE --ignore-not-found=true
    print_info "清理完成"
}

# 主函数
main() {
    case "${1:-deploy}" in
        deploy)
            print_info "开始部署 Helm Proxy 到离线生产环境..."
            check_prerequisites
            create_namespace
            deploy_application
            wait_for_deployment
            verify_deployment
            show_deployment_info
            print_info "离线环境部署成功！"
            ;;
        cleanup)
            cleanup
            ;;
        status)
            kubectl get all -n $NAMESPACE -l app=helm-proxy
            ;;
        logs)
            kubectl logs -f deployment/helm-proxy -n $NAMESPACE
            ;;
        *)
            echo "用法: $0 {deploy|cleanup|status|logs}"
            echo "  deploy  - 部署到离线生产环境（默认）"
            echo "  cleanup - 清理部署"
            echo "  status  - 查看部署状态"
            echo "  logs    - 查看日志"
            exit 1
            ;;
    esac
}

main "$@"
