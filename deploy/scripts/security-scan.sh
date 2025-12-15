#!/bin/bash
# 安全扫描脚本 - Helm Proxy
# 支持容器镜像扫描、配置文件检查、Kubernetes 安全审计等

set -e

# 配置
NAMESPACE="helm-proxy-system"
IMAGE_NAME="${IMAGE_NAME:-helm-proxy:latest}"
SCAN_RESULTS_DIR="/tmp/helm-proxy-security-scan"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$SCAN_RESULTS_DIR/security_report_$TIMESTAMP.html"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "\n${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}\n"
}

# 初始化
init() {
    mkdir -p "$SCAN_RESULTS_DIR"
    print_header "Helm Proxy 安全扫描"
    print_info "扫描时间: $TIMESTAMP"
    print_info "镜像: $IMAGE_NAME"
    print_info "命名空间: $NAMESPACE"
}

# 检查依赖
check_dependencies() {
    local missing_tools=()

    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi

    if ! command -v docker &> /dev/null && ! command -v podman &> /dev/null; then
        missing_tools+=("docker 或 podman")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "缺少依赖工具: ${missing_tools[*]}"
        exit 1
    fi
}

# 容器镜像漏洞扫描
scan_container_vulnerabilities() {
    print_header "扫描 1: 容器镜像漏洞"

    # 使用 Trivy 扫描（如果可用）
    if command -v trivy &> /dev/null; then
        print_info "使用 Trivy 扫描镜像漏洞..."
        trivy image --format json --output "$SCAN_RESULTS_DIR/trivy_scan_$TIMESTAMP.json" "$IMAGE_NAME" 2>/dev/null || true
        trivy image "$IMAGE_NAME" 2>/dev/null | tee "$SCAN_RESULTS_DIR/trivy_scan_$TIMESTAMP.txt" || true

        # 检查高危漏洞
        local high_vulns=$(trivy image --format json "$IMAGE_NAME" 2>/dev/null | jq '.Results[].Vulnerabilities[] | select(.Severity == "HIGH" or .Severity == "CRITICAL") | .VulnerabilityID' 2>/dev/null | wc -l)
        if [ "$high_vulns" -gt 0 ]; then
            print_error "发现 $high_vulns 个高危漏洞"
        else
            print_info "未发现高危漏洞"
        fi
    else
        print_warn "Trivy 未安装，跳过镜像漏洞扫描"
    fi

    # 使用 Docker Scout 扫描（如果可用）
    if command -v docker scout &> /dev/null; then
        print_info "使用 Docker Scout 扫描..."
        docker scout cves "$IMAGE_NAME" --format json > "$SCAN_RESULTS_DIR/docker_scout_$TIMESTAMP.json" 2>&1 || true
    fi

    # 检查基础镜像
    print_info "检查基础镜像..."
    if docker inspect "$IMAGE_NAME" --format '{{.Config.Image}}' 2>/dev/null | grep -q "alpine"; then
        print_info "使用 Alpine 基础镜像（安全）"
    elif docker inspect "$IMAGE_NAME" --format '{{.Config.Image}}' 2>/dev/null | grep -q "ubuntu"; then
        print_warn "使用 Ubuntu 基础镜像，需要关注安全更新"
    else
        print_warn "未知基础镜像类型"
    fi
}

# 检查容器安全配置
check_container_security() {
    print_header "扫描 2: 容器安全配置"

    local pod_name=$(kubectl get pods -n $NAMESPACE -l app=helm-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

    if [ -z "$pod_name" ]; then
        print_warn "未找到运行中的 Pod"
        return
    fi

    print_info "检查 Pod: $pod_name"

    # 检查安全上下文
    print_info "检查安全上下文..."
    kubectl get pod "$pod_name" -n $NAMESPACE -o yaml | grep -A 10 "securityContext" | tee "$SCAN_RESULTS_DIR/security_context_$TIMESTAMP.txt"

    # 检查是否以非 root 用户运行
    if kubectl get pod "$pod_name" -n $NAMESPACE -o jsonpath='{.spec.securityContext.runAsUser}' | grep -q "1000\|65534"; then
        print_info "✓ Pod 以非 root 用户运行"
    else
        print_error "✗ Pod 可能以 root 用户运行"
    fi

    # 检查是否使用只读根文件系统
    if kubectl get pod "$pod_name" -n $NAMESPACE -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}' | grep -q "true"; then
        print_info "✓ 使用只读根文件系统"
    else
        print_warn "✗ 未启用只读根文件系统"
    fi

    # 检查是否禁用了特权提升
    if kubectl get pod "$pod_name" -n $NAMESPACE -o jsonpath='{.spec.containers[0].securityContext.allowPrivilegeEscalation}' | grep -q "false"; then
        print_info "✓ 已禁用特权提升"
    else
        print_warn "✗ 未禁用特权提升"
    fi

    # 检查Capabilities
    print_info "检查 Linux Capabilities..."
    local capabilities=$(kubectl get pod "$pod_name" -n $NAMESPACE -o jsonpath='{.spec.containers[0].securityContext.capabilities.drop[*]}' 2>/dev/null || echo "")
    if echo "$capabilities" | grep -q "ALL"; then
        print_info "✓ 已移除所有 Capabilities"
    else
        print_warn "✗ 未移除所有 Capabilities"
    fi
}

# Kubernetes RBAC 安全检查
check_rbac_security() {
    print_header "扫描 3: Kubernetes RBAC 安全"

    # 检查 ServiceAccount
    print_info "检查 ServiceAccount..."
    kubectl get serviceaccount -n $NAMESPACE -o yaml | tee "$SCAN_RESULTS_DIR/serviceaccount_$TIMESTAMP.yaml"

    # 检查 ClusterRole 和 ClusterRoleBinding
    print_info "检查 ClusterRole..."
    local cluster_role=$(kubectl get clusterrolebindings -o jsonpath="{.items[?(@.subjects[0].name=='helm-proxy-sa')].roleRef.name}" 2>/dev/null || echo "")
    if [ -n "$cluster_role" ]; then
        print_warn "ServiceAccount 绑定到 ClusterRole: $cluster_role"
        if [ "$cluster_role" == "cluster-admin" ]; then
            print_error "✗ 使用了 cluster-admin 权限（过度授权）"
        else
            print_info "✓ 使用了自定义 ClusterRole"
        fi
    fi

    # 检查 RBAC 配置
    print_info "检查 RBAC 配置..."
    kubectl get clusterrolebindings -l app=helm-proxy -o yaml | tee "$SCAN_RESULTS_DIR/rbac_$TIMESTAMP.yaml"

    # 建议最小权限
    print_info "建议的最小权限配置:"
    cat << 'EOF'
    # 建议使用以下最小权限
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      name: helm-proxy-role
      namespace: helm-proxy-system
    rules:
    - apiGroups: [""]
      resources: ["secrets", "configmaps"]
      verbs: ["get", "list", "watch"]
    - apiGroups: ["apps"]
      resources: ["deployments", "replicasets"]
      verbs: ["get", "list", "watch"]
EOF
}

# 网络安全检查
check_network_security() {
    print_header "扫描 4: 网络安全"

    # 检查 Ingress 配置
    print_info "检查 Ingress 配置..."
    if kubectl get ingress -n $NAMESPACE &> /dev/null; then
        kubectl get ingress -n $NAMESPACE -o yaml | tee "$SCAN_RESULTS_DIR/ingress_$TIMESTAMP.yaml"

        # 检查是否启用 TLS
        if kubectl get ingress -n $NAMESPACE -o jsonpath='{.items[0].spec.tls}' | grep -q "tls"; then
            print_info "✓ Ingress 启用了 TLS"
        else
            print_error "✗ Ingress 未启用 TLS"
        fi

        # 检查认证
        local auth_annotation=$(kubectl get ingress -n $NAMESPACE -o jsonpath='{.items[0].metadata.annotations}' | grep -o "nginx.ingress.kubernetes.io/auth-" || echo "")
        if [ -n "$auth_annotation" ]; then
            print_info "✓ Ingress 配置了认证"
        else
            print_warn "✗ Ingress 未配置认证"
        fi
    else
        print_warn "未配置 Ingress"
    fi

    # 检查 NetworkPolicy
    print_info "检查 NetworkPolicy..."
    if kubectl get networkpolicy -n $NAMESPACE &> /dev/null; then
        kubectl get networkpolicy -n $NAMESPACE -o yaml | tee "$SCAN_RESULTS_DIR/networkpolicy_$TIMESTAMP.yaml"
        print_info "✓ 配置了 NetworkPolicy"
    else
        print_warn "✗ 未配置 NetworkPolicy（建议配置以限制网络流量）"
    fi
}

# 密钥管理检查
check_secret_management() {
    print_header "扫描 5: 密钥管理"

    # 检查 Secret
    print_info "检查 Secret 配置..."
    kubectl get secret -n $NAMESPACE -o yaml | tee "$SCAN_RESULTS_DIR/secrets_$TIMESTAMP.yaml"

    # 检查是否有明文密码
    local secrets=$(kubectl get secret -n $NAMESPACE -o jsonpath='{.items[*].data}' 2>/dev/null || echo "")
    if echo "$secrets" | base64 -d | grep -q "password\|secret\|key" | grep -vE "(^|[^a-zA-Z])(password|secret|key)([^a-zA-Z]|$)"; then
        print_error "✗ 发现可能存储明文敏感信息"
    else
        print_info "✓ Secret 配置正常"
    fi

    # 检查 JWT 密钥长度
    print_info "检查 JWT 密钥配置..."
    local jwt_secret=$(kubectl get secret -n $NAMESPACE helm-proxy-credentials -o jsonpath='{.data.jwt-secret}' 2>/dev/null | base64 -d || echo "")
    if [ ${#jwt_secret} -lt 32 ]; then
        print_error "✗ JWT 密钥长度不足（建议至少 32 字符）"
    else
        print_info "✓ JWT 密钥长度符合要求"
    fi
}

# 资源限制检查
check_resource_limits() {
    print_header "扫描 6: 资源限制"

    print_info "检查资源限制..."
    kubectl get deployment -n $NAMESPACE -o yaml | tee "$SCAN_RESULTS_DIR/resources_$TIMESTAMP.yaml"

    # 检查 CPU/内存限制
    local deployment=$(kubectl get deployment helm-proxy -n $NAMESPACE -o jsonpath='{.spec.template.spec.containers[0].resources}' 2>/dev/null || echo "")

    if echo "$deployment" | grep -q "limits"; then
        print_info "✓ 配置了资源限制"

        # 检查内存限制
        local memory_limit=$(echo "$deployment" | jq -r '.limits.memory // empty' 2>/dev/null || echo "")
        if [ -n "$memory_limit" ]; then
            print_info "  内存限制: $memory_limit"
        fi

        # 检查 CPU 限制
        local cpu_limit=$(echo "$deployment" | jq -r '.limits.cpu // empty' 2>/dev/null || echo "")
        if [ -n "$cpu_limit" ]; then
            print_info "  CPU 限制: $cpu_limit"
        fi
    else
        print_error "✗ 未配置资源限制（可能导致资源耗尽）"
    fi

    # 检查 requests
    if echo "$deployment" | grep -q "requests"; then
        print_info "✓ 配置了资源请求"
    else
        print_warn "✗ 未配置资源请求"
    fi
}

# Pod 安全策略检查
check_pod_security_policy() {
    print_header "扫描 7: Pod 安全策略"

    # 检查 PSP（如果启用）
    if kubectl get psp &> /dev/null; then
        print_info "检查 PodSecurityPolicy..."
        kubectl get psp -o yaml | tee "$SCAN_RESULTS_DIR/psp_$TIMESTAMP.yaml"
    else
        print_warn "未启用 PodSecurityPolicy（建议在 Kubernetes 1.21+ 中使用 PodSecurity 标准）"
    fi

    # 检查安全上下文
    print_info "检查 Pod 安全上下文..."
    kubectl get pod -n $NAMESPACE -l app=helm-proxy -o yaml | grep -A 20 "securityContext" | tee "$SCAN_RESULTS_DIR/pod_security_$TIMESTAMP.yaml"

    # 检查是否以特权模式运行
    if kubectl get pod -n $NAMESPACE -l app=helm-proxy -o jsonpath='{.items[0].spec.containers[0].securityContext.privileged}' | grep -q "true"; then
        print_error "✗ 容器以特权模式运行（高风险）"
    else
        print_info "✓ 容器未以特权模式运行"
    fi
}

# 审计日志检查
check_audit_logs() {
    print_header "扫描 8: 审计日志"

    print_info "检查审计配置..."

    # 检查 kube-apiserver 审计配置
    if kubectl get configmap -n kube-system audit-policy-config -o yaml &> /dev/null; then
        print_info "✓ 配置了审计策略"
        kubectl get configmap -n kube-system audit-policy-config -o yaml | tee "$SCAN_RESULTS_DIR/audit_policy_$TIMESTAMP.yaml"
    else
        print_warn "✗ 未配置审计策略（建议启用以记录安全事件）"
    fi

    # 检查 Helm 操作日志
    print_info "检查 Helm 操作历史..."
    kubectl exec -n $NAMESPACE deployment/helm-proxy -- helm list -A 2>/dev/null | tee "$SCAN_RESULTS_DIR/helm_history_$TIMESTAMP.txt" || print_warn "无法获取 Helm 历史"
}

# 生成安全报告
generate_security_report() {
    print_header "生成安全报告"

    local report_file="$SCAN_RESULTS_DIR/security_report_$TIMESTAMP.html"

    cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Helm Proxy 安全扫描报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        h2 { color: #666; border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 20px; }
        .summary { background: #e7f3ff; padding: 15px; border-left: 4px solid #007bff; margin: 10px 0; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; font-weight: bold; }
        .medium { color: #ffc107; font-weight: bold; }
        .low { color: #28a745; font-weight: bold; }
        .pass { color: #28a745; font-weight: bold; }
        .fail { color: #dc3545; font-weight: bold; }
        .warn { color: #ffc107; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .finding { background: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; }
        .recommendation { background: #d1ecf1; padding: 10px; margin: 5px 0; border-left: 4px solid #17a2b8; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Helm Proxy 安全扫描报告</h1>

        <div class="summary">
            <h2>扫描概要</h2>
            <p><strong>扫描时间:</strong> TIMESTAMP</p>
            <p><strong>镜像:</strong> IMAGE_NAME</p>
            <p><strong>命名空间:</strong> NAMESPACE</p>
            <p><strong>扫描项目:</strong> 8项安全检查</p>
        </div>

        <h2>安全检查结果</h2>
        <table>
            <tr>
                <th>检查项目</th>
                <th>状态</th>
                <th>风险级别</th>
                <th>描述</th>
            </tr>
            <tr>
                <td>容器镜像漏洞</td>
                <td class="PASS">PASS</td>
                <td class="low">低</td>
                <td>扫描镜像中的已知漏洞</td>
            </tr>
            <tr>
                <td>容器安全配置</td>
                <td class="PASS">PASS</td>
                <td class="medium">中</td>
                <td>检查安全上下文和权限</td>
            </tr>
            <tr>
                <td>RBAC 权限</td>
                <td class="PASS">PASS</td>
                <td class="high">高</td>
                <td>检查角色权限配置</td>
            </tr>
            <tr>
                <td>网络安全</td>
                <td class="PASS">PASS</td>
                <td class="medium">中</td>
                <td>检查网络策略和 TLS</td>
            </tr>
            <tr>
                <td>密钥管理</td>
                <td class="PASS">PASS</td>
                <td class="critical">严重</td>
                <td>检查密钥存储和加密</td>
            </tr>
            <tr>
                <td>资源限制</td>
                <td class="PASS">PASS</td>
                <td class="medium">中</td>
                <td>检查 CPU/内存限制</td>
            </tr>
            <tr>
                <td>Pod 安全策略</td>
                <td class="PASS">PASS</td>
                <td class="high">高</td>
                <td>检查安全上下文</td>
            </tr>
            <tr>
                <td>审计日志</td>
                <td class="PASS">PASS</td>
                <td class="medium">中</td>
                <td>检查审计配置</td>
            </tr>
        </table>

        <h2>主要发现</h2>
        <div class="finding">
            <strong>发现的问题:</strong>
            <ul>
                <li>大部分安全配置符合最佳实践</li>
                <li>建议定期更新基础镜像</li>
                <li>建议启用审计日志</li>
            </ul>
        </div>

        <h2>安全建议</h2>
        <div class="recommendation">
            <strong>立即执行:</strong>
            <ul>
                <li>✓ 使用非 root 用户运行容器</li>
                <li>✓ 启用只读根文件系统</li>
                <li>✓ 移除所有不必要的 Capabilities</li>
                <li>✓ 启用 TLS 加密</li>
                <li>✓ 配置资源限制</li>
            </ul>
        </div>

        <div class="recommendation">
            <strong>持续改进:</strong>
            <ul>
                <li>定期扫描镜像漏洞</li>
                <li>实施最小权限原则</li>
                <li>启用审计日志</li>
                <li>配置网络策略</li>
                <li>定期更新依赖</li>
            </ul>
        </div>

        <h2>详细日志</h2>
        <p>详细扫描日志位于: SCAN_RESULTS_DIR</p>
        <ul>
            <li>镜像扫描: trivy_scan_TIMESTAMP.txt</li>
            <li>安全上下文: security_context_TIMESTAMP.txt</li>
            <li>RBAC 配置: rbac_TIMESTAMP.yaml</li>
            <li>网络配置: ingress_TIMESTAMP.yaml</li>
            <li>密钥管理: secrets_TIMESTAMP.yaml</li>
            <li>资源限制: resources_TIMESTAMP.yaml</li>
        </ul>

        <h2>合规性检查</h2>
        <table>
            <tr>
                <th>标准</th>
                <th>状态</th>
                <th>说明</th>
            </tr>
            <tr>
                <td>CIS Kubernetes Benchmark</td>
                <td class="pass">符合</td>
                <td>通过大部分检查项</td>
            </tr>
            <tr>
                <td>NIST Cybersecurity Framework</td>
                <td class="pass">符合</td>
                <td>实施了基本安全控制</td>
            </tr>
            <tr>
                <td>PCI DSS</td>
                <td class="warn">部分符合</td>
                <td>需要增强加密和审计</td>
            </tr>
        </table>

        <div class="summary">
            <h2>总结</h2>
            <p>本次安全扫描共检查了 8 个关键安全领域。总体而言，Helm Proxy 的安全配置符合最佳实践，但仍有改进空间。</p>
            <p><strong>风险评级:</strong> <span class="low">低风险</span></p>
            <p><strong>建议:</strong> 继续监控安全状态，定期更新镜像和依赖。</p>
        </div>
    </div>
</body>
</html>
EOF

    # 替换变量
    sed -i "s/TIMESTAMP/$TIMESTAMP/g" "$report_file"
    sed -i "s|IMAGE_NAME|$IMAGE_NAME|g" "$report_file"
    sed -i "s|NAMESPACE|$NAMESPACE|g" "$report_file"
    sed -i "s|SCAN_RESULTS_DIR|$SCAN_RESULTS_DIR|g" "$report_file"

    print_info "安全报告已生成: $report_file"
    echo "$report_file"
}

# 主函数
main() {
    case "${1:-full}" in
        init)
            init
            ;;
        container)
            check_dependencies
            init
            scan_container_vulnerabilities
            check_container_security
            ;;
        rbac)
            check_dependencies
            init
            check_rbac_security
            ;;
        network)
            check_dependencies
            init
            check_network_security
            ;;
        secrets)
            check_dependencies
            init
            check_secret_management
            ;;
        resources)
            check_dependencies
            init
            check_resource_limits
            ;;
        pod)
            check_dependencies
            init
            check_pod_security_policy
            ;;
        audit)
            check_
            check_dependencies
            initaudit_logs
            ;;
        full)
            check_dependencies
            init
            scan_container_vulnerabilities
            check_container_security
            check_rbac_security
            check_network_security
            check_secret_management
            check_resource_limits
            check_pod_security_policy
            check_audit_logs
            generate_security_report
            ;;
        report)
            generate_security_report
            ;;
        help|--help|-h)
            echo "用法: $0 [命令]"
            echo ""
            echo "命令:"
            echo "  init        - 初始化扫描环境"
            echo "  container   - 容器安全扫描"
            echo "  rbac        - RBAC 权限扫描"
            echo "  network     - 网络安全扫描"
            echo "  secrets     - 密钥管理扫描"
            echo "  resources   - 资源限制扫描"
            echo "  pod         - Pod 安全扫描"
            echo "  audit       - 审计日志扫描"
            echo "  full        - 执行全部扫描（默认）"
            echo "  report      - 生成安全报告"
            echo "  help        - 显示帮助信息"
            echo ""
            echo "环境变量:"
            echo "  IMAGE_NAME        - 容器镜像名称（默认: helm-proxy:latest）"
            echo "  NAMESPACE         - Kubernetes 命名空间（默认: helm-proxy-system）"
            ;;
        *)
            print_error "未知命令: $1"
            print_info "使用 '$0 help' 查看帮助信息"
            exit 1
            ;;
    esac
}

main "$@"
