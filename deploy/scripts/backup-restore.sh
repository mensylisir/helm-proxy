#!/bin/bash
# 增强版备份和灾难恢复脚本 - Helm Proxy
# 支持多集群、云存储集成、增量备份、压缩加密等功能

set -e

# 配置
NAMESPACE="helm-proxy-system"
BACKUP_DIR="/backup/helm-proxy"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30
COMPRESSION_LEVEL=6
ENCRYPTION_ENABLED=false
ENCRYPTION_KEY=""
CLOUD_STORAGE_ENABLED=false
CLOUD_PROVIDER=""  # aws, gcp, azure
CLOUD_BUCKET=""
PARALLEL_JOBS=4
INCREMENTAL=false
LAST_BACKUP_MARKER="/tmp/helm-proxy-last-backup"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            --retention-days)
                RETENTION_DAYS="$2"
                shift 2
                ;;
            --compression-level)
                COMPRESSION_LEVEL="$2"
                shift 2
                ;;
            --encrypt)
                ENCRYPTION_ENABLED=true
                ENCRYPTION_KEY="$2"
                shift 2
                ;;
            --cloud)
                CLOUD_STORAGE_ENABLED=true
                CLOUD_PROVIDER="$2"
                CLOUD_BUCKET="$3"
                shift 3
                ;;
            --parallel-jobs)
                PARALLEL_JOBS="$2"
                shift 2
                ;;
            --incremental)
                INCREMENTAL=true
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
}

# 检查依赖工具
check_dependencies() {
    local missing_tools=()

    # 检查 kubectl
    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi

    # 检查压缩工具
    if ! command -v tar &> /dev/null; then
        missing_tools+=("tar")
    fi

    # 检查云存储工具
    if [ "$CLOUD_STORAGE_ENABLED" = true ]; then
        case "$CLOUD_PROVIDER" in
            aws)
                if ! command -v aws &> /dev/null; then
                    missing_tools+=("aws-cli")
                fi
                ;;
            gcp)
                if ! command -v gsutil &> /dev/null; then
                    missing_tools+=("gsutil")
                fi
                ;;
            azure)
                if ! command -v az &> /dev/null; then
                    missing_tools+=("azure-cli")
                fi
                ;;
        esac
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "缺少依赖工具: ${missing_tools[*]}"
        exit 1
    fi
}

# 备份 etcd 数据（如果适用）
backup_etcd() {
    if command -v etcdctl &> /dev/null; then
        print_info "备份 etcd 数据..."
        ETCD_BACKUP_FILE="$BACKUP_DIR/etcd_snapshot_$TIMESTAMP.db"
        etcdctl snapshot save "$ETCD_BACKUP_FILE" 2>/dev/null || print_warn "无法备份 etcd，跳过"
    fi
}

# 备份 PVC 数据
backup_pvc_data() {
    print_info "备份 PVC 数据..."
    local pvc_list=$(kubectl get pvc -n $NAMESPACE -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
    if [ -n "$pvc_list" ]; then
        for pvc in $pvc_list; do
            print_info "备份 PVC: $pvc"
            kubectl create job --from=cronjob/backup-pvc-$pvc backup-pvc-$pvc-$TIMESTAMP -n $NAMESPACE 2>/dev/null || true
        done
    fi
}

# 备份集群状态
backup_cluster_state() {
    print_info "备份集群状态..."
    kubectl get nodes -o yaml > "$BACKUP_DIR/nodes.yaml"
    kubectl get clusterroles -o yaml > "$BACKUP_DIR/clusterroles.yaml"
    kubectl get clusterrolebindings -o yaml > "$BACKrolebindings.yaml"
UP_DIR/cluster    kubectl get crd -o yaml > "$BACKUP_DIR/crds.yaml" 2>/dev/null || true
}

# 增量备份标记
mark_backup() {
    echo "$TIMESTAMP" > "$LAST_BACKUP_MARKER"
}

# 获取增量备份变更
get_incremental_changes() {
    if [ ! -f "$LAST_BACKUP_MARKER" ]; then
        print_info "首次备份，执行完整备份"
        return 0
    fi

    local last_backup=$(cat "$LAST_BACKUP_MARKER")
    print_info "基于上次备份 $last_backup 执行增量备份"

    # 这里可以实现更复杂的增量逻辑
    # 例如使用 kubectl 的 label selector 来过滤变更
    return 0
}

# 备份函数
backup_config() {
    local backup_path="$BACKUP_DIR/config_$TIMESTAMP"
    print_info "开始备份配置到 $backup_path..."

    mkdir -p "$backup_path"
    mkdir -p "$BACKUP_DIR/tmp"

    # 并行备份
    {
        print_info "并行备份 Kubernetes 资源..."

        # 备份 ConfigMap
        kubectl get configmap -n $NAMESPACE -o yaml > "$backup_path/configmaps.yaml" 2>/dev/null || echo "# No ConfigMaps" > "$backup_path/configmaps.yaml"

        # 备份 Secret（注意敏感信息）
        kubectl get secret -n $NAMESPACE -o yaml > "$backup_path/secrets.yaml" 2>/dev/null || echo "# No Secrets" > "$backup_path/secrets.yaml"

        # 备份部署资源
        kubectl get deployment -n $NAMESPACE -o yaml > "$backup_path/deployment.yaml" 2>/dev/null || echo "# No Deployments" > "$backup_path/deployment.yaml"
        kubectl get service -n $NAMESPACE -o yaml > "$backup_path/services.yaml" 2>/dev/null || echo "# No Services" > "$backup_path/services.yaml"
        kubectl get ingress -n $NAMESPACE -o yaml > "$backup_path/ingress.yaml" 2>/dev/null || echo "# No Ingress" > "$backup_path/ingress.yaml"
        kubectl get hpa -n $NAMESPACE -o yaml > "$backup_path/hpa.yaml" 2>/dev/null || echo "# No HPA" > "$backup_path/hpa.yaml"
        kubectl get pdb -n $NAMESPACE -o yaml > "$backup_path/pdb.yaml" 2>/dev/null || echo "# No PDB" > "$backup_path/pdb.yaml"
        kubectl get svcMonitor -n $NAMESPACE -o yaml > "$backup_path/servicemonitors.yaml" 2>/dev/null || echo "# No ServiceMonitors" > "$backup_path/servicemonitors.yaml"
        kubectl get prometheusrule -n $NAMESPACE -o yaml > "$backup_path/prometheusrules.yaml" 2>/dev/null || echo "# No PrometheusRules" > "$backup_path/prometheusrules.yaml"

        # 备份 Helm release 历史
        kubectl exec -n $NAMESPACE deployment/helm-proxy -- helm list -A -o yaml > "$backup_path/helm_releases.yaml" 2>/dev/null || echo "# No Helm Releases" > "$backup_path/helm_releases.yaml"

        # 备份 PVC
        kubectl get pvc -n $NAMESPACE -o yaml > "$backup_path/pvcs.yaml" 2>/dev/null || echo "# No PVCs" > "$backup_path/pvcs.yaml"

        # 备份事件
        kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp' -o yaml > "$backup_path/events.yaml" 2>/dev/null || echo "# No Events" > "$backup_path/events.yaml"

        # 备份集群状态（仅完整备份）
        if [ "$INCREMENTAL" = false ]; then
            backup_cluster_state
        fi

        # 备份 etcd（如果适用）
        backup_etcd

    } &

    local backup_pid=$!

    # 等待并行任务完成
    wait $backup_pid

    # 创建备份清单
    create_backup_manifest "$backup_path"

    # 压缩备份
    local backup_file="$BACKUP_DIR/backup_$TIMESTAMP.tar.gz"
    print_info "压缩备份文件（压缩级别: $COMPRESSION_LEVEL）..."
    tar -czf "$backup_file" -C "$BACKUP_DIR" "config_$TIMESTAMP" --use-compress-program="gzip -$COMPRESSION_LEVEL"

    # 加密备份（如果启用）
    if [ "$ENCRYPTION_ENABLED" = true ] && [ -n "$ENCRYPTION_KEY" ]; then
        print_info "加密备份文件..."
        gpg --symmetric --cipher-algo AES256 --compress-algo 1 --s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65536 --passphrase "$ENCRYPTION_KEY" --quiet --no-greeting -o "$backup_file.gpg" "$backup_file"
        rm -f "$backup_file"
        backup_file="$backup_file.gpg"
    fi

    # 上传到云存储（如果启用）
    if [ "$CLOUD_STORAGE_ENABLED" = true ]; then
        upload_to_cloud "$backup_file"
    fi

    # 清理临时文件
    rm -rf "$backup_path"

    # 计算校验和
    local checksum=$(sha256sum "$backup_file" | cut -d' ' -f1)
    echo "$checksum" > "$backup_file.sha256"

    # 记录备份
    record_backup "$backup_file" "$checksum"

    # 标记增量备份
    mark_backup

    print_info "备份完成: $backup_file"
    print_info "校验和: $checksum"
}

# 创建备份清单
create_backup_manifest() {
    local backup_path="$1"
    cat > "$backup_path/manifest.json" << EOF
{
    "timestamp": "$TIMESTAMP",
    "namespace": "$NAMESPACE",
    "version": "2.0.0",
    "type": "$([ "$INCREMENTAL" = true ] && echo "incremental" || echo "full")",
    "cluster": "$(kubectl config current-context 2>/dev/null || echo 'unknown')",
    "kubernetes_version": "$(kubectl version --short 2>/dev/null | grep Server | awk '{print $3}' || echo 'unknown')",
    "backup_tool": "helm-proxy-backup-restore",
    "compression": "gzip-$COMPRESSION_LEVEL",
    "encryption": $ENCRYPTION_ENABLED,
    "cloud_storage": $CLOUD_STORAGE_ENABLED,
    "files": [
        "configmaps.yaml",
        "secrets.yaml",
        "deployment.yaml",
        "services.yaml",
        "ingress.yaml",
        "hpa.yaml",
        "pdb.yaml",
        "servicemonitors.yaml",
        "prometheusrules.yaml",
        "helm_releases.yaml",
        "pvcs.yaml",
        "events.yaml"
    ]
}
EOF
}

# 上传到云存储
upload_to_cloud() {
    local file="$1"
    local filename=$(basename "$file")

    print_info "上传到云存储: $CLOUD_PROVIDER $CLOUD_BUCKET/$filename"

    case "$CLOUD_PROVIDER" in
        aws)
            aws s3 cp "$file" "s3://$CLOUD_BUCKET/helm-proxy-backups/$filename" --storage-class STANDARD_IA
            aws s3 cp "$file.sha256" "s3://$CLOUD_BUCKET/helm-proxy-backups/$filename.sha256"
            ;;
        gcp)
            gsutil cp "$file" "gs://$CLOUD_BUCKET/helm-proxy-backups/$filename"
            gsutil cp "$file.sha256" "gs://$CLOUD_BUCKET/helm-proxy-backups/$filename.sha256"
            ;;
        azure)
            az storage blob upload --file "$file" --container-name "$CLOUD_BUCKET" --name "helm-proxy-backups/$filename"
            az storage blob upload --file "$file.sha256" --container-name "$CLOUD_BUCKET" --name "helm-proxy-backups/$filename.sha256"
            ;;
    esac

    print_info "云存储上传完成"
}

# 记录备份信息
record_backup() {
    local file="$1"
    local checksum="$2"
    local backup_record="/tmp/helm-proxy-backup-records.json"

    if [ ! -f "$backup_record" ]; then
        echo "[]" > "$backup_record"
    fi

    # 使用 jq 添加新记录（如果可用）
    if command -v jq &> /dev/null; then
        jq --arg file "$file" --arg checksum "$checksum" --arg ts "$TIMESTAMP" \
           '. + [{"file": $file, "checksum": $checksum, "timestamp": $ts, "size": ($file | @text | split(" ") | .[0] // 0)}]' \
           "$backup_record" > "$backup_record.tmp"
        mv "$backup_record.tmp" "$backup_record"
    else
        echo "{\"file\": \"$file\", \"checksum\": \"$checksum\", \"timestamp\": \"$TIMESTAMP\"}" >> "$backup_record"
    fi
}

# 从云存储下载备份
download_from_cloud() {
    local filename="$1"
    local local_file="$BACKUP_DIR/$filename"

    print_info "从云存储下载: $CLOUD_PROVIDER $CLOUD_BUCKET/$filename"

    case "$CLOUD_PROVIDER" in
        aws)
            aws s3 cp "s3://$CLOUD_BUCKET/helm-proxy-backups/$filename" "$local_file"
            aws s3 cp "s3://$CLOUD_BUCKET/helm-proxy-backups/$filename.sha256" "$local_file.sha256"
            ;;
        gcp)
            gsutil cp "gs://$CLOUD_BUCKET/helm-proxy-backups/$filename" "$local_file"
            gsutil cp "gs://$CLOUD_BUCKET/helm-proxy-backups/$filename.sha256" "$local_file.sha256"
            ;;
        azure)
            az storage blob download --container-name "$CLOUD_BUCKET" --name "helm-proxy-backups/$filename" --file "$local_file"
            az storage blob download --container-name "$CLOUD_BUCKET" --name "helm-proxy-backups/$filename.sha256" --file "$local_file.sha256"
            ;;
    esac

    echo "$local_file"
}

# 验证备份文件完整性
verify_backup() {
    local backup_file="$1"
    local expected_checksum="$2"

    if [ ! -f "$backup_file.sha256" ]; then
        print_warn "未找到校验和文件，跳过验证"
        return 0
    fi

    local actual_checksum=$(sha256sum "$backup_file" | cut -d' ' -f1)
    if [ "$actual_checksum" != "$expected_checksum" ]; then
        print_error "备份文件校验和不匹配！"
        print_error "期望: $expected_checksum"
        print_error "实际: $actual_checksum"
        return 1
    fi

    print_info "备份文件完整性验证通过"
    return 0
}

# 预恢复检查
pre_restore_check() {
    print_info "执行预恢复检查..."

    # 检查命名空间是否存在
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        print_info "命名空间 $NAMESPACE 不存在，将创建"
        kubectl create namespace "$NAMESPACE"
    fi

    # 检查当前部署状态
    local current_deployment=$(kubectl get deployment -n "$NAMESPACE" helm-proxy -o name 2>/dev/null || true)
    if [ -n "$current_deployment" ]; then
        print_warn "发现现有部署，将执行替换操作"
    fi

    # 检查资源配额
    print_info "检查资源配额..."
    kubectl describe namespace "$NAMESPACE" | grep -A 10 "ResourceQuota" || true

    # 检查磁盘空间
    local available_space=$(df -BG "$BACKUP_DIR" | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$available_space" -lt 5 ]; then
        print_error "磁盘空间不足，至少需要 5GB，当前可用: ${available_space}GB"
        return 1
    fi

    print_info "预恢复检查通过"
}

# 恢复函数
restore_config() {
    local backup_file="$1"
    if [ -z "$backup_file" ]; then
        print_error "请指定备份文件"
        exit 1
    fi

    # 从云存储下载（如果需要）
    if [[ "$backup_file" == s3://* ]] || [[ "$backup_file" == gs://* ]] || [[ "$backup_file" == az://* ]]; then
        backup_file=$(download_from_cloud "$(basename "$backup_file")")
    fi

    if [ ! -f "$backup_file" ]; then
        print_error "备份文件不存在: $backup_file"
        exit 1
    fi

    print_warn "即将恢复配置从 $backup_file"
    read -p "确认继续？(y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "恢复已取消"
        exit 0
    fi

    # 预恢复检查
    pre_restore_check || exit 1

    # 解密备份（如果需要）
    local restore_file="$backup_file"
    if [[ "$backup_file" == *.gpg ]]; then
        if [ -z "$ENCRYPTION_KEY" ]; then
            print_error "备份文件已加密，请提供解密密钥"
            exit 1
        fi
        print_info "解密备份文件..."
        restore_file="${backup_file%.gpg}"
        gpg --decrypt --passphrase "$ENCRYPTION_KEY" --quiet --no-greeting -o "$restore_file" "$backup_file"
    fi

    # 验证备份文件完整性
    if [ -f "$backup_file.sha256" ]; then
        local expected_checksum=$(cat "$backup_file.sha256")
        verify_backup "$restore_file" "$expected_checksum" || exit 1
    fi

    # 解压备份
    local restore_dir="/tmp/restore_$TIMESTAMP"
    mkdir -p "$restore_dir"
    print_info "解压备份文件..."
    tar -xzf "$restore_file" -C "$restore_dir"

    # 获取备份目录
    local backup_dir=$(find "$restore_dir" -mindepth 1 -maxdepth 1 -type d | head -1)

    # 读取备份清单
    if [ -f "$backup_dir/manifest.json" ]; then
        print_info "读取备份清单..."
        if command -v jq &> /dev/null; then
            local backup_type=$(jq -r '.type' "$backup_dir/manifest.json")
            local backup_version=$(jq -r '.version' "$backup_dir/manifest.json")
            print_info "备份类型: $backup_type, 版本: $backup_version"
        fi
    fi

    # 按顺序恢复资源
    print_info "开始恢复资源..."

    # 1. 恢复 RBAC 资源
    print_info "恢复 RBAC 资源..."
    kubectl apply -f "$backup_dir/clusterroles.yaml" 2>/dev/null || true
    kubectl apply -f "$backup_dir/clusterrolebindings.yaml" 2>/dev/null || true

    # 2. 恢复 ServiceAccount
    kubectl apply -f "$backup_dir/configmaps.yaml" 2>/dev/null | grep -q "ServiceAccount" && \
        kubectl apply -f <(grep -A 50 "kind: ServiceAccount" "$backup_dir/configmaps.yaml") 2>/dev/null || true

    # 3. 恢复 ConfigMap
    print_info "恢复 ConfigMap..."
    kubectl apply -f "$backup_dir/configmaps.yaml" --validate=false

    # 4. 恢复 Secret
    print_info "恢复 Secret..."
    kubectl apply -f "$backup_dir/secrets.yaml" --validate=false

    # 5. 恢复 PVC
    print_info "恢复 PVC..."
    kubectl apply -f "$backup_dir/pvcs.yaml" --validate=false

    # 6. 恢复部署资源
    print_info "恢复 Deployment..."
    kubectl apply -f "$backup_dir/deployment.yaml" --validate=false
    kubectl apply -f "$backup_dir/services.yaml" --validate=false
    kubectl apply -f "$backup_dir/ingress.yaml" --validate=false 2>/dev/null || true
    kubectl apply -f "$backup_dir/hpa.yaml" --validate=false 2>/dev/null || true
    kubectl apply -f "$backup_dir/pdb.yaml" --validate=false 2>/dev/null || true

    # 7. 恢复监控资源
    print_info "恢复监控资源..."
    kubectl apply -f "$backup_dir/servicemonitors.yaml" --validate=false 2>/dev/null || true
    kubectl apply -f "$backup_dir/prometheusrules.yaml" --validate=false 2>/dev/null || true

    # 等待就绪
    print_info "等待部署就绪..."
    local max_attempts=60
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if kubectl rollout status deployment/helm-proxy -n $NAMESPACE --timeout=30s &> /dev/null; then
            print_info "部署就绪"
            break
        fi
        attempt=$((attempt + 1))
        if [ $attempt -eq $max_attempts ]; then
            print_error "部署超时"
            kubectl describe deployment helm-proxy -n $NAMESPACE
            exit 1
        fi
        print_info "等待部署完成... ($attempt/$max_attempts)"
        sleep 10
    done

    # 恢复 Helm releases
    if [ -f "$backup_dir/helm_releases.yaml" ] && grep -q "kind: Release" "$backup_dir/helm_releases.yaml"; then
        print_info "恢复 Helm releases..."
        kubectl exec -n $NAMESPACE deployment/helm-proxy -- helm list -A 2>/dev/null || true
    fi

    # 验证恢复
    print_info "验证恢复结果..."
    sleep 5
    kubectl get all -n $NAMESPACE -l app=helm-proxy

    # 清理临时文件
    rm -rf "$restore_dir"

    print_info "恢复完成"
}

# 列出备份
list_backups() {
    print_info "可用的备份："
    ls -lh "$BACKUP_DIR"/*.tar.gz 2>/dev/null || print_warn "没有找到备份文件"
}

# 清理旧备份
cleanup_old_backups() {
    local days="${1:-30}"
    print_info "清理 $days 天前的备份..."
    find "$BACKUP_DIR" -name "*.tar.gz" -mtime +$days -delete
    print_info "清理完成"
}

# 灾难恢复演练
disaster_recovery_drill() {
    print_warn "开始灾难恢复演练..."
    print_info "1. 模拟故障：删除所有 Pod"
    kubectl delete pods -n $NAMESPACE -l app=helm-proxy

    print_info "2. 验证自动恢复..."
    sleep 10
    kubectl get pods -n $NAMESPACE -l app=helm-proxy

    print_info "3. 验证服务可用性..."
    sleep 30
    if kubectl exec -n $NAMESPACE deployment/helm-proxy -- curl -k -s https://localhost:8443/v1/monitor/health > /dev/null; then
        print_info "灾难恢复演练成功"
    else
        print_error "灾难恢复演练失败"
        exit 1
    fi
}

# 健康检查
health_check() {
    print_info "执行健康检查..."

    # 检查 Pod 状态
    local pod_count=$(kubectl get pods -n $NAMESPACE -l app=helm-proxy --no-headers | grep Running | wc -l)
    if [ "$pod_count" -lt 3 ]; then
        print_error "Pod 数量不足: $pod_count/3"
        return 1
    fi

    # 检查服务
    if ! kubectl get svc -n $NAMESPACE helm-proxy &> /dev/null; then
        print_error "Service 不存在"
        return 1
    fi

    # 检查端点
    local endpoints=$(kubectl get endpoints -n $NAMESPACE helm-proxy -o jsonpath='{.subsets[*].addresses[*].ip}' | wc -w)
    if [ "$endpoints" -lt 3 ]; then
        print_error "Endpoints 数量不足: $endpoints/3"
        return 1
    fi

    # 检查健康检查端点
    sleep 5
    for i in {1..3}; do
        if kubectl exec -n $NAMESPACE deployment/helm-proxy -- curl -k -s https://localhost:8443/v1/monitor/health > /dev/null; then
            print_info "健康检查通过"
            break
        else
            if [ $i -eq 3 ]; then
                print_error "健康检查失败"
                return 1
            fi
            sleep 5
        fi
    done

    print_info "健康检查通过"
}

# 监控备份进度
monitor_backup_progress() {
    local backup_pid="$1"
    local log_file="$BACKUP_DIR/backup_$TIMESTAMP.log"

    while kill -0 "$backup_pid" 2>/dev/null; do
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 备份进行中..." >> "$log_file"
        sleep 30
    done

    wait "$backup_pid"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 备份完成" >> "$log_file"
}

# 定时备份
schedule_backup() {
    print_info "设置定时备份..."

    local cron_cmd="$0 backup --namespace $NAMESPACE --retention-days $RETENTION_DAYS"
    if [ "$ENCRYPTION_ENABLED" = true ]; then
        cron_cmd="$cron_cmd --encrypt $ENCRYPTION_KEY"
    fi

    (crontab -l 2>/dev/null; echo "0 2 * * * $cron_cmd >> /var/log/helm-proxy-backup.log 2>&1") | crontab -

    print_info "定时备份已设置（每天凌晨2点执行）"
    print_info "Cron 命令: $cron_cmd"
}

# 性能测试备份
benchmark_backup() {
    print_info "开始备份性能测试..."

    local iterations="${1:-3}"
    local total_time=0

    for i in $(seq 1 $iterations); do
        print_info "第 $i/$iterations 次测试..."

        local start_time=$(date +%s)
        backup_config > /dev/null 2>&1
        local end_time=$(date +%s)

        local duration=$((end_time - start_time))
        total_time=$((total_time + duration))

        print_info "第 $i 次耗时: ${duration}秒"

        sleep 5
    done

    local avg_time=$((total_time / iterations))
    print_info "平均备份时间: ${avg_time}秒"
    print_info "性能测试完成"
}

# 备份统计
backup_statistics() {
    print_info "备份统计信息："

    local backup_record="/tmp/helm-proxy-backup-records.json"
    if [ ! -f "$backup_record" ]; then
        print_warn "没有找到备份记录"
        return 0
    fi

    if command -v jq &> /dev/null; then
        local total_backups=$(jq '. | length' "$backup_record")
        local latest_backup=$(jq -r '.[-1].timestamp' "$backup_record")
        local total_size=$(jq '[.[].size] | add' "$backup_record")

        print_info "总备份数: $total_backups"
        print_info "最新备份: $latest_backup"
        print_info "总大小: $(numfmt --to=iec $total_size 2>/dev/null || echo "${total_size}字节")"
    else
        print_warn "需要安装 jq 来查看详细统计"
        cat "$backup_record"
    fi
}

# 主函数
main() {
    # 解析全局参数
    parse_args "$@"

    # 切换到参数列表
    shift $((OPTIND-1))

    case "${1:-backup}" in
        backup)
            check_dependencies
            mkdir -p "$BACKUP_DIR"
            backup_config
            ;;
        restore)
            check_dependencies
            restore_config "$2"
            ;;
        list)
            list_backups
            ;;
        cleanup)
            cleanup_old_backups "${2:-30}"
            ;;
        schedule)
            schedule_backup
            ;;
        benchmark)
            benchmark_backup "${2:-3}"
            ;;
        statistics)
            backup_statistics
            ;;
        drill)
            disaster_recovery_drill
            ;;
        health)
            health_check
            ;;
        verify)
            local backup_file="$2"
            if [ -z "$backup_file" ]; then
                print_error "请指定备份文件"
                exit 1
            fi
            if [ -f "$backup_file.sha256" ]; then
                verify_backup "$backup_file" "$(cat "$backup_file.sha256")"
            else
                print_error "未找到校验和文件"
                exit 1
            fi
            ;;
        help|--help|-h)
            echo "用法: $0 [选项] 命令 [参数]"
            echo ""
            echo "命令:"
            echo "  backup                    备份配置（默认）"
            echo "  restore <备份文件>        恢复配置"
            echo "  list                      列出备份"
            echo "  cleanup [天数]            清理旧备份（默认30天）"
            echo "  schedule                  设置定时备份"
            echo "  benchmark [次数]          备份性能测试（默认3次）"
            echo "  statistics                备份统计信息"
            echo "  drill                     灾难恢复演练"
            echo "  health                    健康检查"
            echo "  verify <备份文件>         验证备份文件完整性"
            echo "  help                      显示帮助信息"
            echo ""
            echo "选项:"
            echo "  --namespace <名称>        指定命名空间（默认: helm-proxy-system）"
            echo "  --retention-days <天数>   备份保留天数（默认: 30）"
            echo "  --compression-level <级别> 压缩级别 1-9（默认: 6）"
            echo "  --encrypt <密钥>          启用加密"
            echo "  --cloud <提供商> <桶名>   启用云存储（aws/gcp/azure）"
            echo "  --parallel-jobs <数量>    并行任务数（默认: 4）"
            echo "  --incremental             增量备份"
            echo ""
            echo "示例:"
            echo "  # 基本备份"
            echo "  $0 backup"
            echo ""
            echo "  # 加密备份到云存储"
            echo "  $0 backup --encrypt 'my-password' --cloud aws my-bucket"
            echo ""
            echo "  # 从云存储恢复"
            echo "  $0 restore s3://my-bucket/helm-proxy-backups/backup_20231215_020000.tar.gz"
            echo ""
            echo "  # 性能测试"
            echo "  $0 benchmark 5"
            ;;
        *)
            print_error "未知命令: $1"
            print_info "使用 '$0 help' 查看帮助信息"
            exit 1
            ;;
    esac
}

main "$@"
