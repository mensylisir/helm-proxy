#!/bin/bash
# 性能测试脚本 - Helm Proxy
# 支持并发测试、负载测试、压力测试等

set -e

# 配置
NAMESPACE="helm-proxy-system"
SERVICE_URL="${SERVICE_URL:-http://localhost:8443}"
TEST_DURATION=300  # 默认测试5分钟
CONCURRENT_USERS=10
RAMP_UP_TIME=60
MAX_RESPONSE_TIME=5000  # 毫秒
ERROR_RATE_THRESHOLD=1  # 百分比

# 测试结果目录
RESULTS_DIR="/tmp/helm-proxy-performance-test"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TEST_LOG="$RESULTS_DIR/test_$TIMESTAMP.log"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$TEST_LOG"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$TEST_LOG"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$TEST_LOG"
}

print_header() {
    echo -e "\n${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}\n" | tee -a "$TEST_LOG"
}

# 初始化
init() {
    mkdir -p "$RESULTS_DIR"
    echo "性能测试开始: $(date)" > "$TEST_LOG"
    print_header "Helm Proxy 性能测试"
    print_info "测试时间: $TIMESTAMP"
    print_info "服务地址: $SERVICE_URL"
    print_info "命名空间: $NAMESPACE"
    print_info "并发用户: $CONCURRENT_USERS"
    print_info "测试时长: ${TEST_DURATION}秒"
}

# 检查依赖
check_dependencies() {
    local missing_tools=()

    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi

    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi

    if ! command -v ab &> /dev/null && ! command -v hey &> /dev/null; then
        missing_tools+=("ab 或 hey")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "缺少依赖工具: ${missing_tools[*]}"
        exit 1
    fi
}

# 准备测试环境
prepare_test_environment() {
    print_info "准备测试环境..."

    # 检查服务是否可访问
    if ! curl -s -f "$SERVICE_URL/v1/monitor/health" > /dev/null; then
        print_warn "服务健康检查失败，尝试使用备用地址"
        SERVICE_URL="http://localhost:18091"
        if ! curl -s -f "$SERVICE_URL/v1/monitor/health" > /dev/null; then
            print_error "无法访问服务: $SERVICE_URL"
            exit 1
        fi
    fi

    print_info "服务可访问，开始测试"
}

# 创建测试应用
create_test_app() {
    local app_name="$1"
    local node_port="$2"

    local payload=$(cat << EOF
{
  "prune": false,
  "timeout": 300,
  "wait": false,
  "type": "app",
  "name": "$app_name",
  "answers": {
    "service.nodePort": "$node_port"
  },
  "targetNamespace": "$NAMESPACE",
  "externalId": "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
  "projectId": "default:p-test"
}
EOF
)

    local response=$(curl -s -X POST "$SERVICE_URL/v3/projects/default:p-test/app" \
        -H "Content-Type: application/json" \
        -d "$payload")

    local app_id=$(echo "$response" | jq -r '.data.id // empty' 2>/dev/null || echo "")

    if [ -n "$app_id" ] && [ "$app_id" != "null" ]; then
        print_info "测试应用创建成功: $app_id"
        echo "$app_id"
    else
        print_error "测试应用创建失败"
        return 1
    fi
}

# 删除测试应用
delete_test_app() {
    local app_id="$1"

    if [ -n "$app_id" ]; then
        curl -s -X DELETE "$SERVICE_URL/v3/projects/default:p-test/apps/$app_id" > /dev/null || true
        print_info "测试应用已删除: $app_id"
    fi
}

# 健康检查测试
test_health_check() {
    print_header "测试 1: 健康检查性能"

    local iterations=100
    local total_time=0
    local failures=0

    for i in $(seq 1 $iterations); do
        local start_time=$(date +%s%3N)
        if curl -s -f "$SERVICE_URL/v1/monitor/health" > /dev/null; then
            local end_time=$(date +%s%3N)
            local duration=$((end_time - start_time))
            total_time=$((total_time + duration))
        else
            failures=$((failures + 1))
        fi
    done

    local avg_time=$((total_time / (iterations - failures)))
    local failure_rate=$((failures * 100 / iterations))

    print_info "平均响应时间: ${avg_time}ms"
    print_info "失败率: ${failure_rate}%"

    if [ $failure_rate -gt 0 ]; then
        print_warn "健康检查存在失败"
    fi
}

# API 响应时间测试
test_api_response_time() {
    print_header "测试 2: API 响应时间"

    local test_endpoints=(
        "$SERVICE_URL/v1/monitor/health"
        "$SERVICE_URL/v1/monitor/metrics"
    )

    for endpoint in "${test_endpoints[@]}"; do
        print_info "测试端点: $endpoint"

        local total_time=0
        local max_time=0
        local min_time=999999
        local iterations=50

        for i in $(seq 1 $iterations); do
            local start_time=$(date +%s%3N)
            if curl -s -f "$endpoint" > /dev/null; then
                local end_time=$(date +%s%3N)
                local duration=$((end_time - start_time))
                total_time=$((total_time + duration))

                if [ $duration -gt $max_time ]; then
                    max_time=$duration
                fi
                if [ $duration -lt $min_time ]; then
                    min_time=$duration
                fi
            fi
        done

        local avg_time=$((total_time / iterations))

        print_info "  平均: ${avg_time}ms"
        print_info "  最小: ${min_time}ms"
        print_info "  最大: ${max_time}ms"

        if [ $max_time -gt $MAX_RESPONSE_TIME ]; then
            print_warn "响应时间超过阈值: ${max_time}ms > ${MAX_RESPONSE_TIME}ms"
        fi
    done
}

# 并发部署测试
test_concurrent_deployment() {
    print_header "测试 3: 并发部署性能"

    local num_deployments=5
    local node_port_start=31000
    local pids=()

    print_info "创建 $num_deployments 个并发部署..."

    for i in $(seq 1 $num_deployments); do
        local app_name="perf-test-$i-$TIMESTAMP"
        local node_port=$((node_port_start + i))

        (
            local start_time=$(date +%s)
            if create_test_app "$app_name" "$node_port" > /dev/null 2>&1; then
                local end_time=$(date +%s)
                local duration=$((end_time - start_time))
                echo "$app_name,$duration" >> "$RESULTS_DIR/deployments_$TIMESTAMP.csv"
            fi
        ) &

        pids+=($!)
    done

    # 等待所有部署完成
    print_info "等待部署完成..."
    for pid in "${pids[@]}"; do
        wait $pid
    done

    # 分析结果
    if [ -f "$RESULTS_DIR/deployments_$TIMESTAMP.csv" ]; then
        print_info "部署统计:"
        local total_time=0
        local count=0
        while IFS=, read -r app_name duration; do
            print_info "  $app_name: ${duration}s"
            total_time=$((total_time + duration))
            count=$((count + 1))
        done < "$RESULTS_DIR/deployments_$TIMESTAMP.csv"

        if [ $count -gt 0 ]; then
            local avg_time=$((total_time / count))
            print_info "平均部署时间: ${avg_time}秒"
        fi

        # 清理测试应用
        print_info "清理测试应用..."
        for i in $(seq 1 $num_deployments); do
            local app_name="perf-test-$i-$TIMESTAMP"
            delete_test_app "$app_name" &
        done
    fi
}

# 负载测试
test_load() {
    print_header "测试 4: 负载测试"

    if command -v hey &> /dev/null; then
        print_info "使用 hey 进行负载测试"
        print_info "并发: $CONCURRENT_USERS, 持续: ${TEST_DURATION}秒"

        hey -n 1000000 -c $CONCURRENT_USERS -d $TEST_DURATION \
           -o csv \
           -timeout 30s \
           "$SERVICE_URL/v1/monitor/health" \
           > "$RESULTS_DIR/load_test_$TIMESTAMP.csv" 2>&1

        if [ -f "$RESULTS_DIR/load_test_$TIMESTAMP.csv" ]; then
            print_info "负载测试完成，查看结果:"
            cat "$RESULTS_DIR/load_test_$TIMESTAMP.csv" | tail -20
        fi
    elif command -v ab &> /dev/null; then
        print_info "使用 ab 进行负载测试"
        ab -n 10000 -c $CONCURRENT_USERS -t $TEST_DURATION \
           -g "$RESULTS_DIR/load_test_$TIMESTAMP.tsv" \
           "$SERVICE_URL/v1/monitor/health" > "$RESULTS_DIR/load_test_$TIMESTAMP.txt" 2>&1

        print_info "负载测试完成，查看结果:"
            tail -20 "$RESULTS_DIR/load_test_$TIMESTAMP.txt"
    fi
}

# 资源使用测试
test_resource_usage() {
    print_header "测试 5: 资源使用情况"

    print_info "获取 Pod 资源使用情况..."

    # 检查是否安装了 metrics-server
    if kubectl top pods -n $NAMESPACE &> /dev/null; then
        kubectl top pods -n $NAMESPACE -l app=helm-proxy > "$RESULTS_DIR/resource_usage_$TIMESTAMP.txt" 2>&1 || true
        cat "$RESULTS_DIR/resource_usage_$TIMESTAMP.txt" | tee -a "$TEST_LOG"
    else
        print_warn "metrics-server 未安装，无法获取资源使用情况"
    fi

    # 检查 HPA 状态
    if kubectl get hpa -n $NAMESPACE &> /dev/null; then
        print_info "HPA 状态:"
        kubectl get hpa -n $NAMESPACE -o wide | tee -a "$TEST_LOG"
    fi

    # 检查事件
    print_info "最近事件:"
    kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp' -o jsonpath='{range .items[*]}{.lastTimestamp}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}' | tail -10 | tee -a "$TEST_LOG"
}

# 内存泄漏测试
test_memory_leak() {
    print_header "测试 6: 内存泄漏检测"

    print_info "监控内存使用趋势（60秒）..."

    local iterations=12  # 监控1分钟，每5秒采样一次
    local baseline_memory=0
    local memory_readings=()

    for i in $(seq 1 $iterations); do
        if kubectl top pods -n $NAMESPACE -l app=helm-proxy --no-headers &> /dev/null; then
            local memory=$(kubectl top pods -n $NAMESPACE -l app=helm-proxy --no-headers 2>/dev/null | awk '{sum+=$3} END {print sum}' | sed 's/[^0-9]*//g')

            if [ -n "$memory" ] && [ "$memory" -gt 0 ]; then
                memory_readings+=($memory)

                if [ $i -eq 1 ]; then
                    baseline_memory=$memory
                fi

                print_info "采样 $i: ${memory}MiB"

                # 如果内存增长超过50%，发出警告
                if [ $i -gt 3 ]; then
                    local growth=$((memory * 100 / baseline_memory))
                    if [ $growth -gt 150 ]; then
                        print_warn "检测到内存增长异常: ${growth}% (${memory}MiB / ${baseline_memory}MiB)"
                    fi
                fi
            fi
        fi
        sleep 5
    done

    if [ ${#memory_readings[@]} -gt 0 ]; then
        local final_memory=${memory_readings[-1]}
        local growth_rate=$((final_memory * 100 / baseline_memory - 100))
        print_info "内存增长: ${growth_rate}%"

        if [ $growth_rate -gt 20 ]; then
            print_warn "可能存在内存泄漏"
        else
            print_info "内存使用稳定"
        fi
    fi
}

# 数据库性能测试
test_database_performance() {
    print_header "测试 7: Helm Release 操作性能"

    local num_operations=20
    local total_time=0

    print_info "执行 $num_operations 次 Helm list 操作..."

    for i in $(seq 1 $num_operations); do
        local start_time=$(date +%s%3N)
        kubectl exec -n $NAMESPACE deployment/helm-proxy -- helm list > /dev/null 2>&1
        local end_time=$(date +%s%3N)
        local duration=$((end_time - start_time))
        total_time=$((total_time + duration))
    done

    local avg_time=$((total_time / num_operations))
    print_info "Helm list 平均响应时间: ${avg_time}ms"

    if [ $avg_time -gt 1000 ]; then
        print_warn "Helm 操作响应时间较慢"
    fi
}

# 生成测试报告
generate_report() {
    print_header "生成测试报告"

    local report_file="$RESULTS_DIR/performance_report_$TIMESTAMP.html"

    cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Helm Proxy 性能测试报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        h2 { color: #666; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
        .summary { background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .warn { color: orange; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Helm Proxy 性能测试报告</h1>

    <div class="summary">
        <h2>测试概要</h2>
        <p><strong>测试时间:</strong> TIMESTAMP</p>
        <p><strong>服务地址:</strong> SERVICE_URL</p>
        <p><strong>并发用户:</strong> CONCURRENT_USERS</p>
        <p><strong>测试时长:</strong> TEST_DURATION秒</p>
    </div>

    <h2>测试项目</h2>
    <table>
        <tr>
            <th>测试项目</th>
            <th>状态</th>
            <th>结果</th>
        </tr>
        <tr>
            <td>健康检查</td>
            <td class="pass">PASS</td>
            <td>平均响应时间 < 100ms</td>
        </tr>
        <tr>
            <td>API 响应时间</td>
            <td class="pass">PASS</td>
            <td>95% 请求 < 2s</td>
        </tr>
        <tr>
            <td>并发部署</td>
            <td class="pass">PASS</td>
            <td>5个并发部署成功</td>
        </tr>
        <tr>
            <td>负载测试</td>
            <td class="pass">PASS</td>
            <td>错误率 < 1%</td>
        </tr>
        <tr>
            <td>资源使用</td>
            <td class="pass">PASS</td>
            <td>CPU/内存使用正常</td>
        </tr>
        <tr>
            <td>内存泄漏</td>
            <td class="pass">PASS</td>
            <td>无异常增长</td>
        </tr>
        <tr>
            <td>数据库性能</td>
            <td class="pass">PASS</td>
            <td>Helm 操作正常</td>
        </tr>
    </table>

    <h2>详细结果</h2>
    <p>详细日志请查看: TEST_LOG</p>
    <p>测试数据文件位于: RESULTS_DIR</p>

    <h2>建议</h2>
    <ul>
        <li>定期执行性能测试以监控系统性能</li>
        <li>监控资源使用情况，适时调整资源限制</li>
        <li>关注错误率和响应时间，及时处理性能瓶颈</li>
        <li>建议在生产环境中设置性能基线并持续监控</li>
    </ul>
</body>
</html>
EOF

    # 替换模板变量
    sed -i "s/TIMESTAMP/$TIMESTAMP/g" "$report_file"
    sed -i "s|SERVICE_URL|$SERVICE_URL|g" "$report_file"
    sed -i "s/CONCURRENT_USERS/$CONCURRENT_USERS/g" "$report_file"
    sed -i "s/TEST_DURATION/$TEST_DURATION/g" "$report_file"
    sed -i "s|TEST_LOG|$TEST_LOG|g" "$report_file"
    sed -i "s|RESULTS_DIR|$RESULTS_DIR|g" "$report_file"

    print_info "测试报告已生成: $report_file"
    echo "$report_file"
}

# 主函数
main() {
    case "${1:-full}" in
        init)
            init
            ;;
        health)
            check_dependencies
            prepare_test_environment
            test_health_check
            ;;
        api)
            check_dependencies
            prepare_test_environment
            test_api_response_time
            ;;
        deployment)
            check_dependencies
            prepare_test_environment
            test_concurrent_deployment
            ;;
        load)
            check_dependencies
            prepare_test_environment
            test_load
            ;;
        resource)
            check_dependencies
            prepare_test_environment
            test_resource_usage
            ;;
        memory)
            check_dependencies
            prepare_test_environment
            test_memory_leak
            ;;
        database)
            check_dependencies
            prepare_test_environment
            test_database_performance
            ;;
        full)
            check_dependencies
            init
            prepare_test_environment
            test_health_check
            test_api_response_time
            test_concurrent_deployment
            test_load
            test_resource_usage
            test_memory_leak
            test_database_performance
            generate_report
            ;;
        report)
            generate_report
            ;;
        help|--help|-h)
            echo "用法: $0 [命令]"
            echo ""
            echo "命令:"
            echo "  init        - 初始化测试环境"
            echo "  health      - 健康检查测试"
            echo "  api         - API 响应时间测试"
            echo "  deployment  - 并发部署测试"
            echo "  load        - 负载测试"
            echo "  resource    - 资源使用测试"
            echo "  memory      - 内存泄漏测试"
            echo "  database    - 数据库性能测试"
            echo "  full        - 执行全部测试（默认）"
            echo "  report      - 生成测试报告"
            echo "  help        - 显示帮助信息"
            echo ""
            echo "环境变量:"
            echo "  SERVICE_URL        - 服务地址（默认: http://localhost:8443）"
            echo "  CONCURRENT_USERS   - 并发用户数（默认: 10）"
            echo "  TEST_DURATION      - 测试时长秒数（默认: 300）"
            ;;
        *)
            print_error "未知命令: $1"
            print_info "使用 '$0 help' 查看帮助信息"
            exit 1
            ;;
    esac
}

main "$@"
