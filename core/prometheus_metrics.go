package core

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PrometheusMetrics Prometheus 指标收集器
type PrometheusMetrics struct {
	// HTTP 请求指标
	HttpRequestsTotal    prometheus.CounterVec
	HttpRequestDuration  prometheus.HistogramVec
	HttpRequestsInFlight prometheus.GaugeVec

	// Helm 操作指标
	HelmOperationsTotal      prometheus.CounterVec
	HelmOperationDuration    prometheus.HistogramVec
	HelmOperationsInFlight   prometheus.GaugeVec
	HelmOperationFailures    prometheus.CounterVec

	// 部署指标
	DeploymentsTotal          prometheus.CounterVec
	DeploymentDuration        prometheus.HistogramVec
	DeploymentFailures        prometheus.CounterVec
	ActiveDeployments         prometheus.GaugeVec
	DeploymentRetries         prometheus.CounterVec
	DeploymentRollbacks       prometheus.CounterVec

	// 缓存指标
	ChartCacheHits        prometheus.CounterVec
	ChartCacheMisses      prometheus.CounterVec
	ChartCacheEvictions   prometheus.CounterVec
	ChartCacheSize        prometheus.GaugeVec
	RepoCacheRefreshes    prometheus.CounterVec
	RepoCacheRefreshTime  prometheus.HistogramVec

	// Kubernetes 资源指标
	K8sResourceOperations prometheus.CounterVec
	K8sResourceDuration   prometheus.HistogramVec

	// 健康检查指标
	HealthCheckTotal      prometheus.CounterVec
	HealthCheckDuration   prometheus.HistogramVec
	HealthCheckFailures   prometheus.CounterVec

	// 系统资源指标
	MemoryUsageBytes prometheus.GaugeVec
	CPUUsagePercent  prometheus.GaugeVec
	Goroutines       prometheus.Gauge

	// 限流指标
	RateLimitHits     prometheus.CounterVec
	RateLimitWaitTime prometheus.HistogramVec

	// 自定义业务指标
	CustomOperationsTotal   prometheus.CounterVec
	CustomOperationDuration prometheus.HistogramVec

	// 重试指标
	RetryTotal         prometheus.CounterVec
	RetryDuration      prometheus.HistogramVec
	RetryFailures      prometheus.CounterVec
	CircuitBreakerState prometheus.GaugeVec
	RetryDelay         prometheus.HistogramVec
}

// 全局 Prometheus 指标实例
var (
	PromMetrics *PrometheusMetrics
	promOnce    sync.Once
)

// NewPrometheusMetrics 创建 Prometheus 指标收集器
func NewPrometheusMetrics() *PrometheusMetrics {
	namespace := "helm_proxy"

	return &PrometheusMetrics{
		// HTTP 请求指标
		HttpRequestsTotal: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "http_requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{"method", "endpoint", "status_code"},
		),
		HttpRequestDuration: *promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "http_request_duration_seconds",
				Help:      "Duration of HTTP requests",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"method", "endpoint"},
		),
		HttpRequestsInFlight: *promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "http_requests_in_flight",
				Help:      "Current number of HTTP requests in flight",
			},
			[]string{"method", "endpoint"},
		),

		// Helm 操作指标
		HelmOperationsTotal: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "helm_operations_total",
				Help:      "Total number of Helm operations",
			},
			[]string{"operation", "status"},
		),
		HelmOperationDuration: *promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "helm_operation_duration_seconds",
				Help:      "Duration of Helm operations",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"operation"},
		),
		HelmOperationsInFlight: *promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "helm_operations_in_flight",
				Help:      "Current number of Helm operations in flight",
			},
			[]string{"operation"},
		),
		HelmOperationFailures: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "helm_operation_failures_total",
				Help:      "Total number of Helm operation failures",
			},
			[]string{"operation", "error_type"},
		),

		// 部署指标
		DeploymentsTotal: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "deployments_total",
				Help:      "Total number of deployments",
			},
			[]string{"namespace", "chart", "status"},
		),
		DeploymentDuration: *promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "deployment_duration_seconds",
				Help:      "Duration of deployments",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"namespace", "chart"},
		),
		DeploymentFailures: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "deployment_failures_total",
				Help:      "Total number of deployment failures",
			},
			[]string{"namespace", "chart", "failure_reason"},
		),
		ActiveDeployments: *promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "active_deployments",
				Help:      "Current number of active deployments",
			},
			[]string{"namespace"},
		),
		DeploymentRetries: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "deployment_retries_total",
				Help:      "Total number of deployment retries",
			},
			[]string{"namespace", "chart"},
		),
		DeploymentRollbacks: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "deployment_rollbacks_total",
				Help:      "Total number of deployment rollbacks",
			},
			[]string{"namespace", "chart"},
		),

		// 缓存指标
		ChartCacheHits: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "chart_cache_hits_total",
				Help:      "Total number of chart cache hits",
			},
			[]string{"chart"},
		),
		ChartCacheMisses: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "chart_cache_misses_total",
				Help:      "Total number of chart cache misses",
			},
			[]string{"chart"},
		),
		ChartCacheEvictions: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "chart_cache_evictions_total",
				Help:      "Total number of chart cache evictions",
			},
			[]string{"chart"},
		),
		ChartCacheSize: *promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "chart_cache_size",
				Help:      "Current size of chart cache",
			},
			[]string{},
		),
		RepoCacheRefreshes: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "repo_cache_refreshes_total",
				Help:      "Total number of repository cache refreshes",
			},
			[]string{"repo"},
		),
		RepoCacheRefreshTime: *promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "repo_cache_refresh_duration_seconds",
				Help:      "Duration of repository cache refreshes",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"repo"},
		),

		// Kubernetes 资源指标
		K8sResourceOperations: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "k8s_resource_operations_total",
				Help:      "Total number of Kubernetes resource operations",
			},
			[]string{"resource_type", "operation", "status"},
		),
		K8sResourceDuration: *promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "k8s_resource_operation_duration_seconds",
				Help:      "Duration of Kubernetes resource operations",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"resource_type", "operation"},
		),

		// 健康检查指标
		HealthCheckTotal: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "health_checks_total",
				Help:      "Total number of health checks",
			},
			[]string{"check_type", "status"},
		),
		HealthCheckDuration: *promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "health_check_duration_seconds",
				Help:      "Duration of health checks",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"check_type"},
		),
		HealthCheckFailures: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "health_check_failures_total",
				Help:      "Total number of health check failures",
			},
			[]string{"check_type", "error"},
		),

		// 系统资源指标
		MemoryUsageBytes: *promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "memory_usage_bytes",
				Help:      "Memory usage in bytes",
			},
			[]string{"type"},
		),
		CPUUsagePercent: *promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "cpu_usage_percent",
				Help:      "CPU usage percentage",
			},
			[]string{},
		),
		Goroutines: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "goroutines_total",
				Help:      "Total number of goroutines",
			},
		),

		// 限流指标
		RateLimitHits: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "rate_limit_hits_total",
				Help:      "Total number of rate limit hits",
			},
			[]string{"type"},
		),
		RateLimitWaitTime: *promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "rate_limit_wait_time_seconds",
				Help:      "Wait time due to rate limiting",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"type"},
		),

		// 自定义业务指标
		CustomOperationsTotal: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "custom_operations_total",
				Help:      "Total number of custom operations",
			},
			[]string{"operation", "status"},
		),
		CustomOperationDuration: *promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "custom_operation_duration_seconds",
				Help:      "Duration of custom operations",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"operation"},
		),

		// 重试指标
		RetryTotal: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "retry_total",
				Help:      "Total number of retry attempts",
			},
			[]string{"operation", "status"},
		),
		RetryDuration: *promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "retry_duration_seconds",
				Help:      "Duration of retry operations",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"operation"},
		),
		RetryFailures: *promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "retry_failures_total",
				Help:      "Total number of retry failures by error category",
			},
			[]string{"operation", "error_category"},
		),
		CircuitBreakerState: *promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "circuit_breaker_state",
				Help:      "Circuit breaker state (0=closed, 1=open, 2=half-open)",
			},
			[]string{"operation"},
		),
		RetryDelay: *promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "retry_delay_seconds",
				Help:      "Delay between retry attempts",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"operation", "attempt"},
		),
	}
}

// GetPrometheusMetrics 获取 Prometheus 指标实例
func GetPrometheusMetrics() *PrometheusMetrics {
	promOnce.Do(func() {
		PromMetrics = NewPrometheusMetrics()
	})
	return PromMetrics
}

// 指标记录辅助函数

// RecordHttpRequest 记录 HTTP 请求
func (m *PrometheusMetrics) RecordHttpRequest(method, endpoint string, duration time.Duration, statusCode int) {
	m.HttpRequestsTotal.WithLabelValues(method, endpoint, strconv.Itoa(statusCode)).Inc()
	m.HttpRequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// RecordHelmOperation 记录 Helm 操作
func (m *PrometheusMetrics) RecordHelmOperation(operation, status string, duration time.Duration) {
	m.HelmOperationsTotal.WithLabelValues(operation, status).Inc()
	m.HelmOperationDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// RecordHelmOperationStart 开始 Helm 操作
func (m *PrometheusMetrics) RecordHelmOperationStart(operation string) {
	m.HelmOperationsInFlight.WithLabelValues(operation).Inc()
}

// RecordHelmOperationEnd 结束 Helm 操作
func (m *PrometheusMetrics) RecordHelmOperationEnd(operation string) {
	m.HelmOperationsInFlight.WithLabelValues(operation).Dec()
}

// RecordHelmFailure 记录 Helm 操作失败
func (m *PrometheusMetrics) RecordHelmFailure(operation, errorType string) {
	m.HelmOperationFailures.WithLabelValues(operation, errorType).Inc()
}

// RecordDeployment 记录部署
func (m *PrometheusMetrics) RecordDeployment(namespace, chart, status string, duration time.Duration) {
	m.DeploymentsTotal.WithLabelValues(namespace, chart, status).Inc()
	m.DeploymentDuration.WithLabelValues(namespace, chart).Observe(duration.Seconds())

	if status == "active" {
		m.ActiveDeployments.WithLabelValues(namespace).Inc()
	}
}

// RecordDeploymentFailure 记录部署失败
func (m *PrometheusMetrics) RecordDeploymentFailure(namespace, chart, failureReason string) {
	m.DeploymentFailures.WithLabelValues(namespace, chart, failureReason).Inc()
}

// RecordDeploymentRetry 记录部署重试
func (m *PrometheusMetrics) RecordDeploymentRetry(namespace, chart string) {
	m.DeploymentRetries.WithLabelValues(namespace, chart).Inc()
}

// RecordDeploymentRollback 记录部署回滚
func (m *PrometheusMetrics) RecordDeploymentRollback(namespace, chart string) {
	m.DeploymentRollbacks.WithLabelValues(namespace, chart).Inc()
}

// RecordChartCacheHit 记录 Chart 缓存命中
func (m *PrometheusMetrics) RecordChartCacheHit(chart string) {
	m.ChartCacheHits.WithLabelValues(chart).Inc()
}

// RecordChartCacheMiss 记录 Chart 缓存未命中
func (m *PrometheusMetrics) RecordChartCacheMiss(chart string) {
	m.ChartCacheMisses.WithLabelValues(chart).Inc()
}

// RecordChartCacheEviction 记录 Chart 缓存驱逐
func (m *PrometheusMetrics) RecordChartCacheEviction(chart string) {
	m.ChartCacheEvictions.WithLabelValues(chart).Inc()
}

// SetChartCacheSize 设置 Chart 缓存大小
func (m *PrometheusMetrics) SetChartCacheSize(size int64) {
	m.ChartCacheSize.WithLabelValues().Set(float64(size))
}

// RecordRepoCacheRefresh 记录仓库缓存刷新
func (m *PrometheusMetrics) RecordRepoCacheRefresh(repo string, duration time.Duration) {
	m.RepoCacheRefreshes.WithLabelValues(repo).Inc()
	m.RepoCacheRefreshTime.WithLabelValues(repo).Observe(duration.Seconds())
}

// RecordK8sResourceOperation 记录 Kubernetes 资源操作
func (m *PrometheusMetrics) RecordK8sResourceOperation(resourceType, operation, status string, duration time.Duration) {
	m.K8sResourceOperations.WithLabelValues(resourceType, operation, status).Inc()
	m.K8sResourceDuration.WithLabelValues(resourceType, operation).Observe(duration.Seconds())
}

// RecordHealthCheck 记录健康检查
func (m *PrometheusMetrics) RecordHealthCheck(checkType, status string, duration time.Duration) {
	m.HealthCheckTotal.WithLabelValues(checkType, status).Inc()
	m.HealthCheckDuration.WithLabelValues(checkType).Observe(duration.Seconds())
}

// RecordHealthCheckFailure 记录健康检查失败
func (m *PrometheusMetrics) RecordHealthCheckFailure(checkType, error string) {
	m.HealthCheckFailures.WithLabelValues(checkType, error).Inc()
}

// SetMemoryUsage 设置内存使用
func (m *PrometheusMetrics) SetMemoryUsage(memoryType string, bytes int64) {
	m.MemoryUsageBytes.WithLabelValues(memoryType).Set(float64(bytes))
}

// SetCPUUsage 设置 CPU 使用率
func (m *PrometheusMetrics) SetCPUUsage(percent float64) {
	m.CPUUsagePercent.WithLabelValues().Set(percent)
}

// SetGoroutines 设置协程数量
func (m *PrometheusMetrics) SetGoroutines(count int) {
	m.Goroutines.Set(float64(count))
}

// RecordRateLimitHit 记录限流命中
func (m *PrometheusMetrics) RecordRateLimitHit(rateLimitType string, waitTime time.Duration) {
	m.RateLimitHits.WithLabelValues(rateLimitType).Inc()
	m.RateLimitWaitTime.WithLabelValues(rateLimitType).Observe(waitTime.Seconds())
}

// RecordCustomOperation 记录自定义操作
func (m *PrometheusMetrics) RecordCustomOperation(operation, status string, duration time.Duration) {
	m.CustomOperationsTotal.WithLabelValues(operation, status).Inc()
	m.CustomOperationDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// RecordRetry 记录重试
func (m *PrometheusMetrics) RecordRetry(operation, status string, duration time.Duration) {
	m.RetryTotal.WithLabelValues(operation, status).Inc()
	m.RetryDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// RecordRetryFailure 记录重试失败
func (m *PrometheusMetrics) RecordRetryFailure(operation, errorCategory string) {
	m.RetryFailures.WithLabelValues(operation, errorCategory).Inc()
}

// RecordCircuitBreakerState 记录熔断器状态
func (m *PrometheusMetrics) RecordCircuitBreakerState(operation string, state int) {
	m.CircuitBreakerState.WithLabelValues(operation).Set(float64(state))
}

// RecordRetryDelay 记录重试延迟
func (m *PrometheusMetrics) RecordRetryDelay(operation string, attempt int, delay time.Duration) {
	m.RetryDelay.WithLabelValues(operation, fmt.Sprintf("%d", attempt)).Observe(delay.Seconds())
}
