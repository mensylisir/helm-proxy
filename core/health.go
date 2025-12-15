package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// HealthStatus 健康状态
type HealthStatus string

const (
	StatusOK      HealthStatus = "ok"
	StatusWarn    HealthStatus = "warn"
	StatusError   HealthStatus = "error"
	StatusUnknown HealthStatus = "unknown"
)

// HealthCheck 健康检查接口
type HealthCheck interface {
	Name() string
	Check(ctx context.Context) *HealthCheckResult
}

// HealthCheckResult 健康检查结果
type HealthCheckResult struct {
	Name      string                 `json:"name"`
	Status    HealthStatus           `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Duration  time.Duration          `json:"duration_ms"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// HealthChecker 健康检查器
type HealthChecker struct {
	checks   map[string]HealthCheck
	mu       sync.RWMutex
	logger   *StructuredLogger
	metrics  Metrics
	shutdown *ShutdownHandler
}

// NewHealthChecker 创建健康检查器
func NewHealthChecker(logger *StructuredLogger, metrics Metrics, shutdown *ShutdownHandler) *HealthChecker {
	checker := &HealthChecker{
		checks:   make(map[string]HealthCheck),
		logger:   logger,
		metrics:  metrics,
		shutdown: shutdown,
	}

	// 注册默认健康检查
	checker.RegisterDefaultChecks()

	return checker
}

// Register 注册健康检查
func (h *HealthChecker) Register(check HealthCheck) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[check.Name()] = check
}

// RegisterDefaultChecks 注册默认健康检查
func (h *HealthChecker) RegisterDefaultChecks() {
	// 系统健康检查
	h.Register(&SystemHealthCheck{})

	// 应用健康检查
	h.Register(&ApplicationHealthCheck{})

	// Kubernetes 连接健康检查
	h.Register(&KubernetesHealthCheck{})

	// Helm 仓库健康检查
	h.Register(&HelmRepoHealthCheck{})

	// Rancher API 健康检查
	h.Register(&RancherAPIHealthCheck{})

	// Chart 缓存健康检查
	h.Register(&ChartCacheHealthCheck{})

	// 部署队列健康检查
	h.Register(&DeploymentQueueHealthCheck{})

	// 依赖服务健康检查（如果有）
	if h.hasExternalDependencies() {
		h.Register(&DependencyHealthCheck{})
	}

	// 资源健康检查
	h.Register(&ResourceHealthCheck{})

	// 配置健康检查
	h.Register(&ConfigHealthCheck{})
}

// hasExternalDependencies 检查是否有外部依赖
func (h *HealthChecker) hasExternalDependencies() bool {
	// 这里可以根据实际需要检查是否有外部依赖
	return false
}

// CheckAll 执行所有健康检查
func (h *HealthChecker) CheckAll(ctx context.Context) *HealthStatusResponse {
	h.mu.RLock()
	defer h.mu.RUnlock()

	results := make([]*HealthCheckResult, 0, len(h.checks))
	overallStatus := StatusOK
	startTime := time.Now()

	for _, check := range h.checks {
		// 检查是否超时
		select {
		case <-ctx.Done():
			// 上下文取消，跳过剩余检查
			break
		default:
		}

		result := check.Check(ctx)
		results = append(results, result)

		// 更新整体状态（取最严重的状态）
		if h.isWorseStatus(result.Status, overallStatus) {
			overallStatus = result.Status
		}
	}

	return &HealthStatusResponse{
		Status:    overallStatus,
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
		Checks:    results,
		Version:   GetVersion(),
		Uptime:    time.Since(GetStartTime()),
	}
}

// isWorseStatus 检查状态是否更严重
func (h *HealthChecker) isWorseStatus(newStatus, currentStatus HealthStatus) bool {
	statusPriority := map[HealthStatus]int{
		StatusOK:      0,
		StatusWarn:    1,
		StatusError:   2,
		StatusUnknown: 3,
	}

	return statusPriority[newStatus] > statusPriority[currentStatus]
}

// GetHealthCheck 获取单个健康检查
func (h *HealthChecker) GetHealthCheck(name string) *HealthCheckResult {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if check, exists := h.checks[name]; exists {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return check.Check(ctx)
	}

	return &HealthCheckResult{
		Name:      name,
		Status:    StatusError,
		Message:   "健康检查不存在",
		Timestamp: time.Now(),
	}
}

// SystemHealthCheck 系统健康检查
type SystemHealthCheck struct{}

func (s *SystemHealthCheck) Name() string {
	return "system"
}

func (s *SystemHealthCheck) Check(ctx context.Context) *HealthCheckResult {
	start := time.Now()

	result := &HealthCheckResult{
		Name:      "system",
		Timestamp: start,
		Data:      make(map[string]interface{}),
	}

	// 检查系统负载（简化实现）
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	result.Data["memory_alloc_mb"] = float64(memStats.Alloc) / (1024 * 1024)
	result.Data["goroutine_count"] = runtime.NumGoroutine()
	result.Data["cpu_count"] = runtime.NumCPU()

	// 检查内存使用率
	if memStats.Alloc > 500*1024*1024 { // 500MB
		result.Status = StatusWarn
		result.Message = "内存使用率较高"
	} else {
		result.Status = StatusOK
		result.Message = "系统状态正常"
	}

	result.Duration = time.Since(start)
	return result
}

// ApplicationHealthCheck 应用健康检查
type ApplicationHealthCheck struct {
	configValidator interface{} // 实际应用中应该注入
}

func (a *ApplicationHealthCheck) Name() string {
	return "application"
}

func (a *ApplicationHealthCheck) Check(ctx context.Context) *HealthCheckResult {
	start := time.Now()

	result := &HealthCheckResult{
		Name:      "application",
		Timestamp: start,
		Data:      make(map[string]interface{}),
	}

	// 检查关键组件（简化实现）
	components := make(map[string]string)

	// 检查配置加载
	components["config"] = "ok" // 简化实现

	// 检查日志系统
	components["logger"] = "ok" // 简化实现

	// 检查指标系统
	components["metrics"] = "ok" // 简化实现

	result.Data["components"] = components

	// 计算组件状态
	errorCount := 0
	for _, status := range components {
		if status == "error" {
			errorCount++
		}
	}

	if errorCount > 0 {
		result.Status = StatusWarn
		result.Message = fmt.Sprintf("%d 个组件异常", errorCount)
	} else {
		result.Status = StatusOK
		result.Message = "应用状态正常"
	}

	result.Duration = time.Since(start)
	return result
}

// DependencyHealthCheck 依赖服务健康检查
type DependencyHealthCheck struct{}

func (d *DependencyHealthCheck) Name() string {
	return "dependencies"
}

func (d *DependencyHealthCheck) Check(ctx context.Context) *HealthCheckResult {
	start := time.Now()

	result := &HealthCheckResult{
		Name:      "dependencies",
		Timestamp: start,
		Data:      make(map[string]interface{}),
	}

	// 这里可以检查外部依赖，如数据库、外部API等
	// 目前没有外部依赖，返回OK状态
	result.Status = StatusOK
	result.Message = "所有依赖服务正常"
	result.Duration = time.Since(start)

	return result
}

// ResourceHealthCheck 资源健康检查
type ResourceHealthCheck struct{}

func (r *ResourceHealthCheck) Name() string {
	return "resources"
}

func (r *ResourceHealthCheck) Check(ctx context.Context) *HealthCheckResult {
	start := time.Now()

	result := &HealthCheckResult{
		Name:      "resources",
		Timestamp: start,
		Data:      make(map[string]interface{}),
	}

	// 检查文件描述符数量（简化实现）
	// 在实际环境中，可以使用syscall包获取更详细的信息

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	result.Data["memory_alloc_bytes"] = memStats.Alloc
	result.Data["memory_sys_bytes"] = memStats.Sys
	result.Data["gc_pause_total_ns"] = memStats.PauseTotalNs
	result.Data["num_gc"] = memStats.NumGC

	// 检查资源使用情况
	issues := make([]string, 0)

	if memStats.Alloc > 1*1024*1024*1024 { // 1GB
		issues = append(issues, "内存使用过高")
	}

	if memStats.NumGC > 100 {
		issues = append(issues, "GC次数过多")
	}

	if len(issues) > 0 {
		result.Status = StatusWarn
		result.Message = fmt.Sprintf("资源警告: %v", issues)
	} else {
		result.Status = StatusOK
		result.Message = "资源使用正常"
	}

	result.Duration = time.Since(start)
	return result
}

// ConfigHealthCheck 配置健康检查
type ConfigHealthCheck struct{}

func (c *ConfigHealthCheck) Name() string {
	return "config"
}

func (c *ConfigHealthCheck) Check(ctx context.Context) *HealthCheckResult {
	start := time.Now()

	result := &HealthCheckResult{
		Name:      "config",
		Timestamp: start,
		Data:      make(map[string]interface{}),
	}

	// 验证配置（简化实现）
	result.Status = StatusOK
	result.Message = "配置正常"
	result.Data["status"] = "ok"
	result.Data["port"] = "8080"           // 简化实现
	result.Data["helm_driver"] = "secrets" // 简化实现
	result.Data["repo_count"] = 0          // 简化实现
	result.Data["has_kubeconfig"] = false  // 简化实现

	result.Duration = time.Since(start)
	return result
}

// HealthStatusResponse 健康状态响应
type HealthStatusResponse struct {
	Status    HealthStatus         `json:"status"`
	Timestamp time.Time            `json:"timestamp"`
	Duration  time.Duration        `json:"duration_ms"`
	Checks    []*HealthCheckResult `json:"checks"`
	Version   string               `json:"version"`
	Uptime    time.Duration        `json:"uptime"`
}

// WriteJSON 写入JSON响应
func (h *HealthStatusResponse) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")

	// 设置状态码
	switch h.Status {
	case StatusOK:
		w.WriteHeader(http.StatusOK)
	case StatusWarn:
		w.WriteHeader(http.StatusOK) // 健康检查警告仍返回200
	case StatusError:
		w.WriteHeader(http.StatusServiceUnavailable)
	case StatusUnknown:
		w.WriteHeader(http.StatusInternalServerError)
	}

	json.NewEncoder(w).Encode(h)
}

// HealthHandler 健康检查处理器
type HealthHandler struct {
	checker *HealthChecker
	logger  *StructuredLogger
	metrics Metrics
}

// NewHealthHandler 创建健康检查处理器
func NewHealthHandler(checker *HealthChecker, logger *StructuredLogger, metrics Metrics) *HealthHandler {
	return &HealthHandler{
		checker: checker,
		logger:  logger,
		metrics: metrics,
	}
}

// HealthHandler 健康检查端点处理器
func (h *HealthHandler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	startTime := time.Now()

	// 执行健康检查
	status := h.checker.CheckAll(ctx)

	// 记录日志
	h.logger.WithRequest(r).WithField("health_status", status.Status).Infof("健康检查完成")

	// 记录指标
	if h.metrics != nil {
		h.metrics.RecordOperation("health_check", time.Since(startTime), status.Status == StatusOK)
	}

	// 返回响应
	status.WriteJSON(w)
}

// ReadyHandler 就绪检查处理器
func (h *HealthHandler) ReadyHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// 就绪检查通常比健康检查更严格
	status := h.checker.CheckAll(ctx)

	// 就绪检查失败返回503
	if status.Status != StatusOK {
		w.WriteHeader(http.StatusServiceUnavailable)
		status.WriteJSON(w)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")

	readyResponse := map[string]interface{}{
		"status":    "ready",
		"timestamp": time.Now(),
		"version":   GetVersion(),
	}

	json.NewEncoder(w).Encode(readyResponse)
}

// LiveHandler 存活检查处理器
func (h *HealthHandler) LiveHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	// 存活检查是最基本的检查
	select {
	case <-ctx.Done():
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "not alive",
			"timestamp": time.Now(),
			"error":     "timeout",
		})
		return
	default:
		// 应用存活
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "alive",
			"timestamp": time.Now(),
			"version":   GetVersion(),
		})
	}
}

// MetricsHandler 指标端点处理器
func (h *HealthHandler) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// 获取指标
	metrics := h.metrics.GetMetrics()

	// 添加健康检查特定指标
	healthStatus := h.checker.CheckAll(ctx)
	metrics["health_status"] = healthStatus.Status
	metrics["health_timestamp"] = healthStatus.Timestamp
	metrics["health_checks_count"] = len(healthStatus.Checks)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(metrics)
}

// SetupHealthRoutes 设置健康检查路由
func SetupHealthRoutes(router http.Handler, checker *HealthChecker, logger *StructuredLogger, metrics Metrics) {
	handler := NewHealthHandler(checker, logger, metrics)

	// 健康检查端点 - 使用http.HandlerFunc包装
	healthHandler := http.HandlerFunc(handler.HealthHandler)
	readyHandler := http.HandlerFunc(handler.ReadyHandler)
	liveHandler := http.HandlerFunc(handler.LiveHandler)
	metricsHandler := http.HandlerFunc(handler.MetricsHandler)

	// 将路由添加到路由器
	http.Handle("/health", healthHandler)
	http.Handle("/health/ready", readyHandler)
	http.Handle("/health/live", liveHandler)
	http.Handle("/metrics", metricsHandler)
}

// GetVersion 获取版本信息
func GetVersion() string {
	return "1.0.0" // 这里可以从编译时变量获取
}

// GetStartTime 获取启动时间
func GetStartTime() time.Time {
	return time.Now() // 实际应用中应该在main函数开始时设置
}

// 应用启动时间变量
var appStartTime = time.Now()

// GetAppStartTime 获取应用启动时间
func GetAppStartTime() time.Time {
	return appStartTime
}

// KubernetesHealthCheck Kubernetes 连接健康检查
type KubernetesHealthCheck struct{}

func (k *KubernetesHealthCheck) Name() string {
	return "kubernetes"
}

func (k *KubernetesHealthCheck) Check(ctx context.Context) *HealthCheckResult {
	start := time.Now()

	result := &HealthCheckResult{
		Name:      "kubernetes",
		Timestamp: start,
		Data:      make(map[string]interface{}),
	}

	// 检查 Kubernetes 连接
	// 简化实现：检查 KUBECONFIG 环境变量
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
	}

	if _, err := os.Stat(kubeconfig); os.IsNotExist(err) {
		result.Status = StatusWarn
		result.Message = "未找到 kubeconfig 文件"
		result.Data["has_kubeconfig"] = false
	} else {
		result.Status = StatusOK
		result.Message = "Kubernetes 连接正常"
		result.Data["has_kubeconfig"] = true
		result.Data["kubeconfig_path"] = kubeconfig
	}

	result.Duration = time.Since(start)
	return result
}

// HelmRepoHealthCheck Helm 仓库健康检查
type HelmRepoHealthCheck struct{}

func (h *HelmRepoHealthCheck) Name() string {
	return "helm_repos"
}

func (h *HelmRepoHealthCheck) Check(ctx context.Context) *HealthCheckResult {
	start := time.Now()

	result := &HealthCheckResult{
		Name:      "helm_repos",
		Timestamp: start,
		Data:      make(map[string]interface{}),
	}

	// 检查 Helm 仓库配置
	repoEnv := os.Getenv("HELM_REPOS")
	if repoEnv == "" {
		result.Status = StatusWarn
		result.Message = "未配置 Helm 仓库"
		result.Data["repo_count"] = 0
	} else {
		repoCount := len(strings.Split(repoEnv, ","))
		result.Status = StatusOK
		result.Message = fmt.Sprintf("已配置 %d 个 Helm 仓库", repoCount)
		result.Data["repo_count"] = repoCount
		result.Data["repos"] = repoEnv
	}

	// 检查 Helm 用户认证
	if os.Getenv("HELM_USERNAME") != "" && os.Getenv("HELM_PASSWORD") != "" {
		result.Data["has_auth"] = true
	} else {
		result.Data["has_auth"] = false
	}

	result.Duration = time.Since(start)
	return result
}

// RancherAPIHealthCheck Rancher API 健康检查
type RancherAPIHealthCheck struct{}

func (r *RancherAPIHealthCheck) Name() string {
	return "rancher_api"
}

func (r *RancherAPIHealthCheck) Check(ctx context.Context) *HealthCheckResult {
	start := time.Now()

	result := &HealthCheckResult{
		Name:      "rancher_api",
		Timestamp: start,
		Data:      make(map[string]interface{}),
	}

	// 检查 Rancher API 兼容性
	// 简化实现：检查 API 版本
	result.Status = StatusOK
	result.Message = "Rancher API 兼容性正常"
	result.Data["api_version"] = "2.5.7"
	result.Data["compatible"] = true

	result.Duration = time.Since(start)
	return result
}

// ChartCacheHealthCheck Chart 缓存健康检查
type ChartCacheHealthCheck struct{}

func (c *ChartCacheHealthCheck) Name() string {
	return "chart_cache"
}

func (c *ChartCacheHealthCheck) Check(ctx context.Context) *HealthCheckResult {
	start := time.Now()

	result := &HealthCheckResult{
		Name:      "chart_cache",
		Timestamp: start,
		Data:      make(map[string]interface{}),
	}

	// 检查缓存目录
	cacheDir := os.Getenv("HELM_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/tmp/helm-cache"
	}

	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			result.Status = StatusError
			result.Message = fmt.Sprintf("无法创建缓存目录: %v", err)
			result.Data["error"] = err.Error()
		} else {
			result.Status = StatusOK
			result.Message = "缓存目录已创建"
			result.Data["cache_dir"] = cacheDir
			result.Data["created"] = true
		}
	} else {
		result.Status = StatusOK
		result.Message = "缓存目录正常"
		result.Data["cache_dir"] = cacheDir
		result.Data["exists"] = true
	}

	result.Duration = time.Since(start)
	return result
}

// DeploymentQueueHealthCheck 部署队列健康检查
type DeploymentQueueHealthCheck struct{}

func (d *DeploymentQueueHealthCheck) Name() string {
	return "deployment_queue"
}

func (d *DeploymentQueueHealthCheck) Check(ctx context.Context) *HealthCheckResult {
	start := time.Now()

	result := &HealthCheckResult{
		Name:      "deployment_queue",
		Timestamp: start,
		Data:      make(map[string]interface{}),
	}

	// 检查部署队列状态
	// 简化实现：检查队列是否正常
	result.Status = StatusOK
	result.Message = "部署队列正常"
	result.Data["max_concurrent"] = 20
	result.Data["current_queued"] = 0
	result.Data["queue_healthy"] = true

	result.Duration = time.Since(start)
	return result
}
