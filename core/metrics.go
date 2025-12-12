package core

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// MetricsCollector 指标收集器
type MetricsCollector struct {
	mu           sync.RWMutex
	startTime    time.Time
	requestCount uint64
	errorCount   uint64

	// 请求持续时间直方图（简化版）
	requestDurations []float64

	// 操作统计
	operations map[string]*OperationMetrics

	// 资源使用统计
	resourceStats ResourceStats
}

// OperationMetrics 操作指标
type OperationMetrics struct {
	TotalCount    uint64        `json:"total_count"`
	SuccessCount  uint64        `json:"success_count"`
	ErrorCount    uint64        `json:"error_count"`
	TotalDuration time.Duration `json:"total_duration"`
	MinDuration   time.Duration `json:"min_duration"`
	MaxDuration   time.Duration `json:"max_duration"`

	// 最近请求时间
	LastRequestTime time.Time `json:"last_request_time"`
}

// ResourceStats 资源统计
type ResourceStats struct {
	MemoryUsage    int64        `json:"memory_usage_bytes"`
	CPUUsage       float64      `json:"cpu_usage_percent"`
	GoroutineCount int          `json:"goroutine_count"`
	OpenFDCount    int          `json:"open_fd_count"`
	NetworkStats   NetworkStats `json:"network_stats"`
	DiskStats      DiskStats    `json:"disk_stats"`
}

// NetworkStats 网络统计
type NetworkStats struct {
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
	PacketsSent   uint64 `json:"packets_sent"`
	PacketsRecv   uint64 `json:"packets_received"`
	ErrorsIn      uint64 `json:"errors_in"`
	ErrorsOut     uint64 `json:"errors_out"`
	DropIn        uint64 `json:"drop_in"`
	DropOut       uint64 `json:"drop_out"`
}

// DiskStats 磁盘统计
type DiskStats struct {
	ReadBytes  uint64 `json:"read_bytes"`
	WriteBytes uint64 `json:"write_bytes"`
	ReadCount  uint64 `json:"read_count"`
	WriteCount uint64 `json:"write_count"`
}

// Metrics 指标接口
type Metrics interface {
	// 计数器
	IncrementCounter(name string)
	AddCounter(name string, value uint64)

	// 测量值
	RecordGauge(name string, value float64)
	RecordOperation(operation string, duration time.Duration, success bool)

	// HTTP指标
	RecordRequest(method, path string, duration time.Duration, statusCode int)

	// 获取当前指标
	GetMetrics() map[string]interface{}

	// 获取特定指标
	GetCounter(name string) uint64
	GetGauge(name string) float64
	GetOperationMetrics(operation string) *OperationMetrics

	// 重置指标
	Reset()

	// 获取性能摘要
	GetPerformanceSummary() map[string]interface{}

	// 更新资源统计
	UpdateResourceStats()
}

// NewMetricsCollector 创建指标收集器
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		startTime:        time.Now(),
		requestDurations: make([]float64, 0),
		operations:       make(map[string]*OperationMetrics),
		resourceStats:    ResourceStats{},
	}
}

// 全局指标收集器
var (
	PerformanceMetrics Metrics
	metricsOnce        sync.Once
)

// GetPerformanceMetrics 获取性能指标实例
func GetPerformanceMetrics() Metrics {
	metricsOnce.Do(func() {
		PerformanceMetrics = NewMetricsCollector()
	})
	return PerformanceMetrics
}

// IncrementCounter 增加计数器
func (m *MetricsCollector) IncrementCounter(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch name {
	case "requests_total":
		atomic.AddUint64(&m.requestCount, 1)
	case "errors_total":
		atomic.AddUint64(&m.errorCount, 1)
	}
}

// AddCounter 添加计数器值
func (m *MetricsCollector) AddCounter(name string, value uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch name {
	case "requests_total":
		atomic.AddUint64(&m.requestCount, value)
	case "errors_total":
		atomic.AddUint64(&m.errorCount, value)
	}
}

// RecordGauge 记录测量值
func (m *MetricsCollector) RecordGauge(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 简化实现，实际中可以使用更复杂的数据结构
	switch name {
	case "memory_usage_bytes":
		m.resourceStats.MemoryUsage = int64(value)
	case "cpu_usage_percent":
		m.resourceStats.CPUUsage = value
	case "goroutine_count":
		m.resourceStats.GoroutineCount = int(value)
	case "open_fd_count":
		m.resourceStats.OpenFDCount = int(value)
	}
}

// RecordOperation 记录操作指标
func (m *MetricsCollector) RecordOperation(operation string, duration time.Duration, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.operations[operation]; !exists {
		m.operations[operation] = &OperationMetrics{
			MinDuration: duration,
			MaxDuration: duration,
		}
	}

	op := m.operations[operation]

	// 更新计数器
	atomic.AddUint64(&op.TotalCount, 1)
	if success {
		atomic.AddUint64(&op.SuccessCount, 1)
	} else {
		atomic.AddUint64(&op.ErrorCount, 1)
	}

	// 更新持续时间统计
	op.TotalDuration += duration
	if duration < op.MinDuration || op.MinDuration == 0 {
		op.MinDuration = duration
	}
	if duration > op.MaxDuration {
		op.MaxDuration = duration
	}

	op.LastRequestTime = time.Now()

	// 记录请求持续时间
	m.requestDurations = append(m.requestDurations, duration.Seconds()*1000) // 转换为毫秒

	// 限制数组大小以防止内存泄漏
	if len(m.requestDurations) > 1000 {
		m.requestDurations = m.requestDurations[1:]
	}
}

// RecordRequest 记录HTTP请求指标
func (m *MetricsCollector) RecordRequest(method, path string, duration time.Duration, statusCode int) {
	// 记录基本请求指标
	m.IncrementCounter("requests_total")

	// 记录持续时间
	operationName := method + "_" + path
	m.RecordOperation(operationName, duration, statusCode < 400)

	// 记录状态码指标
	statusCounter := "http_requests_status_" + string(rune(statusCode))
	m.AddCounter(statusCounter, 1)

	// 记录方法指标
	methodCounter := "http_requests_method_" + method
	m.AddCounter(methodCounter, 1)
}

// GetMetrics 获取所有指标
func (m *MetricsCollector) GetMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics := make(map[string]interface{})

	// 基本指标
	metrics["requests_total"] = atomic.LoadUint64(&m.requestCount)
	metrics["errors_total"] = atomic.LoadUint64(&m.errorCount)
	metrics["uptime_seconds"] = time.Since(m.startTime).Seconds()

	// 错误率
	if metrics["requests_total"].(uint64) > 0 {
		metrics["error_rate"] = float64(metrics["errors_total"].(uint64)) / float64(metrics["requests_total"].(uint64))
	} else {
		metrics["error_rate"] = 0.0
	}

	// 请求持续时间统计
	if len(m.requestDurations) > 0 {
		var total float64
		for _, duration := range m.requestDurations {
			total += duration
		}
		avg := total / float64(len(m.requestDurations))

		metrics["request_duration_avg_ms"] = avg
		metrics["request_duration_count"] = len(m.requestDurations)

		// 计算百分位数（简化）
		if len(m.requestDurations) >= 10 {
			p95 := int(float64(len(m.requestDurations)) * 0.95)
			p99 := int(float64(len(m.requestDurations)) * 0.99)
			metrics["request_duration_p95_ms"] = m.requestDurations[p95-1]
			metrics["request_duration_p99_ms"] = m.requestDurations[p99-1]
		}
	}

	// 操作指标
	operations := make(map[string]interface{})
	for name, op := range m.operations {
		opData := map[string]interface{}{
			"total_count":    atomic.LoadUint64(&op.TotalCount),
			"success_count":  atomic.LoadUint64(&op.SuccessCount),
			"error_count":    atomic.LoadUint64(&op.ErrorCount),
			"total_duration": op.TotalDuration.String(),
			"min_duration":   op.MinDuration.String(),
			"max_duration":   op.MaxDuration.String(),
			"last_request":   op.LastRequestTime.Format(time.RFC3339),
		}

		if op.TotalCount > 0 {
			opData["success_rate"] = float64(op.SuccessCount) / float64(op.TotalCount)
			opData["avg_duration"] = (op.TotalDuration / time.Duration(op.TotalCount)).String()
		}

		operations[name] = opData
	}
	metrics["operations"] = operations

	// 资源统计
	metrics["resources"] = m.resourceStats

	return metrics
}

// GetCounter 获取计数器值
func (m *MetricsCollector) GetCounter(name string) uint64 {
	switch name {
	case "requests_total":
		return atomic.LoadUint64(&m.requestCount)
	case "errors_total":
		return atomic.LoadUint64(&m.errorCount)
	default:
		return 0
	}
}

// GetGauge 获取测量值
func (m *MetricsCollector) GetGauge(name string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	switch name {
	case "memory_usage_bytes":
		return float64(m.resourceStats.MemoryUsage)
	case "cpu_usage_percent":
		return m.resourceStats.CPUUsage
	case "goroutine_count":
		return float64(m.resourceStats.GoroutineCount)
	case "open_fd_count":
		return float64(m.resourceStats.OpenFDCount)
	default:
		return 0.0
	}
}

// GetOperationMetrics 获取操作指标
func (m *MetricsCollector) GetOperationMetrics(operation string) *OperationMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if op, exists := m.operations[operation]; exists {
		// 返回副本以避免竞态条件
		return &OperationMetrics{
			TotalCount:      atomic.LoadUint64(&op.TotalCount),
			SuccessCount:    atomic.LoadUint64(&op.SuccessCount),
			ErrorCount:      atomic.LoadUint64(&op.ErrorCount),
			TotalDuration:   op.TotalDuration,
			MinDuration:     op.MinDuration,
			MaxDuration:     op.MaxDuration,
			LastRequestTime: op.LastRequestTime,
		}
	}

	return nil
}

// Reset 重置指标
func (m *MetricsCollector) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	atomic.StoreUint64(&m.requestCount, 0)
	atomic.StoreUint64(&m.errorCount, 0)
	m.requestDurations = m.requestDurations[:0]
	m.operations = make(map[string]*OperationMetrics)
	m.startTime = time.Now()
}

// GetPerformanceSummary 获取性能摘要
func (m *MetricsCollector) GetPerformanceSummary() map[string]interface{} {
	metrics := m.GetMetrics()

	summary := map[string]interface{}{
		"timestamp":      time.Now().Format(time.RFC3339),
		"uptime_seconds": metrics["uptime_seconds"],
		"total_requests": metrics["requests_total"],
		"total_errors":   metrics["errors_total"],
		"error_rate":     metrics["error_rate"],
	}

	if avg, ok := metrics["request_duration_avg_ms"]; ok {
		summary["avg_response_time_ms"] = avg
	}

	if p95, ok := metrics["request_duration_p95_ms"]; ok {
		summary["p95_response_time_ms"] = p95
	}

	if p99, ok := metrics["request_duration_p99_ms"]; ok {
		summary["p99_response_time_ms"] = p99
	}

	// 添加资源使用情况
	if resources, ok := metrics["resources"]; ok {
		if res, ok := resources.(ResourceStats); ok {
			summary["memory_usage_mb"] = float64(res.MemoryUsage) / (1024 * 1024)
			summary["cpu_usage_percent"] = res.CPUUsage
			summary["goroutine_count"] = res.GoroutineCount
		}
	}

	return summary
}

// UpdateResourceStats 更新资源统计
func (m *MetricsCollector) UpdateResourceStats() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 更新内存使用（简化实现）
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.resourceStats.MemoryUsage = int64(ms.Alloc)

	// 更新协程数量
	m.resourceStats.GoroutineCount = runtime.NumGoroutine()

	// 注意：这里可以添加更多系统指标收集逻辑
	// 例如CPU使用率、网络统计、磁盘使用等
}

// StartMetricsCollection 开始指标收集
func StartMetricsCollection(interval time.Duration) {
	metrics := GetPerformanceMetrics()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				metrics.UpdateResourceStats()
			}
		}
	}()
}
