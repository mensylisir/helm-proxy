package core

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// WorkerPool 工作池
type WorkerPool struct {
	workers    []*Worker
	jobQueue   chan Job
	shutdown   chan struct{}
	shutdownWG sync.WaitGroup
	metrics    Metrics
	logger     *StructuredLogger
	config     *PoolConfig
}

// Worker 工作协程
type Worker struct {
	id   int
	pool *WorkerPool
	quit chan struct{}
}

// Job 任务接口
type Job interface {
	Execute(ctx context.Context) error
	GetName() string
}

// PoolConfig 连接池配置
type PoolConfig struct {
	MaxWorkers         int           `json:"max_workers"`
	MinWorkers         int           `json:"min_workers"`
	QueueSize          int           `json:"queue_size"`
	IdleTimeout        time.Duration `json:"idle_timeout"`
	WorkerTimeout      time.Duration `json:"worker_timeout"`
	EnableAutoScale    bool          `json:"enable_auto_scale"`
	ScaleUpThreshold   float64       `json:"scale_up_threshold"`
	ScaleDownThreshold float64       `json:"scale_down_threshold"`
	ScaleInterval      time.Duration `json:"scale_interval"`
}

// DefaultPoolConfig 默认连接池配置
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		MaxWorkers:         100,
		MinWorkers:         10,
		QueueSize:          1000,
		IdleTimeout:        5 * time.Minute,
		WorkerTimeout:      30 * time.Second,
		EnableAutoScale:    true,
		ScaleUpThreshold:   0.8,
		ScaleDownThreshold: 0.3,
		ScaleInterval:      30 * time.Second,
	}
}

// NewWorkerPool 创建工作池
func NewWorkerPool(config *PoolConfig, metrics Metrics, logger *StructuredLogger) *WorkerPool {
	pool := &WorkerPool{
		jobQueue: make(chan Job, config.QueueSize),
		shutdown: make(chan struct{}),
		config:   config,
		metrics:  metrics,
		logger:   logger,
	}

	// 启动最小工作协程数
	pool.startWorkers(config.MinWorkers)

	// 启动自动扩缩容
	if config.EnableAutoScale {
		pool.startAutoScaler()
	}

	return pool
}

// startWorkers 启动工作协程
func (p *WorkerPool) startWorkers(count int) {
	for i := 0; i < count; i++ {
		worker := &Worker{
			id:   i,
			pool: p,
			quit: make(chan struct{}),
		}

		p.workers = append(p.workers, worker)
		p.shutdownWG.Add(1)

		go worker.run()
	}
}

// run 工作协程运行
func (w *Worker) run() {
	defer w.pool.shutdownWG.Done()

	for {
		select {
		case job := <-w.pool.jobQueue:
			ctx, cancel := context.WithTimeout(context.Background(), w.pool.config.WorkerTimeout)
			start := time.Now()

			// 执行任务
			err := job.Execute(ctx)
			duration := time.Since(start)

			// 记录指标
			if w.pool.metrics != nil {
				w.pool.metrics.RecordOperation(job.GetName(), duration, err == nil)
			}

			// 记录日志
			if err != nil {
				w.pool.logger.WithField("job_name", job.GetName()).WithError(err).Error("任务执行失败")
			} else {
				w.pool.logger.WithField("job_name", job.GetName()).WithField("duration", duration).Debug("任务执行完成")
			}

			cancel()

		case <-w.quit:
			return
		}
	}
}

// Submit 提交任务
func (p *WorkerPool) Submit(job Job) error {
	select {
	case p.jobQueue <- job:
		return nil
	case <-p.shutdown:
		return ErrPoolShutdown
	default:
		return ErrPoolQueueFull
	}
}

// SubmitWithTimeout 提交任务（带超时）
func (p *WorkerPool) SubmitWithTimeout(job Job, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	select {
	case p.jobQueue <- job:
		return nil
	case <-ctx.Done():
		return ErrPoolTimeout
	case <-p.shutdown:
		return ErrPoolShutdown
	}
}

// GetStats 获取工作池统计
func (p *WorkerPool) GetStats() *PoolStats {
	return &PoolStats{
		TotalWorkers:     len(p.workers),
		QueueSize:        cap(p.jobQueue),
		QueueLength:      len(p.jobQueue),
		QueueUtilization: float64(len(p.jobQueue)) / float64(cap(p.jobQueue)),
	}
}

// startAutoScaler 启动自动扩缩容
func (p *WorkerPool) startAutoScaler() {
	go func() {
		ticker := time.NewTicker(p.config.ScaleInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				p.scale()
			case <-p.shutdown:
				return
			}
		}
	}()
}

// scale 自动扩缩容
func (p *WorkerPool) scale() {
	stats := p.GetStats()

	// 扩容
	if stats.QueueUtilization > p.config.ScaleUpThreshold &&
		len(p.workers) < p.config.MaxWorkers {

		newWorkers := min(5, p.config.MaxWorkers-len(p.workers))
		p.logger.WithField("new_workers", newWorkers).Info("扩容工作池")

		p.startWorkers(newWorkers)

		// 记录指标
		if p.metrics != nil {
			p.metrics.IncrementCounter("pool.scale_up")
		}
	}

	// 缩容
	if stats.QueueUtilization < p.config.ScaleDownThreshold &&
		len(p.workers) > p.config.MinWorkers {

		// 这里可以添加缩容逻辑
		// 暂时不实现，因为Go的GC会自动处理空闲的协程
	}
}

// Shutdown 关闭工作池
func (p *WorkerPool) Shutdown(timeout time.Duration) error {
	close(p.shutdown)

	// 等待所有工作协程结束
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.shutdownWG.Wait()
	}()

	select {
	case <-done:
		p.logger.Info("工作池已关闭")
		return nil
	case <-time.After(timeout):
		return ErrPoolShutdownTimeout
	}
}

// Close 关闭工作池
func (p *WorkerPool) Close() {
	close(p.shutdown)
	p.shutdownWG.Wait()
}

// PoolStats 连接池统计
type PoolStats struct {
	TotalWorkers     int     `json:"total_workers"`
	QueueSize        int     `json:"queue_size"`
	QueueLength      int     `json:"queue_length"`
	QueueUtilization float64 `json:"queue_utilization"`
}

// RateLimiter 限流器
type RateLimiter struct {
	tokens     chan struct{}
	mu         sync.Mutex
	capacity   int
	rate       time.Duration
	lastRefill time.Time
	available  int
}

// NewRateLimiter 创建限流器
func NewRateLimiter(rps int, burst int) *RateLimiter {
	rl := &RateLimiter{
		capacity:   burst,
		rate:       time.Second / time.Duration(rps),
		lastRefill: time.Now(),
		available:  burst,
		tokens:     make(chan struct{}, burst),
	}

	// 填充令牌桶
	for i := 0; i < burst; i++ {
		rl.tokens <- struct{}{}
	}

	return rl
}

// Allow 允许请求
func (rl *RateLimiter) Allow() bool {
	select {
	case <-rl.tokens:
		return true
	default:
		return false
	}
}

// Wait 等待令牌
func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ErrRateLimitExceeded
	}
}

// ResourcePool 资源池
type ResourcePool struct {
	mu           sync.RWMutex
	resources    map[string]*PooledResource
	maxResources int
	metrics      Metrics
	logger       *StructuredLogger
}

// PooledResource 池化资源
type PooledResource struct {
	ID        string
	Resource  interface{}
	InUse     bool
	CreatedAt time.Time
	LastUsed  time.Time
	mu        sync.RWMutex
}

// NewResourcePool 创建资源池
func NewResourcePool(maxResources int, metrics Metrics, logger *StructuredLogger) *ResourcePool {
	return &ResourcePool{
		resources:    make(map[string]*PooledResource),
		maxResources: maxResources,
		metrics:      metrics,
		logger:       logger,
	}
}

// Acquire 获取资源
func (rp *ResourcePool) Acquire(id string) (*PooledResource, error) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	// 尝试获取现有资源
	if resource, exists := rp.resources[id]; exists {
		resource.mu.Lock()
		defer resource.mu.Unlock()

		if !resource.InUse {
			resource.InUse = true
			resource.LastUsed = time.Now()
			return resource, nil
		}
	}

	// 检查是否达到最大资源数
	if len(rp.resources) >= rp.maxResources {
		return nil, ErrResourcePoolExhausted
	}

	// 创建新资源
	resource := &PooledResource{
		ID:        id,
		Resource:  make(map[string]interface{}), // 简化实现
		InUse:     true,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	rp.resources[id] = resource

	// 记录指标
	if rp.metrics != nil {
		rp.metrics.RecordGauge("resource_pool.active", float64(len(rp.resources)))
	}

	rp.logger.WithField("resource_id", id).Debug("创建新资源")

	return resource, nil
}

// Release 释放资源
func (rp *ResourcePool) Release(id string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if resource, exists := rp.resources[id]; exists {
		resource.mu.Lock()
		defer resource.mu.Unlock()

		resource.InUse = false
		resource.LastUsed = time.Now()

		rp.logger.WithField("resource_id", id).Debug("释放资源")
	}
}

// GetStats 获取资源池统计
func (rp *ResourcePool) GetStats() *ResourcePoolStats {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	activeCount := 0
	for _, resource := range rp.resources {
		resource.mu.RLock()
		if resource.InUse {
			activeCount++
		}
		resource.mu.RUnlock()
	}

	return &ResourcePoolStats{
		TotalResources:     len(rp.resources),
		ActiveResources:    activeCount,
		AvailableResources: len(rp.resources) - activeCount,
		MaxResources:       rp.maxResources,
		Utilization:        float64(len(rp.resources)) / float64(rp.maxResources),
	}
}

// ResourcePoolStats 资源池统计
type ResourcePoolStats struct {
	TotalResources     int     `json:"total_resources"`
	ActiveResources    int     `json:"active_resources"`
	AvailableResources int     `json:"available_resources"`
	MaxResources       int     `json:"max_resources"`
	Utilization        float64 `json:"utilization"`
}

// CircuitBreaker 熔断器
type CircuitBreaker struct {
	state            atomic.Int32
	failureThreshold int
	recoveryTimeout  time.Duration
	failureCount     atomic.Int32
	lastFailureTime  atomic.Value
	lastSuccessTime  atomic.Value
	mu               sync.RWMutex
}

// CircuitBreakerState 熔断器状态
type CircuitBreakerState int32

const (
	StateClosed CircuitBreakerState = iota
	StateOpen
	StateHalfOpen
)

// NewCircuitBreaker 创建熔断器
func NewCircuitBreaker(failureThreshold int, recoveryTimeout time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{
		failureThreshold: failureThreshold,
		recoveryTimeout:  recoveryTimeout,
	}

	cb.state.Store(int32(StateClosed))
	cb.lastFailureTime.Store(time.Time{})
	cb.lastSuccessTime.Store(time.Now())

	return cb
}

// Allow 允许请求
func (cb *CircuitBreaker) Allow() bool {
	state := CircuitBreakerState(cb.state.Load())

	switch state {
	case StateClosed:
		return true
	case StateOpen:
		// 检查是否可以转换到半开状态
		lastFailure := cb.lastFailureTime.Load().(time.Time)
		if time.Since(lastFailure) > cb.recoveryTimeout {
			cb.state.Store(int32(StateHalfOpen))
			return true
		}
		return false
	case StateHalfOpen:
		return true
	default:
		return false
	}
}

// OnSuccess 记录成功
func (cb *CircuitBreaker) OnSuccess() {
	state := CircuitBreakerState(cb.state.Load())

	if state == StateHalfOpen {
		// 转换到关闭状态
		cb.state.Store(int32(StateClosed))
		cb.failureCount.Store(0)
	}

	cb.lastSuccessTime.Store(time.Now())
}

// OnFailure 记录失败
func (cb *CircuitBreaker) OnFailure() {
	state := CircuitBreakerState(cb.state.Load())

	cb.failureCount.Add(1)
	cb.lastFailureTime.Store(time.Now())

	if state == StateClosed && cb.failureCount.Load() >= int32(cb.failureThreshold) {
		// 转换到打开状态
		cb.state.Store(int32(StateOpen))
	}
}

// GetState 获取熔断器状态
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	return CircuitBreakerState(cb.state.Load())
}

// GetStats 获取熔断器统计
func (cb *CircuitBreaker) GetStats() *CircuitBreakerStats {
	return &CircuitBreakerStats{
		State:        cb.GetState(),
		FailureCount: int(cb.failureCount.Load()),
		LastFailure:  cb.lastFailureTime.Load().(time.Time),
		LastSuccess:  cb.lastSuccessTime.Load().(time.Time),
	}
}

// CircuitBreakerStats 熔断器统计
type CircuitBreakerStats struct {
	State        CircuitBreakerState `json:"state"`
	FailureCount int                 `json:"failure_count"`
	LastFailure  time.Time           `json:"last_failure"`
	LastSuccess  time.Time           `json:"last_success"`
}

// 错误定义
var (
	ErrPoolShutdown          = NewAppError(ErrorTypeSystem, "POOL_SHUTDOWN", "连接池已关闭", nil)
	ErrPoolQueueFull         = NewAppError(ErrorTypeSystem, "POOL_QUEUE_FULL", "连接池队列已满", nil)
	ErrPoolTimeout           = NewAppError(ErrorTypeSystem, "POOL_TIMEOUT", "连接池操作超时", nil)
	ErrPoolShutdownTimeout   = NewAppError(ErrorTypeSystem, "POOL_SHUTDOWN_TIMEOUT", "连接池关闭超时", nil)
	ErrRateLimitExceeded     = NewAppError(ErrorTypeSystem, "RATE_LIMIT_EXCEEDED", "超出速率限制", nil)
	ErrResourcePoolExhausted = NewAppError(ErrorTypeSystem, "RESOURCE_POOL_EXHAUSTED", "资源池已耗尽", nil)
)

// min 函数辅助
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
