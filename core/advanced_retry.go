package core

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// AdvancedRetryConfig 增强重试配置
type AdvancedRetryConfig struct {
	// 基础重试配置
	MaxAttempts    int                  `json:"max_attempts"`     // 最大重试次数
	InitialDelay   time.Duration        `json:"initial_delay"`    // 初始延迟
	MaxDelay       time.Duration        `json:"max_delay"`        // 最大延迟
	BackoffFactor  float64              `json:"backoff_factor"`   // 退避因子
	Jitter         bool                 `json:"jitter"`           // 是否启用抖动
	JitterFactor   float64              `json:"jitter_factor"`    // 抖动因子
	RetryableCodes []string             `json:"retryable_codes"`  // 可重试的错误码

	// 高级特性
	CircuitBreaker *CircuitBreakerConfig `json:"circuit_breaker"` // 熔断器配置
	RetryMetrics   bool                  `json:"retry_metrics"`   // 是否记录重试指标
	Timeout        time.Duration         `json:"timeout"`         // 总超时时间

	// 错误分类
	ErrorClassifier ErrorClassifier `json:"-"` // 错误分类器
}

// CircuitBreakerConfig 熔断器配置
type CircuitBreakerConfig struct {
	// 熔断器状态：Closed（关闭）、Open（开启）、Half-Open（半开）
	FailureThreshold  int           `json:"failure_threshold"`  // 失败阈值
	RecoveryTimeout   time.Duration `json:"recovery_timeout"`   // 恢复超时
	SuccessThreshold  int           `json:"success_threshold"`  // 成功阈值（半开状态）
	MonitoringWindow  time.Duration `json:"monitoring_window"`  // 监控窗口
}

// DefaultCircuitBreakerConfig 默认熔断器配置
var DefaultCircuitBreakerConfig = &CircuitBreakerConfig{
	FailureThreshold: 5,
	RecoveryTimeout:  time.Second * 30,
	SuccessThreshold: 3,
	MonitoringWindow: time.Second * 60,
}

// DefaultAdvancedRetryConfig 默认增强重试配置
var DefaultAdvancedRetryConfig = &AdvancedRetryConfig{
	MaxAttempts:   5,
	InitialDelay:  time.Second * 1,
	MaxDelay:      time.Second * 60,
	BackoffFactor: 2.0,
	Jitter:        true,
	JitterFactor:  0.1,
	RetryableCodes: []string{
		"HELM_TIMEOUT",
		"NETWORK_ERROR",
		"K8S_CONNECTION_ERROR",
		"CHART_DOWNLOAD_FAILED",
		"TEMPORARY_FAILURE",
	},
	CircuitBreaker: DefaultCircuitBreakerConfig,
	RetryMetrics:   true,
	Timeout:        time.Minute * 5,
	ErrorClassifier: &DefaultErrorClassifier{},
}

// ErrorClassifier 错误分类器接口
type ErrorClassifier interface {
	// ClassifyError 分类错误
	ClassifyError(err error) ErrorCategory
	// IsRetryable 判断错误是否可重试
	IsRetryable(err error) bool
	// GetRetryDelay 获取重试延迟
	GetRetryDelay(err error, attempt int, config *AdvancedRetryConfig) time.Duration
}

// ErrorCategory 错误类别
type ErrorCategory string

const (
	// 可重试的临时错误
	ErrorCategoryTransient ErrorCategory = "transient"
	// 不可重试的永久错误
	ErrorCategoryPermanent ErrorCategory = "permanent"
	// 业务逻辑错误
	ErrorCategoryBusiness ErrorCategory = "business"
	// 系统错误
	ErrorCategorySystem ErrorCategory = "system"
)

// DefaultErrorClassifier 默认错误分类器
type DefaultErrorClassifier struct{}

// ClassifyError 分类错误
func (c *DefaultErrorClassifier) ClassifyError(err error) ErrorCategory {
	if err == nil {
		return ErrorCategoryPermanent
	}

	errMsg := err.Error()

	// 临时错误（可重试）
	transientPatterns := []string{
		"timeout",
		"connection refused",
		"network unreachable",
		"temporary failure",
		"retry",
		"resource temporarily unavailable",
		"dial tcp",
		"dial udp",
	}

	for _, pattern := range transientPatterns {
		if containsString(errMsg, pattern) {
			return ErrorCategoryTransient
		}
	}

	// 业务逻辑错误（通常不可重试）
	businessPatterns := []string{
		"validation failed",
		"invalid parameter",
		"permission denied",
		"already exists",
		"not found",
		"conflict",
	}

	for _, pattern := range businessPatterns {
		if containsString(errMsg, pattern) {
			return ErrorCategoryBusiness
		}
	}

	// 系统错误（需要判断）
	systemPatterns := []string{
		"internal error",
		"system error",
		"out of memory",
		"disk full",
	}

	for _, pattern := range systemPatterns {
		if containsString(errMsg, pattern) {
			return ErrorCategorySystem
		}
	}

	// 默认分类为临时错误（保守策略）
	return ErrorCategoryTransient
}

// IsRetryable 判断错误是否可重试
func (c *DefaultErrorClassifier) IsRetryable(err error) bool {
	category := c.ClassifyError(err)
	return category == ErrorCategoryTransient
}

// GetRetryDelay 获取重试延迟
func (c *DefaultErrorClassifier) GetRetryDelay(err error, attempt int, config *AdvancedRetryConfig) time.Duration {
	// 基础指数退避
	delay := config.InitialDelay * time.Duration(math.Pow(config.BackoffFactor, float64(attempt-1)))

	// 限制最大延迟
	if delay > config.MaxDelay {
		delay = config.MaxDelay
	}

	// 添加抖动
	if config.Jitter {
		jitter := time.Duration(float64(delay) * config.JitterFactor * rand.Float64())
		delay = delay + jitter
	}

	return delay
}

// CircuitBreakerAdapter 熔断器适配器
type CircuitBreakerAdapter struct {
	cb       *CircuitBreaker
	config   *CircuitBreakerConfig
	mu       sync.RWMutex
	successes atomic.Int64
}

// NewCircuitBreakerAdapter 创建熔断器适配器
func NewCircuitBreakerAdapter(config *CircuitBreakerConfig) *CircuitBreakerAdapter {
	return &CircuitBreakerAdapter{
		cb:     NewCircuitBreaker(config.FailureThreshold, config.RecoveryTimeout),
		config: config,
	}
}

// AllowRequest 允许请求
func (cba *CircuitBreakerAdapter) AllowRequest() bool {
	return cba.cb.Allow()
}

// OnSuccess 记录成功
func (cba *CircuitBreakerAdapter) OnSuccess() {
	cba.cb.OnSuccess()

	// 记录成功计数
	cba.successes.Add(1)
}

// OnFailure 记录失败
func (cba *CircuitBreakerAdapter) OnFailure() {
	cba.cb.OnFailure()
}

// GetState 获取当前状态
func (cba *CircuitBreakerAdapter) GetState() CircuitBreakerState {
	return cba.cb.GetState()
}

// GetCircuitBreaker 获取底层熔断器
func (cba *CircuitBreakerAdapter) GetCircuitBreaker() *CircuitBreaker {
	return cba.cb
}

// RetryResult 重试结果
type RetryResult struct {
	Success      bool          `json:"success"`
	Attempts     int           `json:"attempts"`
	TotalDelay   time.Duration `json:"total_delay"`
	LastError    error         `json:"last_error,omitempty"`
	CircuitBreakerOpen bool    `json:"circuit_breaker_open"`
}

// ExecuteWithAdvancedRetry 执行增强重试
func ExecuteWithAdvancedRetry(
	ctx context.Context,
	operation string,
	fn func() error,
	config *AdvancedRetryConfig,
	logger *zap.Logger,
) (*RetryResult, error) {
	if config == nil {
		config = DefaultAdvancedRetryConfig
	}

	// 创建熔断器适配器
	circuitBreaker := NewCircuitBreakerAdapter(config.CircuitBreaker)
	promMetrics := GetPrometheusMetrics()

	startTime := time.Now()
	result := &RetryResult{
		Success: false,
	}

	var lastErr error
	attempts := 0
	totalDelay := time.Duration(0)

	for {
		attempts++

		// 检查熔断器
		if !circuitBreaker.AllowRequest() {
			result.CircuitBreakerOpen = true
			logger.Warn("Circuit breaker is open, rejecting request",
				zap.String("operation", operation),
				zap.Int("attempt", attempts))
			break
		}

		// 执行函数
		err := fn()

		if err == nil {
			// 成功
			result.Success = true
			result.Attempts = attempts
			result.TotalDelay = totalDelay
			circuitBreaker.OnSuccess()

			if config.RetryMetrics && attempts > 1 {
				promMetrics.RecordCustomOperation("retry", "success", time.Since(startTime))
			}

			logger.Info("Operation succeeded",
				zap.String("operation", operation),
				zap.Int("attempts", attempts),
				zap.Duration("total_delay", totalDelay))
			return result, nil
		}

		lastErr = err

		// 分类错误
		category := config.ErrorClassifier.ClassifyError(err)

		// 记录失败
		circuitBreaker.OnFailure()

		if config.RetryMetrics {
			promMetrics.RecordCustomOperation("retry", "failed", time.Since(startTime))
		}

		// 检查是否可重试
		if !config.ErrorClassifier.IsRetryable(err) {
			logger.Info("Operation failed with non-retryable error",
				zap.String("operation", operation),
				zap.String("category", string(category)),
				zap.Error(err))
			result.Attempts = attempts
			result.TotalDelay = totalDelay
			result.LastError = err
			return result, err
		}

		// 检查是否超过最大尝试次数
		if attempts >= config.MaxAttempts {
			logger.Warn("Operation failed after max attempts",
				zap.String("operation", operation),
				zap.Int("attempts", attempts),
				zap.Error(err))
			break
		}

		// 检查总超时
		if time.Since(startTime) > config.Timeout {
			logger.Warn("Operation timed out",
				zap.String("operation", operation),
				zap.Int("attempts", attempts),
				zap.Duration("elapsed", time.Since(startTime)),
				zap.Error(err))
			break
		}

		// 计算重试延迟
		delay := config.ErrorClassifier.GetRetryDelay(err, attempts, config)
		totalDelay += delay

		logger.Info("Retrying operation",
			zap.String("operation", operation),
			zap.Int("attempt", attempts),
			zap.String("category", string(category)),
			zap.Duration("delay", delay),
			zap.Error(err))

		// 等待或取消
		select {
		case <-ctx.Done():
			logger.Info("Operation cancelled during retry wait",
				zap.String("operation", operation),
				zap.Int("attempt", attempts))
			return result, ctx.Err()
		case <-time.After(delay):
		}
	}

	result.Attempts = attempts
	result.TotalDelay = totalDelay
	result.LastError = lastErr

	logger.Error("Operation failed after all retries",
		zap.String("operation", operation),
		zap.Int("attempts", attempts),
		zap.Duration("total_delay", totalDelay),
		zap.Error(lastErr))

	return result, lastErr
}

// ExecuteWithAdvancedRetryResult 执行增强重试并返回结果
func ExecuteWithAdvancedRetryResult[T any](
	ctx context.Context,
	operation string,
	fn func() (T, error),
	config *AdvancedRetryConfig,
	logger *zap.Logger,
) (T, *RetryResult, error) {
	if config == nil {
		config = DefaultAdvancedRetryConfig
	}

	var result T
	retryResult := &RetryResult{
		Success: false,
	}

	// 使用重试包装函数
	wrappedFn := func() error {
		val, err := fn()
		if err == nil {
			// 如果成功，将结果存储在外部变量中
			result = val
		}
		return err
	}

	retryRes, err := ExecuteWithAdvancedRetry(ctx, operation, wrappedFn, config, logger)
	retryResult = retryRes

	return result, retryResult, err
}

// 辅助函数
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		findInString(s, substr))))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
