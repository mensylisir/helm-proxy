package core

import (
	"fmt"
	"strings"
	"time"
)

// ErrorType 定义错误类型
type ErrorType string

const (
	ErrorTypeValidation ErrorType = "validation" // 验证错误
	ErrorTypeNetwork    ErrorType = "network"    // 网络错误
	ErrorTypeHelm       ErrorType = "helm"       // Helm操作错误
	ErrorTypeKube       ErrorType = "k8s"        // Kubernetes错误
	ErrorTypeSystem     ErrorType = "system"     // 系统错误
	ErrorTypeTimeout    ErrorType = "timeout"    // 超时错误
)

// AppError 自定义错误类型
type AppError struct {
	Type        ErrorType `json:"type"`
	Code        string    `json:"code"`
	Message     string    `json:"message"`
	Details     string    `json:"details,omitempty"`
	Cause       error     `json:"-"`
	Timestamp   time.Time `json:"timestamp"`
	OperationID string    `json:"operation_id,omitempty"`
	HTTPStatus  int       `json:"-"` // HTTP状态码，用于响应
}

// Error 实现error接口
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s:%s] %s: %v", e.Type, e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s:%s] %s", e.Type, e.Code, e.Message)
}

// Unwrap 返回原始错误
func (e *AppError) Unwrap() error {
	return e.Cause
}

// NewAppError 创建新的应用错误
func NewAppError(errorType ErrorType, code, message string, cause ...error) *AppError {
	err := &AppError{
		Type:       errorType,
		Code:       code,
		Message:    message,
		Timestamp:  time.Now(),
		HTTPStatus: getHTTPStatus(errorType),
	}
	if len(cause) > 0 && cause[0] != nil {
		err.Cause = cause[0]
	}
	return err
}

// getHTTPStatus 根据错误类型获取HTTP状态码
func getHTTPStatus(errorType ErrorType) int {
	switch errorType {
	case ErrorTypeValidation:
		return 400
	case ErrorTypeNetwork:
		return 503
	case ErrorTypeHelm, ErrorTypeKube:
		return 400
	case ErrorTypeSystem:
		return 500
	case ErrorTypeTimeout:
		return 408
	default:
		return 500
	}
}

// ValidationError 验证错误
func ValidationError(code, message string, cause ...error) *AppError {
	return NewAppError(ErrorTypeValidation, code, message, cause...)
}

// NetworkError 网络错误
func NetworkError(code, message string, cause ...error) *AppError {
	return NewAppError(ErrorTypeNetwork, code, message, cause...)
}

// HelmError Helm操作错误
func HelmError(code, message string, cause ...error) *AppError {
	return NewAppError(ErrorTypeHelm, code, message, cause...)
}

// KubeError Kubernetes错误
func KubeError(code, message string, cause ...error) *AppError {
	return NewAppError(ErrorTypeKube, code, message, cause...)
}

// SystemError 系统错误
func SystemError(code, message string, cause ...error) *AppError {
	return NewAppError(ErrorTypeSystem, code, message, cause...)
}

// TimeoutError 超时错误
func TimeoutError(code, message string, cause ...error) *AppError {
	return NewAppError(ErrorTypeTimeout, code, message, cause...)
}

// RetryConfig 重试配置
type RetryConfig struct {
	MaxAttempts    int           `json:"max_attempts"`    // 最大重试次数
	InitialDelay   time.Duration `json:"initial_delay"`   // 初始延迟
	MaxDelay       time.Duration `json:"max_delay"`       // 最大延迟
	BackoffFactor  float64       `json:"backoff_factor"`  // 退避因子
	RetryableCodes []string      `json:"retryable_codes"` // 可重试的错误码
}

// DefaultRetryConfig 默认重试配置
var DefaultRetryConfig = &RetryConfig{
	MaxAttempts:   3,
	InitialDelay:  time.Second * 1,
	MaxDelay:      time.Second * 30,
	BackoffFactor: 2.0,
	RetryableCodes: []string{
		"HELM_TIMEOUT",
		"NETWORK_ERROR",
		"K8S_CONNECTION_ERROR",
		"CHART_DOWNLOAD_FAILED",
	},
}

// RetryOption 重试配置选项
type RetryOption func(*RetryConfig)

// WithMaxAttempts 设置最大重试次数
func WithMaxAttempts(attempts int) RetryOption {
	return func(c *RetryConfig) {
		c.MaxAttempts = attempts
	}
}

// WithInitialDelay 设置初始延迟
func WithInitialDelay(delay time.Duration) RetryOption {
	return func(c *RetryConfig) {
		c.InitialDelay = delay
	}
}

// WithMaxDelay 设置最大延迟
func WithMaxDelay(delay time.Duration) RetryOption {
	return func(c *RetryConfig) {
		c.MaxDelay = delay
	}
}

// WithBackoffFactor 设置退避因子
func WithBackoffFactor(factor float64) RetryOption {
	return func(c *RetryConfig) {
		c.BackoffFactor = factor
	}
}

// WithRetryableCodes 设置可重试的错误码
func WithRetryableCodes(codes []string) RetryOption {
	return func(c *RetryConfig) {
		c.RetryableCodes = codes
	}
}

// IsRetryable 判断错误是否可重试
func IsRetryable(err error, config *RetryConfig) bool {
	if err == nil {
		return false
	}

	// 检查是否为AppError
	if appErr, ok := err.(*AppError); ok {
		for _, code := range config.RetryableCodes {
			if appErr.Code == code {
				return true
			}
		}
		return false
	}

	// 检查原始错误是否包含可重试的错误信息
	errMsg := strings.ToLower(err.Error())
	retryablePatterns := []string{
		"timeout",
		"connection refused",
		"network unreachable",
		"temporary failure",
		"retry",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(errMsg, pattern) {
			return true
		}
	}

	return false
}

// ExecuteWithRetry 执行函数并重试
func ExecuteWithRetry(operation string, fn func() error, options ...RetryOption) error {
	config := &RetryConfig{}
	*config = *DefaultRetryConfig

	// 应用配置选项
	for _, option := range options {
		option(config)
	}

	var lastErr error
	delay := config.InitialDelay

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		err := fn()
		if err == nil {
			return nil // 成功
		}

		lastErr = err

		// 如果是不可重试的错误，直接返回
		if !IsRetryable(err, config) {
			return err
		}

		// 如果是最后一次尝试，返回错误
		if attempt == config.MaxAttempts {
			break
		}

		// 记录重试信息
		if attempt > 1 {
			time.Sleep(delay)
			delay = time.Duration(float64(delay) * config.BackoffFactor)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		}
	}

	return lastErr
}

// ExecuteWithRetryResult 执行函数并重试，返回结果
func ExecuteWithRetryResult[T any](operation string, fn func() (T, error), options ...RetryOption) (T, error) {
	config := &RetryConfig{}
	*config = *DefaultRetryConfig

	// 应用配置选项
	for _, option := range options {
		option(config)
	}

	var lastErr error
	var result T
	delay := config.InitialDelay

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		val, err := fn()
		if err == nil {
			return val, nil // 成功
		}

		lastErr = err

		// 如果是不可重试的错误，直接返回
		if !IsRetryable(err, config) {
			return result, err
		}

		// 如果是最后一次尝试，返回错误
		if attempt == config.MaxAttempts {
			break
		}

		// 记录重试信息
		if attempt > 1 {
			time.Sleep(delay)
			delay = time.Duration(float64(delay) * config.BackoffFactor)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		}
	}

	return result, lastErr
}

// 统一响应结构体
// SuccessResponse 统一的成功响应结构体
type SuccessResponse struct {
	Success    bool        `json:"success"`
	Data       interface{} `json:"data"`
	Message    string      `json:"message,omitempty"`
	RequestID  string      `json:"requestId,omitempty"`
	Timestamp  time.Time   `json:"timestamp"`
	Path       string      `json:"path,omitempty"`
	Method     string      `json:"method,omitempty"`
	DurationMs int64       `json:"durationMs,omitempty"`
}

// ErrorResponse 统一的错误响应结构体
type ErrorResponse struct {
	Success   bool      `json:"success"`
	Error     *AppError `json:"error"`
	RequestID string    `json:"requestId,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Path      string    `json:"path,omitempty"`
	Method    string    `json:"method,omitempty"`
	DurationMs int64    `json:"durationMs,omitempty"`
}

// PaginatedResponse 分页响应结构体
type PaginatedResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data"`
	Pagination Pagination  `json:"pagination"`
	RequestID string      `json:"requestId,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	Path      string      `json:"path,omitempty"`
	Method    string      `json:"method,omitempty"`
	DurationMs int64      `json:"durationMs,omitempty"`
}

// Pagination 分页信息
type Pagination struct {
	Page       int   `json:"page"`
	PerPage    int   `json:"perPage"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"totalPages"`
	HasNext    bool  `json:"hasNext"`
	HasPrev    bool  `json:"hasPrev"`
}
