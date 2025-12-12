package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	
	"github.com/mensylisir/helm-proxy/core"
)

// RequestContext 请求上下文信息
type RequestContext struct {
	RequestID    string    `json:"request_id"`
	Timestamp    time.Time `json:"timestamp"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	ClientIP     string    `json:"client_ip"`
	UserAgent    string    `json:"user_agent"`
	ContentType  string    `json:"content_type"`
	ContentLength int64    `json:"content_length"`
	StatusCode   int       `json:"status_code"`
	Duration     int64     `json:"duration_ms"`
	ResponseSize int64     `json:"response_size"`
	Error        string    `json:"error,omitempty"`
}

// StructuredLogger 结构化日志中间件
func StructuredLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 生成请求ID
		requestID := GenerateRequestID()
		c.Set("request_id", requestID)
		
		// 记录请求开始时间
		startTime := time.Now()
		
		// 获取请求信息
		method := c.Request.Method
		path := c.Request.URL.Path
		clientIP := getClientIP(c)
		userAgent := c.Request.UserAgent()
		contentType := c.Request.Header.Get("Content-Type")
		contentLength := c.Request.ContentLength
		
		// 创建请求上下文
		reqCtx := RequestContext{
			RequestID:     requestID,
			Timestamp:     startTime,
			Method:        method,
			Path:          path,
			ClientIP:      clientIP,
			UserAgent:     userAgent,
			ContentType:   contentType,
			ContentLength: contentLength,
		}
		
		// 记录请求开始日志
		logger.Info("request_started",
			zap.String("request_id", requestID),
			zap.String("method", method),
			zap.String("path", path),
			zap.String("client_ip", clientIP),
			zap.String("user_agent", userAgent),
			zap.String("content_type", contentType),
			zap.Int64("content_length", contentLength),
		)
		
		// 复制请求体用于记录（限制大小）
		var requestBody string
		if c.Request.Body != nil && contentLength > 0 && contentLength <= 1024 {
			bodyBytes, _ := io.ReadAll(c.Request.Body)
			requestBody = string(bodyBytes)
			// 重新设置请求体
			c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		
		// 捕获响应
		c.Header("X-Request-ID", requestID)
		
		// 执行请求
		c.Next()
		
		// 计算处理时间
		duration := time.Since(startTime)
		durationMs := duration.Milliseconds()
		
		// 获取响应状态码和大小
		statusCode := c.Writer.Status()
		responseSize := int64(c.Writer.Size())
		
		// 记录请求结束日志
		reqCtx.StatusCode = statusCode
		reqCtx.Duration = durationMs
		reqCtx.ResponseSize = responseSize
		
		// 检查是否有错误
		if len(c.Errors) > 0 {
			reqCtx.Error = c.Errors.Last().Error()
		}
		
		// 构建日志字段
		logFields := []zap.Field{
			zap.String("request_id", requestID),
			zap.String("method", method),
			zap.String("path", path),
			zap.String("client_ip", clientIP),
			zap.Int("status_code", statusCode),
			zap.Int64("duration_ms", durationMs),
			zap.Int64("response_size", responseSize),
		}
		
		// 添加错误信息
		if reqCtx.Error != "" {
			logFields = append(logFields, zap.String("error", reqCtx.Error))
		}
		
		// 根据状态码选择日志级别
		if statusCode >= 500 {
			logger.Error("request_completed", logFields...)
		} else if statusCode >= 400 {
			logger.Warn("request_completed", logFields...)
		} else {
			logger.Info("request_completed", logFields...)
		}
		
		// 记录请求体（如果有且不超过限制）
		if requestBody != "" && len(requestBody) <= 1024 {
			logger.Debug("request_body",
				zap.String("request_id", requestID),
				zap.String("body", requestBody),
			)
		}
	}
}

// PerformanceMonitor 性能监控中间件
func PerformanceMonitor(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		
		// 执行请求
		c.Next()
		
		// 计算性能指标
		duration := time.Since(startTime)
		durationMs := duration.Milliseconds()
		
		// 获取请求ID
		requestID, _ := c.Get("request_id")
		
		// 记录性能指标到全局metrics系统
		core.GetPerformanceMetrics().RecordRequest(
			c.Request.Method,
			c.Request.URL.Path,
			duration,
			c.Writer.Status(),
		)
		
		// 记录慢查询
		if durationMs > 1000 {
			logger.Warn("slow_request",
				zap.String("request_id", requestID.(string)),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.Int64("duration_ms", durationMs),
				zap.Int("status_code", c.Writer.Status()),
			)
		}
		
		// 添加性能头部
		c.Header("X-Response-Time", fmt.Sprintf("%dms", durationMs))
		c.Header("X-Request-ID", requestID.(string))
		
		// 记录详细性能日志
		logger.Debug("performance_metrics",
			zap.String("request_id", requestID.(string)),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int64("duration_ms", durationMs),
			zap.Int("status_code", c.Writer.Status()),
		)
	}
}

// RequestIDGenerator 请求ID生成器中间件
func RequestIDGenerator() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 生成唯一请求ID
		requestID := GenerateRequestID()
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		
		// 将请求ID添加到日志上下文
		c.Header("X-Request-ID", requestID)
	}
}

// AuditLogger 已迁移到 middleware/audit.go
// 此函数已弃用，请使用新的审计日志系统：
//   middleware.AuditMiddleware(logger)
// 或直接使用：
//   middleware.LogAuditEvent(logger, ...)

// SecurityLogger 安全日志中间件
func SecurityLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// 执行请求
		c.Next()

		// 检查安全相关状态码
		statusCode := c.Writer.Status()
		duration := time.Since(startTime)

		// 记录安全事件
		switch {
		case statusCode == http.StatusUnauthorized:
			logger.Warn("unauthorized_access",
				zap.String("request_id", c.GetString("request_id")),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("client_ip", getClientIPHelper(c)),
				zap.String("user_agent", c.Request.UserAgent()),
				zap.Int64("duration_ms", duration.Milliseconds()),
			)

		case statusCode == http.StatusForbidden:
			logger.Warn("forbidden_access",
				zap.String("request_id", c.GetString("request_id")),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("client_ip", getClientIPHelper(c)),
				zap.String("user_agent", c.Request.UserAgent()),
				zap.String("user_id", c.GetString("user_id")),
				zap.Int64("duration_ms", duration.Milliseconds()),
			)

		case statusCode == http.StatusTooManyRequests:
			logger.Warn("rate_limit_exceeded",
				zap.String("request_id", c.GetString("request_id")),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("client_ip", getClientIPHelper(c)),
				zap.Int64("duration_ms", duration.Milliseconds()),
			)
		}
	}
}

// MetricsHandler 提供metrics端点
func MetricsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取性能指标
		metrics := core.GetPerformanceMetrics().GetMetrics()
		
		// 添加时间戳
		metrics["timestamp"] = time.Now().Format(time.RFC3339)
		metrics["endpoint"] = "/metrics"
		
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   metrics,
		})
	}
}

// PerformanceSummaryHandler 提供性能摘要端点
func PerformanceSummaryHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取性能摘要
		summary := core.GetPerformanceMetrics().GetPerformanceSummary()
		
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   summary,
		})
	}
}

// ... existing code ...

// getClientIPHelper 获取客户端IP的辅助函数
func getClientIPHelper(c *gin.Context) string {
	// 检查代理头部
	xff := c.GetHeader("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	xfRealIP := c.GetHeader("X-Real-IP")
	if xfRealIP != "" {
		return strings.TrimSpace(xfRealIP)
	}

	// 降级到默认方法
	return c.ClientIP()
}

// isValidIP 验证IP地址格式
func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	
	for _, part := range parts {
		if len(part) == 0 {
			return false
		}
		// 允许纯数字（兼容性）
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	
	return true
}

// LogRequestBody 记录请求体日志
func LogRequestBody(logger *zap.Logger, maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body == nil {
			c.Next()
			return
		}
		
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.Next()
			return
		}
		
		// 限制记录大小
		if int64(len(bodyBytes)) <= maxSize {
			requestID := c.GetString("request_id")
			logger.Debug("request_body",
				zap.String("request_id", requestID),
				zap.String("body", string(bodyBytes)),
			)
		}
		
		// 重新设置请求体
		c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		c.Next()
	}
}

// LogResponseBody 记录响应体日志
func LogResponseBody(logger *zap.Logger, maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 捕获响应
		writer := &responseWriter{
			ResponseWriter: c.Writer,
			body:           &bytes.Buffer{},
		}
		c.Writer = writer
		
		c.Next()
		
		// 记录响应体
		if int64(writer.body.Len()) <= maxSize {
			requestID := c.GetString("request_id")
			logger.Debug("response_body",
				zap.String("request_id", requestID),
				zap.String("body", writer.body.String()),
			)
		}
	}
}

// responseWriter 响应体捕获器
type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
}

// JSONFormatter JSON格式化日志
func JSONFormatter(logData map[string]interface{}) string {
	if logData == nil {
		return ""
	}
	
	jsonBytes, err := json.Marshal(logData)
	if err != nil {
		return fmt.Sprintf("error formatting JSON: %v", err)
	}
	
	return string(jsonBytes)
}