package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AuditLevel 审计级别
type AuditLevel string

const (
	AuditLevelInfo  AuditLevel = "info"
	AuditLevelWarn  AuditLevel = "warn"
	AuditLevelError AuditLevel = "error"
)

// AuditAction 审计动作类型
type AuditAction string

const (
	ActionCreate    AuditAction = "create"
	ActionUpdate    AuditAction = "update"
	ActionDelete    AuditAction = "delete"
	ActionDeploy    AuditAction = "deploy"
	ActionRollback  AuditAction = "rollback"
	ActionUpgrade   AuditAction = "upgrade"
	ActionView      AuditAction = "view"
	ActionLogin     AuditAction = "login"
	ActionLogout    AuditAction = "logout"
)

// AuditResource 审计资源类型
type AuditResource string

const (
	ResourceApp         AuditResource = "app"
	ResourceNamespace   AuditResource = "namespace"
	ResourceUser        AuditResource = "user"
	ResourceConfig      AuditResource = "config"
	ResourceSystem      AuditResource = "system"
)

// AuditResult 审计结果
type AuditResult string

const (
	ResultSuccess AuditResult = "success"
	ResultFailure AuditResult = "failure"
)

// AuditLog 审计日志结构体
type AuditLog struct {
	// 基本信息
	Timestamp    time.Time      `json:"timestamp"`
	Level        AuditLevel     `json:"level"`
	Action       AuditAction    `json:"action"`
	Resource     AuditResource  `json:"resource"`
	ResourceID   string         `json:"resourceId"`
	Result       AuditResult    `json:"result"`

	// 用户信息
	UserID       string         `json:"userId,omitempty"`
	Username     string         `json:"username,omitempty"`
	IPAddress    string         `json:"ipAddress"`
	UserAgent    string         `json:"userAgent"`

	// 请求信息
	RequestID    string         `json:"requestId"`
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	QueryParams  map[string]string `json:"queryParams,omitempty"`

	// 响应信息
	StatusCode   int            `json:"statusCode"`
	ResponseTime time.Duration  `json:"responseTime"`

	// 详细信息
	Message      string         `json:"message"`
	Details      map[string]interface{} `json:"details,omitempty"`

	// 错误信息
	ErrorMessage string         `json:"errorMessage,omitempty"`
}

// String 返回JSON格式的审计日志
func (a *AuditLog) String() string {
	data, _ := json.Marshal(a)
	return string(data)
}

// AuditLogger 审计日志器
type AuditLogger struct {
	logger *zap.Logger
}

// NewAuditLogger 创建新的审计日志器
func NewAuditLogger(logger *zap.Logger) *AuditLogger {
	return &AuditLogger{
		logger: logger,
	}
}

// Log 记录审计日志
func (l *AuditLogger) Log(audit *AuditLog) {
	// 将审计日志转换为结构化日志
	l.logger.Info("Audit log",
		zap.String("timestamp", audit.Timestamp.Format(time.RFC3339)),
		zap.String("level", string(audit.Level)),
		zap.String("action", string(audit.Action)),
		zap.String("resource", string(audit.Resource)),
		zap.String("resourceId", audit.ResourceID),
		zap.String("result", string(audit.Result)),
		zap.String("userId", audit.UserID),
		zap.String("username", audit.Username),
		zap.String("ipAddress", audit.IPAddress),
		zap.String("userAgent", audit.UserAgent),
		zap.String("requestId", audit.RequestID),
		zap.String("method", audit.Method),
		zap.String("path", audit.Path),
		zap.Any("queryParams", audit.QueryParams),
		zap.Int("statusCode", audit.StatusCode),
		zap.String("responseTime", audit.ResponseTime.String()),
		zap.String("message", audit.Message),
		zap.Any("details", audit.Details),
		zap.String("errorMessage", audit.ErrorMessage),
	)
}

// ExtractUserID 从请求中提取用户ID
func ExtractUserID(c *gin.Context) string {
	// 尝试从Authorization header提取
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		// 简化处理：假设Bearer token格式，实际项目中应解析JWT
		return "user-" + authHeader[len("Bearer "):]
	}

	// 尝试从查询参数提取
	if userID := c.Query("userId"); userID != "" {
		return userID
	}

	// 默认用户
	return "anonymous"
}

// ExtractUsername 从请求中提取用户名
func ExtractUsername(c *gin.Context) string {
	// 简化处理：使用userId作为username
	return ExtractUserID(c)
}

// AuditMiddleware 审计中间件
func AuditMiddleware(logger *zap.Logger) gin.HandlerFunc {
	auditLogger := NewAuditLogger(logger)

	return func(c *gin.Context) {
		// 记录开始时间
		startTime := time.Now()

		// 从上下文中获取请求ID（由RequestIDGenerator中间件生成）
		requestID, _ := c.Get("request_id")
		if requestID == nil {
			requestID = GenerateRequestID()
		}

		// 创建审计日志
		audit := &AuditLog{
			Timestamp:   startTime,
			Level:       AuditLevelInfo,
			Action:      ActionView,
			Resource:    ResourceSystem,
			ResourceID:  "",
			Result:      ResultSuccess,
			UserID:      ExtractUserID(c),
			Username:    ExtractUsername(c),
			IPAddress:   c.ClientIP(),
			UserAgent:   c.GetHeader("User-Agent"),
			RequestID:   requestID.(string),
			Method:      c.Request.Method,
			Path:        c.Request.URL.Path,
			QueryParams: extractQueryParams(c),
			StatusCode:  200,
			Message:     "",
			Details:     make(map[string]interface{}),
		}

		// 根据路径推断资源类型和动作
		audit = inferResourceAndAction(audit, c)

		// 继续处理请求
		c.Next()

		// 计算响应时间
		audit.ResponseTime = time.Since(startTime)
		audit.StatusCode = c.Writer.Status()

		// 确定审计级别和结果
		if audit.StatusCode >= 400 {
			audit.Level = AuditLevelWarn
			audit.Result = ResultFailure
			if len(c.Errors) > 0 {
				audit.ErrorMessage = c.Errors.Last().Error()
			}
		}

		// 添加响应详情
		audit.Details["status_code"] = audit.StatusCode
		audit.Details["response_time_ms"] = audit.ResponseTime.Milliseconds()

		// 记录审计日志
		auditLogger.Log(audit)
	}
}

// extractQueryParams 提取查询参数
func extractQueryParams(c *gin.Context) map[string]string {
	params := make(map[string]string)
	for k, v := range c.Request.URL.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}
	return params
}

// inferResourceAndAction 根据路径推断资源和动作
func inferResourceAndAction(audit *AuditLog, c *gin.Context) *AuditLog {
	path := c.Request.URL.Path
	method := c.Request.Method

	// 应用相关操作
	if contains(path, "/app") {
		audit.Resource = ResourceApp
		audit.ResourceID = c.Param("name")

		switch method {
		case http.MethodPost:
			if contains(path, "/app") && !contains(path, "/apps/") {
				audit.Action = ActionCreate
			} else if contains(path, "/upgrade") {
				audit.Action = ActionUpgrade
			} else if contains(path, "/rollback") {
				audit.Action = ActionRollback
			} else {
				audit.Action = ActionDeploy
			}
		case http.MethodPut:
			audit.Action = ActionUpdate
		case http.MethodDelete:
			audit.Action = ActionDelete
		case http.MethodGet:
			audit.Action = ActionView
		}
	}

	// 用户相关操作
	if contains(path, "/user") {
		audit.Resource = ResourceUser
		audit.ResourceID = c.Param("id")

		switch method {
		case http.MethodPost:
			audit.Action = ActionCreate
		case http.MethodPut:
			audit.Action = ActionUpdate
		case http.MethodDelete:
			audit.Action = ActionDelete
		case http.MethodGet:
			audit.Action = ActionView
		}
	}

	// 配置相关操作
	if contains(path, "/config") {
		audit.Resource = ResourceConfig

		switch method {
		case http.MethodPost:
			audit.Action = ActionCreate
		case http.MethodPut:
			audit.Action = ActionUpdate
		case http.MethodGet:
			audit.Action = ActionView
		}
	}

	// 健康检查和就绪检查
	if contains(path, "/health") || contains(path, "/ready") {
		audit.Resource = ResourceSystem
		audit.Action = ActionView
		audit.Level = AuditLevelInfo
	}

	// 添加资源详情到消息
	audit.Message = fmt.Sprintf("%s %s %s:%s %s",
		audit.Action,
		audit.Resource,
		audit.Resource,
		audit.ResourceID,
		audit.Result,
	)

	return audit
}

// contains 检查字符串是否包含子字符串
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		   len(s) > len(substr) && s[len(s)-len(substr):] == substr ||
		   len(s) > len(substr) && findSubstring(s, substr)
}

// findSubstring 查找子字符串（简化版）
func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// LogAuditEvent 手动记录审计事件
func LogAuditEvent(logger *zap.Logger, action AuditAction, resource AuditResource, resourceID string, result AuditResult, message string, details map[string]interface{}) {
	auditLogger := NewAuditLogger(logger)

	audit := &AuditLog{
		Timestamp:   time.Now(),
		Level:       AuditLevelInfo,
		Action:      action,
		Resource:    resource,
		ResourceID:  resourceID,
		Result:      result,
		Message:     message,
		Details:     details,
		IPAddress:   "system",
		UserAgent:   "helm-proxy",
		RequestID:   "system",
		Method:      "SYSTEM",
		Path:        "internal",
		StatusCode:  0,
		ResponseTime: 0,
	}

	auditLogger.Log(audit)
}
