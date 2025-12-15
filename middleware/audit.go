package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	ActionAPICall   AuditAction = "api.call"
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
	ResultWarning AuditResult = "warning"
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
	RequestBody  string         `json:"requestBody,omitempty"`

	// 响应信息
	StatusCode   int            `json:"statusCode"`
	ResponseTime time.Duration  `json:"responseTime"`
	ResponseSize int64          `json:"responseSize"`

	// 详细信息
	Message      string         `json:"message"`
	Details      map[string]interface{} `json:"details,omitempty"`

	// 错误信息
	ErrorMessage string         `json:"errorMessage,omitempty"`
}

// AuditLogger 审计日志器
type AuditLogger struct {
	mu      sync.RWMutex
	logs    []*AuditLog
	logDir  string
	maxLogs int
	logger  *zap.Logger
}

// NewAuditLogger 创建新的审计日志器
func NewAuditLogger(logDir string, maxLogs int, logger *zap.Logger) *AuditLogger {
	// 创建日志目录
	if err := os.MkdirAll(logDir, 0755); err != nil {
		logger.Warn("Failed to create audit log directory", zap.String("dir", logDir), zap.Error(err))
	}

	return &AuditLogger{
		logs:    make([]*AuditLog, 0, maxLogs),
		logDir:  logDir,
		maxLogs: maxLogs,
		logger:  logger,
	}
}

// Log 记录审计日志
func (l *AuditLogger) Log(audit *AuditLog) {
	// 添加到内存缓冲区
	l.mu.Lock()
	l.logs = append(l.logs, audit)
	// 限制日志数量
	if len(l.logs) > l.maxLogs {
		l.logs = l.logs[1:]
	}
	l.mu.Unlock()

	// 写入文件
	l.writeToFile(audit)

	// 记录到结构化日志
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
		zap.Int("statusCode", audit.StatusCode),
		zap.String("responseTime", audit.ResponseTime.String()),
		zap.Int64("responseSize", audit.ResponseSize),
	)
}

// writeToFile 写入文件
func (l *AuditLogger) writeToFile(audit *AuditLog) {
	// 按日期创建日志文件
	dateStr := audit.Timestamp.Format("2006-01-02")
	logFile := filepath.Join(l.logDir, fmt.Sprintf("audit-%s.log", dateStr))

	// 序列化日志
	line, err := json.Marshal(audit)
	if err != nil {
		l.logger.Error("Failed to marshal audit log", zap.Error(err))
		return
	}
	line = append(line, '\n')

	// 写入文件（追加模式）
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		l.logger.Error("Failed to open audit log file", zap.String("file", logFile), zap.Error(err))
		return
	}
	defer f.Close()

	if _, err := f.Write(line); err != nil {
		l.logger.Error("Failed to write audit log", zap.String("file", logFile), zap.Error(err))
	}
}

// Query 查询审计日志
func (l *AuditLogger) Query(filter AuditLogFilter) ([]*AuditLog, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var results []*AuditLog

	for _, log := range l.logs {
		// 应用过滤条件
		if filter.StartTime != nil && log.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && log.Timestamp.After(*filter.EndTime) {
			continue
		}
		if filter.Action != nil && log.Action != *filter.Action {
			continue
		}
		if filter.Resource != nil && log.Resource != *filter.Resource {
			continue
		}
		if filter.Result != nil && log.Result != *filter.Result {
			continue
		}
		if filter.Username != "" && log.Username != filter.Username {
			continue
		}
		if filter.RequestID != "" && log.RequestID != filter.RequestID {
			continue
		}

		results = append(results, log)
	}

	return results, nil
}

// GetRecentLogs 获取最近的审计日志
func (l *AuditLogger) GetRecentLogs(limit int) []*AuditLog {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if limit <= 0 || limit > len(l.logs) {
		limit = len(l.logs)
	}

	// 返回最近的日志（倒序）
	result := make([]*AuditLog, limit)
	copy(result, l.logs[len(l.logs)-limit:])
	return result
}

// AuditLogFilter 审计日志过滤条件
type AuditLogFilter struct {
	StartTime *time.Time
	EndTime   *time.Time
	Action    *AuditAction
	Resource  *AuditResource
	Result    *AuditResult
	Username  string
	RequestID string
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
func AuditMiddleware(auditLogger *AuditLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 跳过审计的路径
		if isSkippedPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		// 记录开始时间
		startTime := time.Now()

		// 读取请求体
		var requestBody string
		if c.Request.Body != nil {
			bodyBytes, _ := io.ReadAll(c.Request.Body)
			requestBody = string(bodyBytes)
			// 重新设置请求体，供后续处理使用
			c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		// 从上下文中获取请求ID
		requestID, _ := c.Get("request_id")
		if requestID == nil {
			requestID = GenerateRequestID()
			c.Set("request_id", requestID)
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
			RequestBody: sanitizeRequestBody(requestBody),
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

// isSkippedPath 检查路径是否跳过审计
func isSkippedPath(path string) bool {
	skipPaths := []string{
		"/metrics",
		"/metrics/custom",
		"/health",
		"/v1/monitor/health",
		"/v1/monitor/metrics",
		"/favicon.ico",
		"/swagger",
	}

	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// sanitizeRequestBody 脱敏请求体中的敏感信息
func sanitizeRequestBody(body string) string {
	if body == "" {
		return body
	}

	// 敏感字段列表
	sensitiveFields := []string{
		"password", "secret", "token", "key", "credential",
		"jwt", "auth", "private", "cert", "ca",
	}

	sanitized := body

	for _, field := range sensitiveFields {
		// 替换敏感字段的值
		pattern := fmt.Sprintf(`"%s"\s*:\s*"[^"]*"`, field)
		replacement := fmt.Sprintf(`"%s":"***REDACTED***"`, field)
		sanitized = strings.ReplaceAll(sanitized, pattern, replacement)

		// 处理单引号
		pattern = fmt.Sprintf(`'%s'\s*:\s*'[^']*'`, field)
		replacement = fmt.Sprintf(`'%s':'***REDACTED***'`, field)
		sanitized = strings.ReplaceAll(sanitized, pattern, replacement)
	}

	return sanitized
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

	// 应用部署相关
	if strings.HasPrefix(path, "/v3/projects/") && strings.Contains(path, "/app") {
		audit.Resource = ResourceApp
		audit.ResourceID = c.Param("name")

		switch method {
		case http.MethodPost:
			if strings.HasSuffix(path, "/app") {
				audit.Action = ActionCreate
			} else if strings.Contains(path, "/upgrade") {
				audit.Action = ActionUpgrade
			} else if strings.Contains(path, "/rollback") {
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
	if strings.Contains(path, "/user") {
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
	if strings.Contains(path, "/config") {
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
	if strings.Contains(path, "/health") || strings.Contains(path, "/ready") {
		audit.Resource = ResourceSystem
		audit.Action = ActionView
		audit.Level = AuditLevelInfo
	}

	// API调用
	if audit.Resource == ResourceSystem && audit.Action == ActionView {
		audit.Action = ActionAPICall
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

// LogAuditEvent 手动记录审计事件
func LogAuditEvent(logger *zap.Logger, action AuditAction, resource AuditResource, resourceID string, result AuditResult, message string, details map[string]interface{}) {
	// 记录到结构化日志
	logger.Info("Manual audit event",
		zap.String("action", string(action)),
		zap.String("resource", string(resource)),
		zap.String("resourceId", resourceID),
		zap.String("result", string(result)),
		zap.String("message", message),
		zap.Any("details", details),
	)
}
