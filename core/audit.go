package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AuditAction 审计动作类型
type AuditAction string

const (
	// 用户认证相关
	ActionUserLogin       AuditAction = "user.login"
	ActionUserLogout      AuditAction = "user.logout"
	ActionUserAuthFailure AuditAction = "user.auth_failure"

	// 应用部署相关
	ActionAppDeploy        AuditAction = "app.deploy"
	ActionAppUpgrade       AuditAction = "app.upgrade"
	ActionAppRollback      AuditAction = "app.rollback"
	ActionAppDelete        AuditAction = "app.delete"
	ActionAppGetStatus     AuditAction = "app.get_status"
	ActionAppList          AuditAction = "app.list"

	// 仓库相关
	ActionRepoAdd    AuditAction = "repo.add"
	ActionRepoUpdate AuditAction = "repo.update"
	ActionRepoDelete AuditAction = "repo.delete"

	// 系统管理相关
	ActionConfigUpdate AuditAction = "config.update"
	ActionSystemRestart AuditAction = "system.restart"
	ActionSystemHealthCheck AuditAction = "system.health_check"

	// API 调用相关
	ActionAPICall AuditAction = "api.call"
)

// AuditResource 审计资源类型
type AuditResource string

const (
	ResourceUser      AuditResource = "user"
	ResourceApp       AuditResource = "app"
	ResourceNamespace AuditResource = "namespace"
	ResourceChart     AuditResource = "chart"
	ResourceRepo      AuditResource = "repo"
	ResourceConfig    AuditResource = "config"
	ResourceSystem    AuditResource = "system"
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
	// 基础信息
	ID          string      `json:"id"`          // 审计日志ID
	Timestamp   time.Time   `json:"timestamp"`   // 时间戳
	Action      AuditAction `json:"action"`      // 操作动作
	Resource    AuditResource `json:"resource"`  // 资源类型
	ResourceID  string      `json:"resource_id"` // 资源ID
	Result      AuditResult `json:"result"`      // 结果

	// 用户信息
	UserID      string      `json:"user_id,omitempty"`       // 用户ID
	Username    string      `json:"username,omitempty"`       // 用户名
	RequestID   string      `json:"request_id,omitempty"`     // 请求ID

	// 请求信息
	Method      string      `json:"method"`        // HTTP方法
	Path        string      `json:"path"`          // 请求路径
	RemoteAddr  string      `json:"remote_addr"`   // 客户端地址
	UserAgent   string      `json:"user_agent"`    // 用户代理
	RequestBody string      `json:"request_body,omitempty"`   // 请求体（敏感信息已脱敏）

	// 响应信息
	StatusCode  int         `json:"status_code"`   // 响应状态码
	ResponseSize int64      `json:"response_size"` // 响应大小

	// 性能信息
	Duration    time.Duration `json:"duration"`     // 执行时长

	// 错误信息
	ErrorCode   string      `json:"error_code,omitempty"`   // 错误码
	ErrorMessage string     `json:"error_message,omitempty"` // 错误信息

	// 元数据
	Metadata    map[string]interface{} `json:"metadata,omitempty"` // 附加信息
}

// AuditLogger 审计日志记录器
type AuditLogger struct {
	mu         sync.RWMutex
	logs       []*AuditLog
	logDir     string
	maxLogs    int // 最大保存日志数量
	logger     *zap.Logger
	promMetrics *PrometheusMetrics
}

// NewAuditLogger 创建新的审计日志记录器
func NewAuditLogger(logDir string, maxLogs int, logger *zap.Logger) *AuditLogger {
	// 创建日志目录
	if err := os.MkdirAll(logDir, 0755); err != nil {
		logger.Warn("Failed to create audit log directory", zap.String("dir", logDir), zap.Error(err))
	}

	auditLogger := &AuditLogger{
		logs:       make([]*AuditLog, 0, maxLogs),
		logDir:     logDir,
		maxLogs:    maxLogs,
		logger:     logger,
		promMetrics: GetPrometheusMetrics(),
	}

	// 从文件加载历史日志
	auditLogger.loadFromFile()

	return auditLogger
}

// Log 记录审计日志
func (al *AuditLogger) Log(ctx context.Context, log *AuditLog) {
	// 设置默认值
	if log.ID == "" {
		log.ID = uuid.New().String()
	}
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now()
	}

	// 添加到内存缓冲区
	al.mu.Lock()
	al.logs = append(al.logs, log)
	// 限制日志数量
	if len(al.logs) > al.maxLogs {
		al.logs = al.logs[1:]
	}
	al.mu.Unlock()

	// 记录到文件
	al.writeToFile(log)

	// 记录到 Zap 日志
	al.logger.Info("Audit log",
		zap.String("action", string(log.Action)),
		zap.String("resource", string(log.Resource)),
		zap.String("resource_id", log.ResourceID),
		zap.String("result", string(log.Result)),
		zap.String("user", log.Username),
		zap.String("request_id", log.RequestID),
		zap.String("method", log.Method),
		zap.String("path", log.Path),
		zap.Int("status_code", log.StatusCode),
		zap.Duration("duration", log.Duration),
	)

	// 记录到 Prometheus 指标
	if al.promMetrics != nil {
		al.promMetrics.RecordCustomOperation(
			fmt.Sprintf("audit_%s", log.Action),
			string(log.Result),
			log.Duration,
		)
	}
}

// LogRequest 记录请求审计日志
func (al *AuditLogger) LogRequest(
	ctx context.Context,
	method, path, remoteAddr, userAgent string,
	statusCode int,
	duration time.Duration,
	requestBody string,
	responseSize int64,
	userID, username, requestID string,
	action AuditAction,
	resource AuditResource,
	resourceID string,
	result AuditResult,
	errorCode, errorMessage string,
	metadata map[string]interface{},
) {
	// 脱敏请求体
	sanitizedBody := al.sanitizeRequestBody(requestBody)

	log := &AuditLog{
		Method:       method,
		Path:         path,
		RemoteAddr:   remoteAddr,
		UserAgent:    userAgent,
		StatusCode:   statusCode,
		Duration:     duration,
		RequestBody:  sanitizedBody,
		ResponseSize: responseSize,
		UserID:       userID,
		Username:     username,
		RequestID:    requestID,
		Action:       action,
		Resource:     resource,
		ResourceID:   resourceID,
		Result:       result,
		ErrorCode:    errorCode,
		ErrorMessage: errorMessage,
		Metadata:     metadata,
	}

	al.Log(ctx, log)
}

// sanitizeRequestBody 脱敏请求体中的敏感信息
func (al *AuditLogger) sanitizeRequestBody(body string) string {
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

// writeToFile 写入文件
func (al *AuditLogger) writeToFile(log *AuditLog) {
	// 按日期创建日志文件
	dateStr := log.Timestamp.Format("2006-01-02")
	logFile := filepath.Join(al.logDir, fmt.Sprintf("audit-%s.log", dateStr))

	// 序列化日志
	line, err := json.Marshal(log)
	if err != nil {
		al.logger.Error("Failed to marshal audit log", zap.Error(err))
		return
	}
	line = append(line, '\n')

	// 写入文件（追加模式）
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		al.logger.Error("Failed to open audit log file", zap.String("file", logFile), zap.Error(err))
		return
	}
	defer f.Close()

	if _, err := f.Write(line); err != nil {
		al.logger.Error("Failed to write audit log", zap.String("file", logFile), zap.Error(err))
	}
}

// loadFromFile 从文件加载历史日志
func (al *AuditLogger) loadFromFile() {
	// 读取最近7天的日志文件
	for i := 0; i < 7; i++ {
		date := time.Now().AddDate(0, 0, -i)
		dateStr := date.Format("2006-01-02")
		logFile := filepath.Join(al.logDir, fmt.Sprintf("audit-%s.log", dateStr))

		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(logFile)
		if err != nil {
			al.logger.Warn("Failed to read audit log file", zap.String("file", logFile), zap.Error(err))
			continue
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}

			var log AuditLog
			if err := json.Unmarshal([]byte(line), &log); err != nil {
				continue
			}

			al.mu.Lock()
			al.logs = append(al.logs, &log)
			al.mu.Unlock()
		}
	}

	// 限制日志数量
	al.mu.Lock()
	if len(al.logs) > al.maxLogs {
		al.logs = al.logs[len(al.logs)-al.maxLogs:]
	}
	al.mu.Unlock()

	al.logger.Info("Loaded audit logs from files", zap.Int("count", len(al.logs)))
}

// Query 查询审计日志
func (al *AuditLogger) Query(filter AuditLogFilter) ([]*AuditLog, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var results []*AuditLog

	for _, log := range al.logs {
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
func (al *AuditLogger) GetRecentLogs(limit int) []*AuditLog {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if limit <= 0 || limit > len(al.logs) {
		limit = len(al.logs)
	}

	// 返回最近的日志（倒序）
	result := make([]*AuditLog, limit)
	copy(result, al.logs[len(al.logs)-limit:])
	return result
}

// GetStatistics 获取审计统计信息
func (al *AuditLogger) GetStatistics() *AuditStatistics {
	al.mu.RLock()
	defer al.mu.RUnlock()

	stats := &AuditStatistics{
		TotalLogs:      len(al.logs),
		ActionCounts:   make(map[AuditAction]int),
		ResourceCounts: make(map[AuditResource]int),
		ResultCounts:   make(map[AuditResult]int),
		DateCounts:     make(map[string]int),
	}

	for _, log := range al.logs {
		stats.ActionCounts[log.Action]++
		stats.ResourceCounts[log.Resource]++
		stats.ResultCounts[log.Result]++

		dateStr := log.Timestamp.Format("2006-01-02")
		stats.DateCounts[dateStr]++

		// 计算平均响应时间
		if log.Duration > 0 {
			stats.TotalDuration += log.Duration
			stats.DurationCount++
		}
	}

	if stats.DurationCount > 0 {
		stats.AvgDuration = stats.TotalDuration / time.Duration(stats.DurationCount)
	}

	// 计算成功率
	if stats.TotalLogs > 0 {
		stats.SuccessRate = float64(stats.ResultCounts[ResultSuccess]) / float64(stats.TotalLogs)
	}

	return stats
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

// AuditStatistics 审计统计信息
type AuditStatistics struct {
	TotalLogs      int                     `json:"total_logs"`
	ActionCounts   map[AuditAction]int     `json:"action_counts"`
	ResourceCounts map[AuditResource]int   `json:"resource_counts"`
	ResultCounts   map[AuditResult]int     `json:"result_counts"`
	DateCounts     map[string]int          `json:"date_counts"`
	SuccessRate    float64                 `json:"success_rate"`
	AvgDuration    time.Duration           `json:"avg_duration"`
	TotalDuration  time.Duration           `json:"total_duration"`
	DurationCount  int                     `json:"duration_count"`
}
