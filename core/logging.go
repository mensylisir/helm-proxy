package core

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// LogLevel 日志级别
type LogLevel string

const (
	DEBUG LogLevel = "debug"
	INFO  LogLevel = "info"
	WARN  LogLevel = "warn"
	ERROR LogLevel = "error"
	FATAL LogLevel = "fatal"
	PANIC LogLevel = "panic"
)

// Logger 接口定义
type Logger interface {
	Debug(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
	Fatal(args ...interface{})
	Panic(args ...interface{})
	Print(args ...interface{})

	Printf(format string, v ...interface{})
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Panicf(format string, args ...interface{})

	WithFields(fields logrus.Fields) *logrus.Entry
	WithField(key string, value interface{}) *logrus.Entry

	SetLevel(level LogLevel)
	GetLevel() LogLevel

	// 结构化日志方法
	WithContext(ctx interface{}) *logrus.Entry
	WithRequest(req *http.Request) *logrus.Entry
	WithOperation(operation string) *logrus.Entry
	WithDuration(duration time.Duration) *logrus.Entry

	// 性能监控日志
	Performance(operation string, duration time.Duration, success bool, details map[string]interface{})

	// 安全日志
	Security(event string, level LogLevel, details map[string]interface{})

	// 业务日志
	Business(event string, data map[string]interface{})
}

// StructuredLogger 结构化日志器
type StructuredLogger struct {
	logger    *logrus.Logger
	mu        sync.RWMutex
	operation string
	requestID string
	startTime time.Time
	fields    logrus.Fields
}

// NewStructuredLogger 创建结构化日志器
func NewStructuredLogger() *StructuredLogger {
	logger := logrus.New()

	// 设置日志格式
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
		PrettyPrint:     false,
	})

	// 设置日志级别
	level := INFO
	if envLevel := os.Getenv("LOG_LEVEL"); envLevel != "" {
		level = LogLevel(strings.ToLower(envLevel))
	}

	logLevel, err := logrus.ParseLevel(string(level))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logger.SetLevel(logLevel)

	// 设置输出
	if logFile := os.Getenv("LOG_FILE"); logFile != "" {
		if err := ensureLogDirectory(logFile); err != nil {
			logger.Warnf("无法创建日志目录: %v", err)
		} else {
			file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				logger.Warnf("无法打开日志文件: %v", err)
			} else {
				// 同时输出到文件和控制台
				logger.SetOutput(io.MultiWriter(file, os.Stdout))
			}
		}
	}

	return &StructuredLogger{
		logger: logger,
		fields: make(logrus.Fields),
	}
}

// ensureLogDirectory 确保日志目录存在
func ensureLogDirectory(logFile string) error {
	dir := filepath.Dir(logFile)
	return os.MkdirAll(dir, 0755)
}

// WithFields 添加字段
func (s *StructuredLogger) WithFields(fields logrus.Fields) *logrus.Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	mergedFields := make(logrus.Fields)
	for k, v := range s.fields {
		mergedFields[k] = v
	}
	for k, v := range fields {
		mergedFields[k] = v
	}

	return s.logger.WithFields(mergedFields)
}

// WithField 添加单个字段
func (s *StructuredLogger) WithField(key string, value interface{}) *logrus.Entry {
	return s.WithFields(logrus.Fields{key: value})
}

// Debug 调试日志
func (s *StructuredLogger) Debug(args ...interface{}) {
	s.logger.Debug(args...)
}

// Info 信息日志
func (s *StructuredLogger) Info(args ...interface{}) {
	s.logger.Info(args...)
}

// Warn 警告日志
func (s *StructuredLogger) Warn(args ...interface{}) {
	s.logger.Warn(args...)
}

// Error 错误日志
func (s *StructuredLogger) Error(args ...interface{}) {
	s.logger.Error(args...)
}

// Fatal 致命错误日志
func (s *StructuredLogger) Fatal(args ...interface{}) {
	s.logger.Fatal(args...)
}

// Panic 恐慌日志
func (s *StructuredLogger) Panic(args ...interface{}) {
	s.logger.Panic(args...)
}

// Print 打印日志
func (s *StructuredLogger) Print(args ...interface{}) {
	s.logger.Print(args...)
}

// Printf 格式化打印日志
func (s *StructuredLogger) Printf(format string, v ...interface{}) {
	s.logger.Printf(format, v...)
}

// Debugf 格式化调试日志
func (s *StructuredLogger) Debugf(format string, args ...interface{}) {
	s.logger.Debugf(format, args...)
}

// Infof 格式化信息日志
func (s *StructuredLogger) Infof(format string, args ...interface{}) {
	s.logger.Infof(format, args...)
}

// Warnf 格式化警告日志
func (s *StructuredLogger) Warnf(format string, args ...interface{}) {
	s.logger.Warnf(format, args...)
}

// Errorf 格式化错误日志
func (s *StructuredLogger) Errorf(format string, args ...interface{}) {
	s.logger.Errorf(format, args...)
}

// Fatalf 格式化致命错误日志
func (s *StructuredLogger) Fatalf(format string, args ...interface{}) {
	s.logger.Fatalf(format, args...)
}

// Panicf 格式化恐慌日志
func (s *StructuredLogger) Panicf(format string, args ...interface{}) {
	s.logger.Panicf(format, args...)
}

// SetLevel 设置日志级别
func (s *StructuredLogger) SetLevel(level LogLevel) {
	logLevel, err := logrus.ParseLevel(string(level))
	if err != nil {
		s.logger.Warnf("无效的日志级别: %s", level)
		return
	}
	s.logger.SetLevel(logLevel)
}

// GetLevel 获取日志级别
func (s *StructuredLogger) GetLevel() LogLevel {
	return LogLevel(s.logger.GetLevel().String())
}

// WithContext 添加上下文
func (s *StructuredLogger) WithContext(ctx interface{}) *logrus.Entry {
	return s.WithField("context", ctx)
}

// WithRequest 添加请求信息
func (s *StructuredLogger) WithRequest(req *http.Request) *logrus.Entry {
	fields := logrus.Fields{
		"method":      req.Method,
		"path":        req.URL.Path,
		"query":       req.URL.RawQuery,
		"user_agent":  req.Header.Get("User-Agent"),
		"remote_addr": req.RemoteAddr,
	}

	if requestID := req.Header.Get("X-Request-ID"); requestID != "" {
		fields["request_id"] = requestID
	}

	return s.WithFields(fields)
}

// WithOperation 添加操作信息
func (s *StructuredLogger) WithOperation(operation string) *logrus.Entry {
	s.mu.Lock()
	s.operation = operation
	s.mu.Unlock()

	return s.WithField("operation", operation)
}

// WithDuration 添加持续时间
func (s *StructuredLogger) WithDuration(duration time.Duration) *logrus.Entry {
	return s.WithField("duration_ms", duration.Nanoseconds()/1000000)
}

// Performance 性能监控日志
func (s *StructuredLogger) Performance(operation string, duration time.Duration, success bool, details map[string]interface{}) {
	fields := logrus.Fields{
		"operation":   operation,
		"duration_ms": duration.Nanoseconds() / 1000000,
		"success":     success,
		"timestamp":   time.Now().Format(time.RFC3339Nano),
	}

	for k, v := range details {
		fields["perf_"+k] = v
	}

	// 添加性能指标
	PerformanceMetrics.RecordOperation(operation, duration, success)

	s.WithFields(fields).Info("性能指标记录")
}

// Security 安全日志
func (s *StructuredLogger) Security(event string, level LogLevel, details map[string]interface{}) {
	fields := logrus.Fields{
		"event":     event,
		"timestamp": time.Now().Format(time.RFC3339Nano),
		"category":  "security",
	}

	for k, v := range details {
		fields["sec_"+k] = v
	}

	// 添加调用栈信息
	if _, file, line, ok := runtime.Caller(2); ok {
		fields["caller"] = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}

	switch level {
	case DEBUG:
		s.WithFields(fields).Debug("安全事件")
	case INFO:
		s.WithFields(fields).Info("安全事件")
	case WARN:
		s.WithFields(fields).Warn("安全事件")
	case ERROR:
		s.WithFields(fields).Error("安全事件")
	case FATAL:
		s.WithFields(fields).Fatal("安全事件")
	case PANIC:
		s.WithFields(fields).Panic("安全事件")
	}
}

// Business 业务日志
func (s *StructuredLogger) Business(event string, data map[string]interface{}) {
	fields := logrus.Fields{
		"event":     event,
		"timestamp": time.Now().Format(time.RFC3339Nano),
		"category":  "business",
	}

	for k, v := range data {
		fields["biz_"+k] = v
	}

	s.WithFields(fields).Info("业务事件")
}

// RequestLogger 请求日志中间件
type RequestLogger struct {
	logger *StructuredLogger
}

// NewRequestLogger 创建请求日志器
func NewRequestLogger(logger *StructuredLogger) *RequestLogger {
	return &RequestLogger{
		logger: logger,
	}
}

// LogRequest 记录HTTP请求
func (r *RequestLogger) LogRequest(req *http.Request, startTime time.Time) {
	duration := time.Since(startTime)

	fields := logrus.Fields{
		"method":      req.Method,
		"path":        req.URL.Path,
		"query":       req.URL.RawQuery,
		"duration_ms": duration.Nanoseconds() / 1000000,
		"user_agent":  req.Header.Get("User-Agent"),
		"remote_addr": req.RemoteAddr,
		"timestamp":   startTime.Format(time.RFC3339Nano),
	}

	if requestID := req.Header.Get("X-Request-ID"); requestID != "" {
		fields["request_id"] = requestID
	}

	r.logger.WithFields(fields).Info("HTTP请求")

	// 记录性能指标
	PerformanceMetrics.RecordRequest(req.Method, req.URL.Path, duration, 200) // 假设200状态码
}

// LogResponse 记录HTTP响应
func (r *RequestLogger) LogResponse(req *http.Request, startTime time.Time, statusCode int, responseSize int64) {
	duration := time.Since(startTime)

	fields := logrus.Fields{
		"method":        req.Method,
		"path":          req.URL.Path,
		"status_code":   statusCode,
		"response_size": responseSize,
		"duration_ms":   duration.Nanoseconds() / 1000000,
		"timestamp":     startTime.Format(time.RFC3339Nano),
	}

	if requestID := req.Header.Get("X-Request-ID"); requestID != "" {
		fields["request_id"] = requestID
	}

	level := INFO
	if statusCode >= 500 {
		level = ERROR
	} else if statusCode >= 400 {
		level = WARN
	}

	switch level {
	case INFO:
		r.logger.WithFields(fields).Info("HTTP响应")
	case WARN:
		r.logger.WithFields(fields).Warn("HTTP响应")
	case ERROR:
		r.logger.WithFields(fields).Error("HTTP响应")
	}

	// 记录性能指标
	PerformanceMetrics.RecordRequest(req.Method, req.URL.Path, duration, statusCode)
}

// LoggerMiddleware 日志中间件
func LoggerMiddleware(logger *StructuredLogger) func(http.Handler) http.Handler {
	requestLogger := NewRequestLogger(logger)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startTime := time.Now()

			// 创建响应写入器以捕获状态码和响应大小
			responseWriter := &responseWriter{
				ResponseWriter: w,
				statusCode:     200,
				bytesWritten:   0,
			}

			// 记录请求开始
			requestLogger.LogRequest(r, startTime)

			// 调用下一个处理器
			next.ServeHTTP(responseWriter, r)

			// 记录响应
			requestLogger.LogResponse(r, startTime, responseWriter.statusCode, responseWriter.bytesWritten)
		})
	}
}

// responseWriter 响应写入器
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

// GetCallerInfo 获取调用者信息
func GetCallerInfo(skip int) (file string, line int, function string) {
	pc, file, line, _ := runtime.Caller(skip)
	function = runtime.FuncForPC(pc).Name()

	// 提取函数名（去掉包路径）
	if idx := strings.LastIndex(function, "/"); idx != -1 {
		function = function[idx+1:]
	}

	return
}

// LogError 记录错误
func LogError(logger *StructuredLogger, err error, context string) {
	fields := logrus.Fields{
		"error":      err.Error(),
		"error_type": fmt.Sprintf("%T", err),
		"context":    context,
		"timestamp":  time.Now().Format(time.RFC3339Nano),
	}

	// 添加调用者信息
	if file, line, function := GetCallerInfo(3); file != "" {
		fields["caller"] = fmt.Sprintf("%s:%d (%s)", filepath.Base(file), line, function)
	}

	logger.WithFields(fields).Error("错误发生")
}

// 全局日志器实例
var globalLogger *StructuredLogger
var once sync.Once

// GetGlobalLogger 获取全局日志器
func GetGlobalLogger() *StructuredLogger {
	once.Do(func() {
		globalLogger = NewStructuredLogger()
	})
	return globalLogger
}

// InitializeGlobalLogger 初始化全局日志器
func InitializeGlobalLogger() *StructuredLogger {
	return GetGlobalLogger()
}
