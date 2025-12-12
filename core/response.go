package core

import (
	"time"

	"github.com/gin-gonic/gin"
)

// RequestContext 请求上下文结构体
type RequestContext struct {
	RequestID string
	StartTime time.Time
	UserID    string
	IP        string
	Method    string
	Path      string
}

// ContextKey 请求上下文的键类型
type ContextKey string

const (
	RequestIDKey ContextKey = "request_id"
	StartTimeKey ContextKey = "start_time"
	UserIDKey    ContextKey = "user_id"
)

// SetRequestContext 设置请求上下文
func SetRequestContext(c *gin.Context, ctx *RequestContext) {
	c.Set(string(RequestIDKey), ctx.RequestID)
	c.Set(string(StartTimeKey), ctx.StartTime)
	c.Set(string(UserIDKey), ctx.UserID)
}

// GetRequestContext 获取请求上下文
func GetRequestContext(c *gin.Context) *RequestContext {
	ctx := &RequestContext{
		RequestID: c.GetString(string(RequestIDKey)),
		StartTime: c.GetTime(string(StartTimeKey)),
		UserID:    c.GetString(string(UserIDKey)),
		IP:        c.ClientIP(),
		Method:    c.Request.Method,
		Path:      c.Request.URL.Path,
	}
	return ctx
}

// ResponseFormatter 响应格式化器
type ResponseFormatter struct{}

// NewResponseFormatter 创建新的响应格式化器
func NewResponseFormatter() *ResponseFormatter {
	return &ResponseFormatter{}
}

// Success 成功响应
func (f *ResponseFormatter) Success(c *gin.Context, data interface{}, message string) {
	ctx := GetRequestContext(c)
	duration := time.Since(ctx.StartTime).Milliseconds()

	c.JSON(200, SuccessResponse{
		Success:    true,
		Data:       data,
		Message:    message,
		RequestID:  ctx.RequestID,
		Timestamp:  time.Now(),
		Path:       ctx.Path,
		Method:     ctx.Method,
		DurationMs: duration,
	})
}

// Error 错误响应
func (f *ResponseFormatter) Error(c *gin.Context, err *AppError) {
	ctx := GetRequestContext(c)
	duration := time.Since(ctx.StartTime).Milliseconds()

	c.JSON(err.HTTPStatus, ErrorResponse{
		Success:    false,
		Error:      err,
		RequestID:  ctx.RequestID,
		Timestamp:  time.Now(),
		Path:       ctx.Path,
		Method:     ctx.Method,
		DurationMs: duration,
	})
}

// Paginated 分页响应
func (f *ResponseFormatter) Paginated(c *gin.Context, data interface{}, page, perPage, total int64) {
	ctx := GetRequestContext(c)
	duration := time.Since(ctx.StartTime).Milliseconds()

	totalPages := int((total + perPage - 1) / perPage)

	c.JSON(200, PaginatedResponse{
		Success: true,
		Data:    data,
		Pagination: Pagination{
			Page:       int(page),
			PerPage:    int(perPage),
			Total:      total,
			TotalPages: totalPages,
			HasNext:    page < int64(totalPages),
			HasPrev:    page > 1,
		},
		RequestID:  ctx.RequestID,
		Timestamp:  time.Now(),
		Path:       ctx.Path,
		Method:     ctx.Method,
		DurationMs: duration,
	})
}

// BadRequest 返回400错误
func (f *ResponseFormatter) BadRequest(c *gin.Context, message string) {
	err := NewAppError(ErrorTypeValidation, "BAD_REQUEST", message)
	f.Error(c, err)
}

// Unauthorized 返回401错误
func (f *ResponseFormatter) Unauthorized(c *gin.Context, message string) {
	err := NewAppError(ErrorTypeValidation, "UNAUTHORIZED", message)
	f.Error(c, err)
}

// Forbidden 返回403错误
func (f *ResponseFormatter) Forbidden(c *gin.Context, message string) {
	err := NewAppError(ErrorTypeValidation, "FORBIDDEN", message)
	f.Error(c, err)
}

// NotFound 返回404错误
func (f *ResponseFormatter) NotFound(c *gin.Context, resource string) {
	err := NewAppError(ErrorTypeValidation, "NOT_FOUND", resource+" not found")
	f.Error(c, err)
}

// InternalError 返回500错误
func (f *ResponseFormatter) InternalError(c *gin.Context, message string) {
	err := NewAppError(ErrorTypeSystem, "INTERNAL_ERROR", message)
	f.Error(c, err)
}

// ValidationError 返回验证错误
func (f *ResponseFormatter) ValidationError(c *gin.Context, message string, details ...string) {
	err := NewAppError(ErrorTypeValidation, "VALIDATION_ERROR", message)
	if len(details) > 0 {
		err.Details = details[0]
	}
	f.Error(c, err)
}

// HelmError 返回Helm错误
func (f *ResponseFormatter) HelmError(c *gin.Context, message string) {
	err := NewAppError(ErrorTypeHelm, "HELM_ERROR", message)
	f.Error(c, err)
}

// KubeError 返回Kubernetes错误
func (f *ResponseFormatter) KubeError(c *gin.Context, message string) {
	err := NewAppError(ErrorTypeKube, "KUBE_ERROR", message)
	f.Error(c, err)
}
