package middleware

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ValidationRule 验证规则接口
type ValidationRule interface {
	Validate(value interface{}) error
}

// ValidationError 验证错误结构体
type ValidationError struct {
	Field   string
	Code    string
	Message string
	Meta    interface{}
}

// Error 实现error接口
func (e ValidationError) Error() string {
	return e.Message
}

// NewValidationError 创建验证错误
func NewValidationError(field, code string, meta ...interface{}) ValidationError {
	message := fmt.Sprintf("Validation failed for field '%s': %s", field, code)
	if len(meta) > 0 {
		if msg, ok := meta[0].(string); ok {
			message = msg
		}
	}
	
	return ValidationError{
		Field:   field,
		Code:    code,
		Message: message,
		Meta:    meta,
	}
}

// Type 返回错误类型
func (e ValidationError) Type() string {
	return "validation_error"
}

// RequiredRule 必需字段验证规则
type RequiredRule struct{}

func (r RequiredRule) Validate(value interface{}) error {
	if value == nil {
		return NewValidationError("field", "required")
	}
	
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return NewValidationError("field", "required")
		}
	case []interface{}:
		if len(v) == 0 {
			return NewValidationError("field", "required")
		}
	case map[string]interface{}:
		if len(v) == 0 {
			return NewValidationError("field", "required")
		}
	}
	return nil
}

// MinLengthRule 最小长度验证规则
type MinLengthRule struct {
	Min int
}

func (r MinLengthRule) Validate(value interface{}) error {
	if str, ok := value.(string); ok {
		if len(str) < r.Min {
			return NewValidationError("field", "min_length", fmt.Sprintf("minimum length is %d", r.Min))
		}
	}
	return nil
}

// MaxLengthRule 最大长度验证规则
type MaxLengthRule struct {
	Max int
}

func (r MaxLengthRule) Validate(value interface{}) error {
	if str, ok := value.(string); ok {
		if len(str) > r.Max {
			return NewValidationError("field", "max_length", fmt.Sprintf("maximum length is %d", r.Max))
		}
	}
	return nil
}

// PatternRule 正则表达式验证规则
type PatternRule struct {
	Pattern string
	Regexp  *regexp.Regexp
}

func (r PatternRule) Validate(value interface{}) error {
	if str, ok := value.(string); ok {
		if !r.Regexp.MatchString(str) {
			return NewValidationError("field", "pattern", fmt.Sprintf("must match pattern %s", r.Pattern))
		}
	}
	return nil
}

// EmailRule 邮箱验证规则
type EmailRule struct {
	EmailRegexp *regexp.Regexp
}

func NewEmailRule() EmailRule {
	return EmailRule{
		EmailRegexp: regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
	}
}

func (r EmailRule) Validate(value interface{}) error {
	if str, ok := value.(string); ok {
		if !r.EmailRegexp.MatchString(str) {
			return NewValidationError("field", "email", "must be a valid email address")
		}
	}
	return nil
}

// URLRule URL验证规则
type URLRule struct {
	SchemeRegexp *regexp.Regexp
}

func NewURLRule() URLRule {
	return URLRule{
		SchemeRegexp: regexp.MustCompile(`^(http|https)://[^\s/$.?#].[^\s]*$`),
	}
}

func (r URLRule) Validate(value interface{}) error {
	if str, ok := value.(string); ok {
		if !r.SchemeRegexp.MatchString(str) {
			return NewValidationError("field", "url", "must be a valid URL")
		}
	}
	return nil
}

// IntegerRule 整数验证规则
type IntegerRule struct {
	Min *int64
	Max *int64
}

func (r IntegerRule) Validate(value interface{}) error {
	if str, ok := value.(string); ok {
		num, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			return NewValidationError("field", "integer", "must be a valid integer")
		}
		
		if r.Min != nil && num < *r.Min {
			return NewValidationError("field", "min", fmt.Sprintf("minimum value is %d", *r.Min))
		}
		
		if r.Max != nil && num > *r.Max {
			return NewValidationError("field", "max", fmt.Sprintf("maximum value is %d", *r.Max))
		}
	}
	return nil
}

// ValidationField 验证字段
type ValidationField struct {
	Name        string
	Rules       []ValidationRule
	CustomError string
}

// ValidationSchema 验证模式
type ValidationSchema struct {
	Fields map[string]ValidationField
}

// ValidateSchema 验证模式接口
type ValidateSchema interface {
	Validate(data map[string]interface{}) map[string]string
}

// JSONSchemaValidator JSON模式验证器
type JSONSchemaValidator struct {
	Schemas map[string]*ValidationSchema
}

// NewJSONSchemaValidator 创建新的JSON模式验证器
func NewJSONSchemaValidator() *JSONSchemaValidator {
	return &JSONSchemaValidator{
		Schemas: make(map[string]*ValidationSchema),
	}
}

// AddSchema 添加验证模式
func (v *JSONSchemaValidator) AddSchema(name string, schema *ValidationSchema) {
	v.Schemas[name] = schema
}

// Validate 验证数据
func (v *JSONSchemaValidator) Validate(schemaName string, data map[string]interface{}) map[string]string {
	schema, exists := v.Schemas[schemaName]
	if !exists {
		return map[string]string{"_schema": "Schema not found: " + schemaName}
	}
	
	errors := make(map[string]string)
	
	for fieldName, field := range schema.Fields {
		value, exists := data[fieldName]
		if !exists {
			// 检查是否为必需字段
			hasRequiredRule := false
			for _, rule := range field.Rules {
				if _, ok := rule.(RequiredRule); ok {
					hasRequiredRule = true
					break
				}
			}
			if hasRequiredRule {
				if field.CustomError != "" {
					errors[fieldName] = field.CustomError
				} else {
					errors[fieldName] = "Field '" + fieldName + "' is required"
				}
			}
			continue
		}
		
		// 应用验证规则
		for _, rule := range field.Rules {
			if err := rule.Validate(value); err != nil {
				if field.CustomError != "" {
					errors[fieldName] = field.CustomError
				} else {
					errors[fieldName] = err.Error()
				}
				break // 只返回第一个错误
			}
		}
	}
	
	return errors
}

// ValidateJSONMiddleware JSON验证中间件
func ValidateJSONMiddleware(validator *JSONSchemaValidator, schemaName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var data map[string]interface{}
		
		// 解析JSON请求体
		if err := c.ShouldBindJSON(&data); err != nil {
			c.AbortWithStatusJSON(400, gin.H{
				"error":   "Invalid JSON",
				"message": err.Error(),
			})
			return
		}
		
		// 验证数据
		errors := validator.Validate(schemaName, data)
		if len(errors) > 0 {
			c.AbortWithStatusJSON(400, gin.H{
				"error":   "Validation failed",
				"details": errors,
			})
			return
		}
		
		// 将验证后的数据存储到上下文中
		c.Set("validated_data", data)
		c.Set("raw_data", data)
		
		c.Next()
	}
}

// SanitizeInputMiddleware 输入清理中间件
// 注意：这个中间件只进行基本检查，不读取请求体
func SanitizeInputMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 检查Content-Type
		contentType := c.GetHeader("Content-Type")
		if contentType != "" && !strings.Contains(strings.ToLower(contentType), "application/json") {
			// 不是JSON请求，直接跳过
			c.Next()
			return
		}

		// 检查请求体大小
		contentLength := c.Request.ContentLength
		if contentLength > 10*1024*1024 { // 10MB限制
			HandleBadRequest(c, "Request too large", fmt.Sprintf("Content-Length: %d bytes (max: 10MB)", contentLength))
			c.Abort()
			return
		}

		c.Next()
	}
}

// sanitizeData 清理数据
func sanitizeData(data map[string]interface{}) map[string]interface{} {
	sanitized := make(map[string]interface{})
	
	for key, value := range data {
		switch v := value.(type) {
		case string:
			sanitized[key] = sanitizeString(v)
		case []interface{}:
			sanitized[key] = sanitizeSlice(v)
		case map[string]interface{}:
			sanitized[key] = sanitizeData(v)
		default:
			sanitized[key] = v
		}
	}
	
	return sanitized
}

// sanitizeString 清理字符串
func sanitizeString(str string) string {
	// 移除潜在的危险字符
	str = strings.ReplaceAll(str, "<script>", "")
	str = strings.ReplaceAll(str, "</script>", "")
	str = strings.ReplaceAll(str, "javascript:", "")
	str = strings.ReplaceAll(str, "onload=", "")
	str = strings.ReplaceAll(str, "onerror=", "")
	
	// 移除控制字符
	var result strings.Builder
	for _, r := range str {
		if r >= 32 && r != 127 {
			result.WriteRune(r)
		}
	}
	
	return result.String()
}

// sanitizeSlice 清理切片
func sanitizeSlice(slice []interface{}) []interface{} {
	result := make([]interface{}, len(slice))
	for i, value := range slice {
		switch v := value.(type) {
		case string:
			result[i] = sanitizeString(v)
		case []interface{}:
			result[i] = sanitizeSlice(v)
		case map[string]interface{}:
			result[i] = sanitizeData(v)
		default:
			result[i] = v
		}
	}
	return result
}

// QueryValidationMiddleware 查询参数验证中间件
func QueryValidationMiddleware(rules map[string][]ValidationRule) gin.HandlerFunc {
	return func(c *gin.Context) {
		errors := make(map[string]string)
		
		for field, fieldRules := range rules {
			value := c.Query(field)
			
			for _, rule := range fieldRules {
				if err := rule.Validate(value); err != nil {
					errors[field] = err.Error()
					break
				}
			}
		}
		
		if len(errors) > 0 {
			c.AbortWithStatusJSON(400, gin.H{
				"error":   "Query validation failed",
				"details": errors,
			})
			return
		}
		
		c.Next()
	}
}

// PathValidationMiddleware 路径参数验证中间件
func PathValidationMiddleware(rules map[string][]ValidationRule) gin.HandlerFunc {
	return func(c *gin.Context) {
		errors := make(map[string]string)
		
		for field, fieldRules := range rules {
			value := c.Param(field)
			
			for _, rule := range fieldRules {
				if err := rule.Validate(value); err != nil {
					errors[field] = err.Error()
					break
				}
			}
		}
		
		if len(errors) > 0 {
			c.AbortWithStatusJSON(400, gin.H{
				"error":   "Path validation failed",
				"details": errors,
			})
			return
		}
		
		c.Next()
	}
}

// GenerateRequestID 生成请求ID
func GenerateRequestID() string {
	return time.Now().Format("20060102150405") + "-" + time.Now().Format("000000")
}

// ErrorHandlingMiddleware 错误处理中间件
func ErrorHandlingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		
		// 检查是否有错误发生
		if len(c.Errors) > 0 {
			err := c.Errors.Last()
			c.JSON(c.Writer.Status(), gin.H{
				"error": gin.H{
					"code":    string(err.Type),
					"message": err.Error(),
					"details": err.Meta,
				},
			})
		}
	}
}

// HandleSuccess 处理成功响应
// bypassWrapper: 是否绕过包装层，直接返回数据（用于 Rancher API 兼容性）
func HandleSuccess(c *gin.Context, data interface{}, bypassWrapper ...bool) {
	if len(bypassWrapper) > 0 && bypassWrapper[0] {
		// 绕过包装，直接返回数据（Rancher API 格式）
		c.JSON(http.StatusOK, data)
	} else {
		// 标准包装格式
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    data,
		})
	}
}

// HandlePaginatedSuccess 处理分页成功响应
func HandlePaginatedSuccess(c *gin.Context, data interface{}, total int64, page, pageSize int) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    data,
		"pagination": gin.H{
			"total":      total,
			"page":       page,
			"page_size":  pageSize,
			"total_page": (total + int64(pageSize) - 1) / int64(pageSize),
		},
	})
}

// HandleBadRequest 处理错误请求
func HandleBadRequest(c *gin.Context, message, details string) {
	c.JSON(http.StatusBadRequest, gin.H{
		"success": false,
		"error": gin.H{
			"code":    "bad_request",
			"message": message,
			"details": details,
		},
	})
}

// HandleNotFound 处理未找到错误
func HandleNotFound(c *gin.Context, message, details string) {
	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error": gin.H{
			"code":    "not_found",
			"message": message,
			"details": details,
		},
	})
}

// HandleInternalServerError 处理内部服务器错误
func HandleInternalServerError(c *gin.Context, message, details string) {
	c.JSON(http.StatusInternalServerError, gin.H{
		"success": false,
		"error": gin.H{
			"code":    "internal_server_error",
			"message": message,
			"details": details,
		},
	})
}