package middleware

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// CORSConfig CORS配置
type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	ExposedHeaders []string
	MaxAge         int
	AllowCredentials bool
}

// DefaultCORSConfig 默认CORS配置（生产环境安全配置）
var DefaultCORSConfig = &CORSConfig{
	// ⚠️  安全警告：生产环境不应使用通配符 "*"
	// 必须明确指定允许的源，如：
	// AllowedOrigins: []string{"https://yourdomain.com", "https://app.yourdomain.com"}
	AllowedOrigins: []string{}, // 空表示必须通过环境变量或配置文件明确设置

	AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
	AllowedHeaders: []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
	ExposedHeaders: []string{"X-Total-Count", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
	MaxAge:         86400, // 24小时
	AllowCredentials: false, // 允许凭据时必须设置具体的AllowedOrigins，不能使用"*"
}

// GetProductionCORSConfig 获取生产环境CORS配置
func GetProductionCORSConfig() *CORSConfig {
	// 从环境变量获取允许的源
	allowedOrigins := strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",")
	// 过滤空字符串
	var filteredOrigins []string
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			filteredOrigins = append(filteredOrigins, origin)
		}
	}

	return &CORSConfig{
		AllowedOrigins: filteredOrigins,
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders: []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
		ExposedHeaders: []string{"X-Total-Count", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
		MaxAge:         86400,
		AllowCredentials: false,
	}
}

// CORSMiddleware CORS中间件
func CORSMiddleware(config *CORSConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultCORSConfig
	}

	return func(c *gin.Context) {
		// 设置CORS头部
		c.Header("Access-Control-Allow-Origin", getAllowOrigin(c, config))
		c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
		c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
		c.Header("Access-Control-Allow-Credentials", strconv.FormatBool(config.AllowCredentials))
		c.Header("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))

		// 处理预检请求
		if c.Request.Method == http.MethodOptions {
			c.Header("Access-Control-Allow-Origin", getAllowOrigin(c, config))
			c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
			c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
			c.Header("Access-Control-Allow-Credentials", strconv.FormatBool(config.AllowCredentials))
			c.Header("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// getAllowOrigin 获取允许的源
func getAllowOrigin(c *gin.Context, config *CORSConfig) string {
	origin := c.GetHeader("Origin")
	
	// 如果配置了特定的允许源，检查是否匹配
	if len(config.AllowedOrigins) > 0 && config.AllowedOrigins[0] != "*" {
		for _, allowedOrigin := range config.AllowedOrigins {
			if origin == allowedOrigin {
				return origin
			}
		}
		return "" // 不允许的源
	}
	
	// 通配符或没有配置特定源
	return origin
}

// SecurityHeadersMiddleware 安全头部中间件
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 防止XSS攻击
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		
		// 内容安全策略
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		
		// HSTS (仅在HTTPS环境下)
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		
		// 隐藏服务器信息
		c.Header("Server", "")
		
		c.Next()
	}
}

// NoCacheMiddleware 禁用缓存中间件
func NoCacheMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Next()
	}
}

// RequestSizeLimitMiddleware 请求大小限制中间件
func RequestSizeLimitMiddleware(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":   "Request entity too large",
				"message": "Request size exceeds the maximum allowed limit",
			})
			return
		}
		c.Next()
	}
}

// ClientIPMiddleware 客户端IP中间件
func ClientIPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := getClientIP(c)
		c.Set("client_ip", clientIP)
		c.Header("X-Real-IP", clientIP)
		c.Header("X-Forwarded-For", clientIP)
		c.Next()
	}
}

// getClientIP 获取真实客户端IP
func getClientIP(c *gin.Context) string {
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

// TimeoutMiddleware 超时中间件
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 创建带有超时的上下文
		ctx := c.Request.Context()
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		
		c.Request = c.Request.WithContext(ctx)
		
		// 设置响应超时头部
		c.Header("X-Response-Timeout", timeout.String())
		
		c.Next()
	}
}