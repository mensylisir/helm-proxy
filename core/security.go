package core

import (
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/handlers"
)

// SecurityConfig 安全配置
type SecurityConfig struct {
	// HTTP安全配置
	EnableHTTPS           bool   `json:"enable_https"`
	EnableHSTS            bool   `json:"enable_hsts"`
	HSTSMaxAge            int    `json:"hsts_max_age"`
	EnableCSP             bool   `json:"enable_csp"`
	ContentSecurityPolicy string `json:"content_security_policy"`
	EnableXSSProtection   bool   `json:"enable_xss_protection"`
	EnableFrameOptions    bool   `json:"enable_frame_options"`

	// CORS配置
	EnableCORS         bool     `json:"enable_cors"`
	CORSAllowedOrigins []string `json:"cors_allowed_origins"`
	CORSAllowedMethods []string `json:"cors_allowed_methods"`
	CORSAllowedHeaders []string `json:"cors_allowed_headers"`
	CORSMaxAge         int      `json:"cors_max_age"`

	// 请求限流配置
	EnableRateLimit bool    `json:"enable_rate_limit"`
	RateLimitRPS    float64 `json:"rate_limit_rps"`
	RateLimitBurst  int     `json:"rate_limit_burst"`
	RateLimitMemory int     `json:"rate_limit_memory"`

	// 认证配置
	EnableBasicAuth   bool   `json:"enable_basic_auth"`
	BasicAuthUsername string `json:"basic_auth_username"`
	BasicAuthPassword string `json:"basic_auth_password"`

	// IP白名单/黑名单
	EnableIPFilter bool     `json:"enable_ip_filter"`
	AllowedIPs     []string `json:"allowed_ips"`
	BlockedIPs     []string `json:"blocked_ips"`

	// 输入验证配置
	EnableInputValidation        bool  `json:"enable_input_validation"`
	MaxRequestSize               int64 `json:"max_request_size"`
	EnableSQLInjectionProtection bool  `json:"enable_sql_injection_protection"`

	// TLS配置
	TLSMinVersion string `json:"tls_min_version"`
	TLSMaxVersion string `json:"tls_max_version"`
	EnableTLS12   bool   `json:"enable_tls_12"`
	EnableTLS13   bool   `json:"enable_tls_13"`
}

// ClientRateLimiter 客户端限流器
type ClientRateLimiter struct {
	mu      sync.Mutex
	clients map[string]*ClientLimiter
	config  *SecurityConfig
}

type ClientLimiter struct {
	tokens   float64
	lastSeen time.Time
}

// SecurityMiddleware 安全中间件
type SecurityMiddleware struct {
	rateLimiter *ClientRateLimiter
	config      *SecurityConfig
	logger      SecurityLogger
}

// SecurityLogger 日志接口
type SecurityLogger interface {
	Printf(format string, v ...interface{})
	Print(v ...interface{})
}

// NewSecurityConfig 创建安全配置
func NewSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		EnableHTTPS:           false,
		EnableHSTS:            true,
		HSTSMaxAge:            31536000, // 1年
		EnableCSP:             true,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none';",
		EnableXSSProtection:   true,
		EnableFrameOptions:    true,

		EnableCORS:         true,
		CORSAllowedOrigins: []string{"*"},
		CORSAllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		CORSAllowedHeaders: []string{"Content-Type", "Authorization", "X-Requested-With"},
		CORSMaxAge:         86400, // 24小时

		EnableRateLimit: true,
		RateLimitRPS:    10.0,
		RateLimitBurst:  20,
		RateLimitMemory: 1000,

		EnableBasicAuth: false,

		EnableIPFilter: false,

		EnableInputValidation:        true,
		MaxRequestSize:               10 * 1024 * 1024, // 10MB
		EnableSQLInjectionProtection: true,

		TLSMinVersion: "1.2",
		TLSMaxVersion: "1.3",
		EnableTLS12:   true,
		EnableTLS13:   true,
	}
}

// NewSecurityMiddleware 创建安全中间件
func NewSecurityMiddleware(config *SecurityConfig, logger Logger) *SecurityMiddleware {
	return &SecurityMiddleware{
		rateLimiter: &ClientRateLimiter{
			clients: make(map[string]*ClientLimiter),
			config:  config,
		},
		config: config,
		logger: logger,
	}
}

// SecurityMiddlewareChain 创建安全中间件链
func SecurityMiddlewareChain(next http.Handler, securityConfig *SecurityConfig, logger Logger) http.Handler {
	security := NewSecurityMiddleware(securityConfig, logger)

	middlewares := []func(http.Handler) http.Handler{
		security.IPFilterMiddleware,
		security.RateLimitMiddleware,
		security.InputValidationMiddleware,
		security.SecurityHeadersMiddleware,
		security.CORSMiddleware,
		security.BasicAuthMiddleware,
	}

	// 应用中间件（从外到内）
	for i := len(middlewares) - 1; i >= 0; i-- {
		next = middlewares[i](next)
	}

	return next
}

// SecurityHeadersMiddleware 安全头中间件
func (s *SecurityMiddleware) SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HSTS (HTTP Strict Transport Security)
		if s.config.EnableHSTS {
			w.Header().Set("Strict-Transport-Security",
				fmt.Sprintf("max-age=%d; includeSubDomains; preload", s.config.HSTSMaxAge))
		}

		// CSP (Content Security Policy)
		if s.config.EnableCSP && s.config.ContentSecurityPolicy != "" {
			w.Header().Set("Content-Security-Policy", s.config.ContentSecurityPolicy)
		}

		// XSS Protection
		if s.config.EnableXSSProtection {
			w.Header().Set("X-XSS-Protection", "1; mode=block")
		}

		// Frame Options
		if s.config.EnableFrameOptions {
			w.Header().Set("X-Frame-Options", "DENY")
		}

		// Content Type Options
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Referrer Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions Policy
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware CORS中间件
func (s *SecurityMiddleware) CORSMiddleware(next http.Handler) http.Handler {
	if !s.config.EnableCORS {
		return next
	}

	corsHandler := handlers.CORS(
		handlers.AllowedOrigins(s.config.CORSAllowedOrigins),
		handlers.AllowedMethods(s.config.CORSAllowedMethods),
		handlers.AllowedHeaders(s.config.CORSAllowedHeaders),
		handlers.MaxAge(s.config.CORSMaxAge),
		handlers.AllowCredentials(),
	)

	return corsHandler(next)
}

// RateLimitMiddleware 限流中间件
func (s *SecurityMiddleware) RateLimitMiddleware(next http.Handler) http.Handler {
	if !s.config.EnableRateLimit {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := s.getClientIP(r)

		if !s.rateLimiter.Allow(clientIP) {
			http.Error(w, "请求过于频繁，请稍后再试", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Allow 检查是否允许请求
func (rl *ClientRateLimiter) Allow(clientIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	limiter, exists := rl.clients[clientIP]
	if !exists {
		// 新客户端
		limiter = &ClientLimiter{
			tokens:   float64(rl.config.RateLimitBurst),
			lastSeen: now,
		}
		rl.clients[clientIP] = limiter
		return true
	}

	// 计算新令牌数量
	elapsed := now.Sub(limiter.lastSeen).Seconds()
	limiter.tokens += elapsed * rl.config.RateLimitRPS

	if limiter.tokens > float64(rl.config.RateLimitBurst) {
		limiter.tokens = float64(rl.config.RateLimitBurst)
	}

	limiter.lastSeen = now

	if limiter.tokens >= 1.0 {
		limiter.tokens -= 1.0
		return true
	}

	return false
}

// getClientIP 获取客户端IP
func (s *SecurityMiddleware) getClientIP(r *http.Request) string {
	// 检查代理头
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// 解析RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// IPFilterMiddleware IP过滤中间件
func (s *SecurityMiddleware) IPFilterMiddleware(next http.Handler) http.Handler {
	if !s.config.EnableIPFilter {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := s.getClientIP(r)

		// 检查黑名单
		for _, blockedIP := range s.config.BlockedIPs {
			if s.ipMatches(clientIP, blockedIP) {
				http.Error(w, "访问被拒绝", http.StatusForbidden)
				return
			}
		}

		// 检查白名单（如果配置了）
		if len(s.config.AllowedIPs) > 0 {
			allowed := false
			for _, allowedIP := range s.config.AllowedIPs {
				if s.ipMatches(clientIP, allowedIP) {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "访问被拒绝", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// ipMatches 检查IP是否匹配规则
func (s *SecurityMiddleware) ipMatches(ip, pattern string) bool {
	// 精确匹配
	if ip == pattern {
		return true
	}

	// CIDR匹配
	if strings.Contains(pattern, "/") {
		_, cidr, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		targetIP := net.ParseIP(ip)
		if targetIP != nil && cidr.Contains(targetIP) {
			return true
		}
	}

	// 通配符匹配（简单实现）
	if strings.Contains(pattern, "*") {
		regex := strings.ReplaceAll(pattern, "*", ".*")
		matched, _ := regexp.MatchString("^"+regex+"$", ip)
		return matched
	}

	return false
}

// InputValidationMiddleware 输入验证中间件
func (s *SecurityMiddleware) InputValidationMiddleware(next http.Handler) http.Handler {
	if !s.config.EnableInputValidation {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查请求大小
		if s.config.MaxRequestSize > 0 {
			if r.ContentLength > s.config.MaxRequestSize {
				http.Error(w, "请求体过大", http.StatusRequestEntityTooLarge)
				return
			}
		}

		// 读取并验证请求体
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			if err := s.validateRequestBody(r); err != nil {
				http.Error(w, fmt.Sprintf("请求验证失败: %v", err), http.StatusBadRequest)
				return
			}
		}

		// 验证URL参数
		if err := s.validateURLParameters(r.URL.Query()); err != nil {
			http.Error(w, fmt.Sprintf("URL参数验证失败: %v", err), http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// validateRequestBody 验证请求体
func (s *SecurityMiddleware) validateRequestBody(r *http.Request) error {
	// 这里可以实现具体的请求体验证逻辑
	// 例如检查JSON结构、SQL注入等

	if s.config.EnableSQLInjectionProtection {
		// SQL注入防护（示例）
		// 实际应用中应该使用更专业的库或方法
	}

	return nil
}

// validateURLParameters 验证URL参数
func (s *SecurityMiddleware) validateURLParameters(params map[string][]string) error {
	for key, values := range params {
		for _, value := range values {
			// 检查危险字符
			if containsDangerousChars(value) {
				return fmt.Errorf("URL参数包含危险字符: %s=%s", key, value)
			}
		}
	}
	return nil
}

// containsDangerousChars 检查是否包含危险字符
func containsDangerousChars(input string) bool {
	dangerous := []string{
		"<script", "javascript:", "vbscript:",
		"onload", "onerror", "onclick",
		"<iframe", "<object", "<embed",
		"../", "..\\\\", "eval(",
		"drop table", "delete from", "insert into",
		"union select", "--", "/*", "*/",
	}

	lowerInput := strings.ToLower(input)
	for _, danger := range dangerous {
		if strings.Contains(lowerInput, danger) {
			return true
		}
	}
	return false
}

// BasicAuthMiddleware 基本认证中间件
func (s *SecurityMiddleware) BasicAuthMiddleware(next http.Handler) http.Handler {
	if !s.config.EnableBasicAuth {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()

		if !ok {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Restricted\"")
			http.Error(w, "需要认证", http.StatusUnauthorized)
			return
		}

		// 验证用户名和密码
		if !s.validateBasicAuth(username, password) {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Restricted\"")
			http.Error(w, "认证失败", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// validateBasicAuth 验证基本认证
func (s *SecurityMiddleware) validateBasicAuth(username, password string) bool {
	// 使用常量时间比较防止时序攻击
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(s.config.BasicAuthUsername)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(s.config.BasicAuthPassword)) == 1

	return usernameMatch && passwordMatch
}

// TLSConfig 创建TLS配置
func (s *SecurityMiddleware) TLSConfig() *tls.Config {
	config := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		PreferServerCipherSuites: true,
	}

	// 根据配置设置版本
	switch s.config.TLSMinVersion {
	case "1.2":
		config.MinVersion = tls.VersionTLS12
	case "1.3":
		config.MinVersion = tls.VersionTLS13
	}

	switch s.config.TLSMaxVersion {
	case "1.2":
		config.MaxVersion = tls.VersionTLS12
	case "1.3":
		config.MaxVersion = tls.VersionTLS13
	}

	return config
}

// GetSecurityConfigFromEnv 从环境变量加载安全配置
func GetSecurityConfigFromEnv() *SecurityConfig {
	config := NewSecurityConfig()

	// 从环境变量读取配置（如果存在）
	if envConfig := os.Getenv("SECURITY_CONFIG"); envConfig != "" {
		// 这里可以实现从环境变量解析配置的逻辑
		// 例如使用JSON等
	}

	return config
}

// ValidateSecurityConfig 验证安全配置
func ValidateSecurityConfig(config *SecurityConfig) error {
	if config.RateLimitRPS <= 0 {
		return fmt.Errorf("RateLimitRPS 必须大于0")
	}

	if config.RateLimitBurst <= 0 {
		return fmt.Errorf("RateLimitBurst 必须大于0")
	}

	if config.MaxRequestSize <= 0 {
		return fmt.Errorf("MaxRequestSize 必须大于0")
	}

	if config.EnableBasicAuth {
		if config.BasicAuthUsername == "" || config.BasicAuthPassword == "" {
			return fmt.Errorf("启用基本认证时必须设置用户名和密码")
		}
	}

	return nil
}
