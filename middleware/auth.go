package middleware

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// UserInfo 用户信息
type UserInfo struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	Scopes   []string `json:"scopes"`
	Expiry   time.Time `json:"expiry"`
}

// Authenticator 认证器接口
type Authenticator interface {
	Authenticate(c *gin.Context) (*UserInfo, error)
}

// JWTAuthenticator JWT认证器
type JWTAuthenticator struct {
	secret    string
	issuer    string
	audience  string
}

// NewJWTAuthenticator 创建新的JWT认证器
func NewJWTAuthenticator(secret, issuer, audience string) *JWTAuthenticator {
	return &JWTAuthenticator{
		secret:   secret,
		issuer:   issuer,
		audience: audience,
	}
}

// Authenticate 认证JWT令牌
func (j *JWTAuthenticator) Authenticate(c *gin.Context) (*UserInfo, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}
	
	// 检查Bearer token格式
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, fmt.Errorf("invalid authorization header format")
	}
	
	token := strings.TrimPrefix(authHeader, "Bearer ")
	
	// 这里应该使用实际的JWT库来验证token
	// 为了演示，我们实现一个简单的验证逻辑
	userInfo, err := j.validateJWT(token)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}
	
	return userInfo, nil
}

// validateJWT 验证JWT令牌（待实现）
func (j *JWTAuthenticator) validateJWT(token string) (*UserInfo, error) {
	// ⚠️  安全警告：这是简化实现，不应在生产环境使用
	// 生产环境必须：
	// 1. 使用专业的JWT库（如 github.com/golang-jwt/jwt）
	// 2. 验证签名和过期时间
	// 3. 避免硬编码任何令牌

	// 示例：验证token格式（Base64解码检查）
	// 实际实现应使用完整的JWT验证流程

	// 拒绝空token和已知的不安全token
	if token == "" || token == "demo-token" || token == "test-token" {
		return nil, fmt.Errorf("token is invalid or forbidden")
	}

	// TODO: 实现真正的JWT验证逻辑
	// 建议：
	// - 使用 jwt.Parse() 解析令牌
	// - 验证签名算法（RS256或HS256）
	// - 检查过期时间 (exp)
	// - 验证受众 (aud) 和签发者 (iss)
	// - 从数据库或缓存获取公钥

	return nil, fmt.Errorf("JWT validation not implemented - use a proper JWT library in production")
}

// APIKeyAuthenticator API Key认证器
type APIKeyAuthenticator struct {
	validKeys map[string]*UserInfo
}

// NewAPIKeyAuthenticator 创建新的API Key认证器
func NewAPIKeyAuthenticator(apiKeys map[string]*UserInfo) *APIKeyAuthenticator {
	return &APIKeyAuthenticator{
		validKeys: apiKeys,
	}
}

// Authenticate 认证API Key
func (a *APIKeyAuthenticator) Authenticate(c *gin.Context) (*UserInfo, error) {
	// 尝试从多个来源获取API Key
	apiKey := ""
	
	// 1. 从Header获取
	apiKey = c.GetHeader("X-API-Key")
	if apiKey == "" {
		// 2. 从Query参数获取
		apiKey = c.Query("api_key")
	}
	if apiKey == "" {
		// 3. 从Basic Auth获取
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Basic ") {
			encoded := strings.TrimPrefix(authHeader, "Basic ")
			if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					apiKey = parts[0]
				}
			}
		}
	}
	
	if apiKey == "" {
		return nil, fmt.Errorf("missing API key")
	}
	
	// 验证API Key
	userInfo, exists := a.validKeys[apiKey]
	if !exists {
		return nil, fmt.Errorf("invalid API key")
	}
	
	// 检查过期时间
	if userInfo.Expiry.Before(time.Now()) {
		return nil, fmt.Errorf("API key has expired")
	}
	
	return userInfo, nil
}

// BasicAuthenticator Basic认证器
type BasicAuthenticator struct {
	validCredentials map[string]string // username:password
}

// NewBasicAuthenticator 创建新的Basic认证器
func NewBasicAuthenticator(credentials map[string]string) *BasicAuthenticator {
	return &BasicAuthenticator{
		validCredentials: credentials,
	}
}

// Authenticate 认证Basic认证
func (b *BasicAuthenticator) Authenticate(c *gin.Context) (*UserInfo, error) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Basic ") {
		return nil, fmt.Errorf("missing or invalid basic auth header")
	}
	
	encoded := strings.TrimPrefix(authHeader, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding")
	}
	
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid basic auth format")
	}
	
	username, password := parts[0], parts[1]
	expectedPassword, exists := b.validCredentials[username]
	if !exists || !constantTimeEqual(password, expectedPassword) {
		return nil, fmt.Errorf("invalid credentials")
	}
	
	return &UserInfo{
		ID:       "user-" + username,
		Username: username,
		Roles:    []string{"user"},
		Scopes:   []string{"read", "write"},
	}, nil
}

// constantTimeEqual 使用常量时间比较字符串，避免时序攻击
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	
	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}
	
	return result == 0
}

// AuthMiddleware 认证中间件
func AuthMiddleware(authenticator Authenticator, required bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		userInfo, err := authenticator.Authenticate(c)
		
		if err != nil {
			if required {
				c.Header("WWW-Authenticate", "Bearer realm=\"helm-proxy\"")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":   "Authentication failed",
					"message": err.Error(),
				})
				return
			}
			// 认证失败但不是必需的，继续处理
			c.Next()
			return
		}
		
		// 将用户信息存储到上下文中
		c.Set("user_id", userInfo.ID)
		c.Set("username", userInfo.Username)
		c.Set("user_roles", userInfo.Roles)
		c.Set("user_scopes", userInfo.Scopes)
		c.Set("user_info", userInfo)
		
		c.Next()
	}
}

// OptionalAuthMiddleware 可选认证中间件
func OptionalAuthMiddleware(authenticator Authenticator) gin.HandlerFunc {
	return AuthMiddleware(authenticator, false)
}

// RequiredAuthMiddleware 必需认证中间件
func RequiredAuthMiddleware(authenticator Authenticator) gin.HandlerFunc {
	return AuthMiddleware(authenticator, true)
}

// RoleMiddleware 角色检查中间件
func RoleMiddleware(allowedRoles []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(allowedRoles) == 0 {
			c.Next()
			return
		}
		
		userRoles := c.GetStringSlice("user_roles")
		if len(userRoles) == 0 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"message": "User roles not found",
			})
			return
		}
		
		// 检查用户是否具有所需角色之一
		for _, role := range userRoles {
			for _, allowedRole := range allowedRoles {
				if role == allowedRole {
					c.Next()
					return
				}
			}
		}
		
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":   "Access denied",
			"message": "Insufficient permissions",
		})
	}
}

// ScopeMiddleware 权限检查中间件
func ScopeMiddleware(requiredScopes []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(requiredScopes) == 0 {
			c.Next()
			return
		}
		
		userScopes := c.GetStringSlice("user_scopes")
		if len(userScopes) == 0 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"message": "User scopes not found",
			})
			return
		}
		
		// 检查用户是否具有所有必需的权限
		hasAllScopes := true
		for _, requiredScope := range requiredScopes {
			found := false
			for _, userScope := range userScopes {
				if userScope == requiredScope {
					found = true
					break
				}
			}
			if !found {
				hasAllScopes = false
				break
			}
		}
		
		if !hasAllScopes {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"message": "Insufficient scope permissions",
			})
			return
		}
		
		c.Next()
	}
}