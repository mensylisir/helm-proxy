package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 主配置结构体
type Config struct {
	// 服务器配置
	Server ServerConfig `yaml:"server"`

	// Helm 配置
	Helm HelmConfig `yaml:"helm"`

	// 安全配置
	Security SecurityConfig `yaml:"security"`

	// 监控配置
	Monitoring MonitoringConfig `yaml:"monitoring"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port         string `yaml:"port" env:"PORT" default:"8443"`
	ReadTimeout  int    `yaml:"readTimeout" env:"READ_TIMEOUT" default:"30"`
	WriteTimeout int    `yaml:"writeTimeout" env:"WRITE_TIMEOUT" default:"30"`
	IdleTimeout  int    `yaml:"idleTimeout" env:"IDLE_TIMEOUT" default:"120"`
	MaxBodySize  int64  `yaml:"maxBodySize" env:"MAX_BODY_SIZE" default:"10485760"` // 10MB
}

// HelmConfig Helm 相关配置
type HelmConfig struct {
	Driver     string            `yaml:"driver" env:"HELM_DRIVER" default:"secret"`
	RepoMap    map[string]string `yaml:"repos"`
	CacheDir   string            `yaml:"cacheDir" env:"HELM_CACHE_DIR" default:"/tmp/helm-cache"`
	ConfigDir  string            `yaml:"configDir" env:"HELM_CONFIG_DIR" default:"/tmp/helm-config"`
	Timeout    int               `yaml:"timeout" env:"HELM_TIMEOUT" default:"300"`
	MaxHistory int               `yaml:"maxHistory" env:"HELM_MAX_HISTORY" default:"10"`
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	CORS      CORSConfig      `yaml:"cors"`
	RateLimit RateLimitConfig `yaml:"rateLimit"`
	Auth      AuthConfig      `yaml:"auth"`
}

// CORSConfig CORS 配置
type CORSConfig struct {
	Enabled          bool     `yaml:"enabled" env:"CORS_ENABLED" default:"false"`
	AllowOrigins     []string `yaml:"allowOrigins" env:"CORS_ALLOW_ORIGINS"`
	AllowMethods     []string `yaml:"allowMethods" env:"CORS_ALLOW_METHODS" default:"GET,POST,PUT,DELETE,OPTIONS"`
	AllowHeaders     []string `yaml:"allowHeaders" env:"CORS_ALLOW_HEADERS" default:"Origin,Content-Type,Accept,Authorization"`
	AllowCredentials bool     `yaml:"allowCredentials" env:"CORS_ALLOW_CREDENTIALS" default:"true"`
	MaxAge           int      `yaml:"maxAge" env:"CORS_MAX_AGE" default:"86400"`
}

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	Enabled   bool     `yaml:"enabled" env:"RATE_LIMIT_ENABLED" default:"true"`
	Rate      int      `yaml:"rate" env:"RATE_LIMIT_RATE" default:"100"`
	Burst     int      `yaml:"burst" env:"RATE_LIMIT_BURST" default:"200"`
	IPLimit   int      `yaml:"ipLimit" env:"IP_LIMIT" default:"1000"`
	BlockTime int      `yaml:"blockTime" env:"BLOCK_TIME" default:"300"`
	Whitelist []string `yaml:"whitelist" env:"WHITELIST"`
}

// AuthConfig 认证配置
type AuthConfig struct {
	Enabled       bool              `yaml:"enabled" env:"AUTH_ENABLED" default:"false"`
	JWTSecret     string            `yaml:"jwtSecret" env:"JWT_SECRET"`
	JWTTokenTTL   int               `yaml:"jwtTokenTTL" env:"JWT_TOKEN_TTL" default:"3600"` // 1小时
	APIKeyEnabled bool              `yaml:"apiKeyEnabled" env:"API_KEY_ENABLED" default:"false"`
	APIKeys       map[string]string `yaml:"apiKeys"` // API Key 到用户的映射
}

// MonitoringConfig 监控配置
type MonitoringConfig struct {
	MetricsEnabled bool              `yaml:"metricsEnabled" env:"METRICS_ENABLED" default:"true"`
	HealthCheck    HealthCheckConfig `yaml:"healthCheck"`
	LogLevel       string            `yaml:"logLevel" env:"LOG_LEVEL" default:"info"`
	LogFormat      string            `yaml:"logFormat" env:"LOG_FORMAT" default:"json"`
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	Path     string `yaml:"path" env:"HEALTH_PATH" default:"/health"`
	Timeout  int    `yaml:"timeout" env:"HEALTH_TIMEOUT" default:"10"`
	Interval int    `yaml:"interval" env:"HEALTH_INTERVAL" default:"30"`
}

// Load 加载配置
func Load() (*Config, error) {
	return LoadWithOptions("", "", "")
}

// LoadWithOptions 使用命令行参数和配置文件加载配置
func LoadWithOptions(configFile, port, logLevel string) (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port: "8443",
		},
		Helm: HelmConfig{
			Driver: "secret",
		},
		Security: SecurityConfig{
			CORS: CORSConfig{
				Enabled: false,
			},
			RateLimit: RateLimitConfig{
				Enabled: true,
				Rate:    100,
				Burst:   200,
			},
			Auth: AuthConfig{
				Enabled:     false,
				JWTTokenTTL: 3600,
			},
		},
		Monitoring: MonitoringConfig{
			MetricsEnabled: true,
			HealthCheck: HealthCheckConfig{
				Path:     "/health",
				Timeout:  10,
				Interval: 30,
			},
			LogLevel:  "info",
			LogFormat: "json",
		},
	}

	// 1. 从环境变量加载
	if err := loadFromEnv(cfg); err != nil {
		return nil, fmt.Errorf("failed to load from environment: %w", err)
	}

	// 2. 从配置文件加载（如果存在）
	if configFile == "" {
		configFile = os.Getenv("CONFIG_FILE")
	}
	if configFile == "" {
		// 尝试默认配置文件路径
		defaultPaths := []string{
			"config.yaml",
			"config/config.yaml",
			"/etc/helm-proxy/config.yaml",
			filepath.Join(os.Getenv("HOME"), ".config", "helm-proxy", "config.yaml"),
		}

		for _, path := range defaultPaths {
			if _, err := os.Stat(path); err == nil {
				configFile = path
				break
			}
		}
	}

	if configFile != "" {
		if err := loadFromFile(configFile, cfg); err != nil {
			return nil, fmt.Errorf("failed to load from file %s: %w", configFile, err)
		}
	}

	// 覆盖端口配置
	if port != "" {
		cfg.Server.Port = port
	}

	// 覆盖日志级别配置
	if logLevel != "" {
		cfg.Monitoring.LogLevel = logLevel
	}

	// 3. 验证配置
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// 4. 初始化 Helm 仓库配置（向后兼容）
	initializeHelmRepos(cfg)

	return cfg, nil
}

// loadFromEnv 从环境变量加载配置
func loadFromEnv(cfg *Config) error {
	// 使用标准的 envconfig 或类似库来处理环境变量
	// 这里简化实现，实际项目中建议使用专业库
	return nil
}

// loadFromFile 从配置文件加载
func loadFromFile(filename string, cfg *Config) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, cfg)
}

// Validate 验证配置
func (c *Config) Validate() error {
	// 验证端口
	if c.Server.Port == "" {
		return fmt.Errorf("server port cannot be empty")
	}

	// 验证 Helm 驱动
	validDrivers := map[string]bool{"secret": true, "configmap": true, "memory": true}
	if !validDrivers[c.Helm.Driver] {
		return fmt.Errorf("invalid helm driver: %s, must be one of: secret, configmap, memory", c.Helm.Driver)
	}

	// 验证 URL 格式
	for name, urlStr := range c.Helm.RepoMap {
		if _, err := url.Parse(urlStr); err != nil {
			return fmt.Errorf("invalid repo URL for %s: %w", name, err)
		}
	}

	// 验证 JWT 配置
	if c.Security.Auth.Enabled && c.Security.Auth.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required when auth is enabled")
	}

	// 验证限流配置
	if c.Security.RateLimit.Rate <= 0 {
		return fmt.Errorf("rate limit rate must be positive")
	}

	return nil
}

// initializeHelmRepos 初始化 Helm 仓库配置（向后兼容）
func initializeHelmRepos(cfg *Config) {
	// 如果没有配置仓库，添加默认配置
	if len(cfg.Helm.RepoMap) == 0 {
		cfg.Helm.RepoMap = map[string]string{
			"stable":     "https://charts.helm.sh/stable",
			"bitnami":    "https://charts.bitnami.com/bitnami",
			"prometheus": "https://prometheus-community.github.io/helm-charts",
		}
	}

	// 从环境变量覆盖仓库配置
	repoEnv := os.Getenv("HELM_REPOS")
	if repoEnv != "" {
		repoMap := make(map[string]string)
		parts := strings.Split(repoEnv, ",")
		for _, p := range parts {
			kv := strings.Split(p, "=")
			if len(kv) == 2 {
				repoMap[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
		if len(repoMap) > 0 {
			cfg.Helm.RepoMap = repoMap
		}
	}
}

// GetPort 获取端口（向后兼容方法）
func (c *Config) GetPort() string {
	return c.Server.Port
}

// GetRepoMap 获取仓库映射（向后兼容方法）
func (c *Config) GetRepoMap() map[string]string {
	return c.Helm.RepoMap
}
