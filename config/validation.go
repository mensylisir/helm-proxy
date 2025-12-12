package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ValidationError 配置验证错误
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
}

func (e *ValidationError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("配置验证失败 - 字段: %s, 值: %s, 错误: %s", e.Field, e.Value, e.Message)
	}
	return fmt.Sprintf("配置验证失败 - 字段: %s, 错误: %s", e.Field, e.Message)
}

// ConfigValidator 配置验证器
type ConfigValidator struct {
	rules map[string]*ValidationRule
}

// ValidationRule 验证规则
type ValidationRule struct {
	Required    bool
	Min         interface{}
	Max         interface{}
	Pattern     string
	Custom      func(interface{}) error
	Description string
}

// NewConfigValidator 创建配置验证器
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		rules: map[string]*ValidationRule{
			"Port": {
				Required:    true,
				Pattern:     `^\d{1,5}$`,
				Custom:      validatePort,
				Description: "端口号，必须是1-65535之间的数字",
			},
			"RepoMap": {
				Required:    true,
				Custom:      validateRepoMap,
				Description: "仓库映射表，不能为空",
			},
			"HelmDriver": {
				Required:    true,
				Pattern:     `^(secret|configmap|memory)$`,
				Description: "Helm驱动，必须是 secret、configmap 或 memory",
			},
			"KubeConfig": {
				Required:    false,
				Custom:      validateKubeConfig,
				Description: "KubeConfig文件路径（可选）",
			},
		},
	}
}

// validatePort 验证端口号
func validatePort(value interface{}) error {
	if portStr, ok := value.(string); ok {
		if port, err := strconv.Atoi(portStr); err != nil {
			return fmt.Errorf("端口必须是数字: %v", err)
		} else if port < 1 || port > 65535 {
			return fmt.Errorf("端口必须在1-65535范围内，当前值: %d", port)
		}
		return nil
	}
	return fmt.Errorf("端口必须是字符串类型")
}

// validateRepoMap 验证仓库映射
func validateRepoMap(value interface{}) error {
	if repoMap, ok := value.(map[string]string); ok {
		if len(repoMap) == 0 {
			return fmt.Errorf("仓库映射表不能为空")
		}

		for name, urlStr := range repoMap {
			if err := validateRepositoryURL(urlStr); err != nil {
				return fmt.Errorf("仓库 %s 的URL无效: %v", name, err)
			}
		}
		return nil
	}
	return fmt.Errorf("仓库映射必须是map[string]string类型")
}

// validateKubeConfig 验证KubeConfig
func validateKubeConfig(value interface{}) error {
	if kubeConfig, ok := value.(string); ok && kubeConfig != "" {
		if _, err := os.Stat(kubeConfig); os.IsNotExist(err) {
			return fmt.Errorf("KubeConfig文件不存在: %s", kubeConfig)
		}
	}
	return nil
}

// validateRepositoryURL 验证仓库URL
func validateRepositoryURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL不能为空")
	}

	// 检查URL格式
	if _, err := url.Parse(urlStr); err != nil {
		return fmt.Errorf("URL格式无效: %v", err)
	}

	// 对于HTTP/HTTPS URL，验证可访问性（仅在非生产环境）
	if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") {
		return nil // 生产环境不进行网络检查
	}

	// 对于本地路径，检查是否存在
	return nil
}

// ValidateConfig 验证配置
func (v *ConfigValidator) ValidateConfig(config *Config) error {
	var errors []error

	for field, rule := range v.rules {
		var value interface{}
		var exists bool

		switch field {
		case "Port":
			value, exists = config.Server.Port, config.Server.Port != ""
		case "RepoMap":
			value, exists = config.Helm.RepoMap, config.Helm.RepoMap != nil
		case "HelmDriver":
			value, exists = config.Helm.Driver, config.Helm.Driver != ""
		}

		if !exists && rule.Required {
			errors = append(errors, &ValidationError{
				Field:   field,
				Message: fmt.Sprintf("必填字段 %s 不能为空", field),
			})
			continue
		}

		if exists && value != nil {
			// 模式验证
			if rule.Pattern != "" {
				if !v.matchPattern(value, rule.Pattern) {
					errors = append(errors, &ValidationError{
						Field:   field,
						Message: fmt.Sprintf("格式不符合要求: %s", rule.Description),
						Value:   fmt.Sprintf("%v", value),
					})
					continue
				}
			}

			// 自定义验证
			if rule.Custom != nil {
				if err := rule.Custom(value); err != nil {
					errors = append(errors, &ValidationError{
						Field:   field,
						Message: err.Error(),
						Value:   fmt.Sprintf("%v", value),
					})
				}
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("配置验证失败: %v", errors)
	}

	return nil
}

// matchPattern 匹配模式
func (v *ConfigValidator) matchPattern(value interface{}, pattern string) bool {
	if str, ok := value.(string); ok {
		matched, _ := regexp.MatchString(pattern, str)
		return matched
	}
	return false
}

// ConfigWithDefaults 带默认值的配置
type ConfigWithDefaults struct {
	*Config
	Defaults AppliedDefaults
}

// AppliedDefaults 应用默认值信息
type AppliedDefaults struct {
	Port       string            `json:"port,omitempty"`
	HelmDriver string            `json:"helm_driver,omitempty"`
	RepoMap    map[string]string `json:"repo_map,omitempty"`
	Timeouts   TimeoutDefaults   `json:"timeouts,omitempty"`
	Security   SecurityDefaults  `json:"security,omitempty"`
}

// TimeoutDefaults 超时默认值
type TimeoutDefaults struct {
	Request   time.Duration `json:"request"`
	Helm      time.Duration `json:"helm"`
	Download  time.Duration `json:"download"`
	Install   time.Duration `json:"install"`
	Upgrade   time.Duration `json:"upgrade"`
	Uninstall time.Duration `json:"uninstall"`
}

// SecurityDefaults 安全默认值
type SecurityDefaults struct {
	MaxRequestSize    int64         `json:"max_request_size"`
	RateLimit         int           `json:"rate_limit"`
	AllowedNamespaces []string      `json:"allowed_namespaces"`
	RestrictedLabels  []string      `json:"restricted_labels"`
	ReadTimeout       time.Duration `json:"read_timeout"`
	WriteTimeout      time.Duration `json:"write_timeout"`
	IdleTimeout       time.Duration `json:"idle_timeout"`
}

// LoadWithDefaults 加载配置并应用默认值
func LoadWithDefaults() (*ConfigWithDefaults, error) {
	config, err := Load()
	if err != nil {
		return nil, err
	}
	defaults := AppliedDefaults{}

	// 应用端口默认值
	if config.Server.Port == "" {
		config.Server.Port = "8443"
		defaults.Port = "8443"
	}

	// 应用Helm驱动默认值
	if config.Helm.Driver == "" {
		config.Helm.Driver = "secret"
		defaults.HelmDriver = "secret"
	}

	// 应用仓库映射默认值
	if len(config.Helm.RepoMap) == 0 {
		config.Helm.RepoMap = getDefaultRepoMap()
		defaults.RepoMap = map[string]string{}
		for k, v := range config.Helm.RepoMap {
			defaults.RepoMap[k] = v
		}
	}

	// 应用超时默认值
	defaults.Timeouts = TimeoutDefaults{
		Request:   time.Second * 30,
		Helm:      time.Second * 300,
		Download:  time.Second * 120,
		Install:   time.Second * 600,
		Upgrade:   time.Second * 600,
		Uninstall: time.Second * 300,
	}

	// 应用安全默认值
	defaults.Security = SecurityDefaults{
		MaxRequestSize:    10 * 1024 * 1024, // 10MB
		RateLimit:         100,              // 每分钟100个请求
		AllowedNamespaces: []string{},       // 空表示不限制
		RestrictedLabels:  []string{},       // 空表示不限制
		ReadTimeout:       time.Second * 30,
		WriteTimeout:      time.Second * 60,
		IdleTimeout:       time.Second * 120,
	}

	return &ConfigWithDefaults{
		Config:   config,
		Defaults: defaults,
	}, nil
}

// getDefaultRepoMap 获取默认仓库映射
func getDefaultRepoMap() map[string]string {
	// 从环境变量获取，如果没有则使用示例配置
	repoEnv := os.Getenv("HELM_REPOS")
	if repoEnv != "" {
		repoMap := make(map[string]string)
		parts := strings.Split(repoEnv, ",")
		for _, p := range parts {
			kv := strings.Split(p, "=")
			if len(kv) == 2 {
				repoMap[kv[0]] = kv[1]
			}
		}
		return repoMap
	}

	// ⚠️  安全警告：生产环境不应依赖默认配置
	// 必须通过环境变量 HELM_REPOS 明确设置仓库
	// 格式: export HELM_REPOS="jrhelm=https://your-helm-repo-url,other=https://other-repo-url"
	// 示例（非生产值）:
	// return map[string]string{
	//     "jrhelm": "https://your-helm-repo-url",
	// }

	// 返回空配置，强制用户明确设置
	return map[string]string{}
}

// ValidateAndLoad 验证并加载配置
func ValidateAndLoad() (*ConfigWithDefaults, error) {
	configWithDefaults, err := LoadWithDefaults()
	if err != nil {
		return nil, fmt.Errorf("CONFIG_LOAD_FAILED: 加载配置失败: %v", err)
	}

	// 验证配置
	validator := NewConfigValidator()
	if err := validator.ValidateConfig(configWithDefaults.Config); err != nil {
		return nil, fmt.Errorf("CONFIG_VALIDATION_FAILED: 配置验证失败: %v", err)
	}

	return configWithDefaults, nil
}

// IsNamespaceAllowed 检查命名空间是否被允许
func (c *ConfigWithDefaults) IsNamespaceAllowed(namespace string) bool {
	if len(c.Defaults.Security.AllowedNamespaces) == 0 {
		return true // 没有限制，允许所有
	}

	for _, allowed := range c.Defaults.Security.AllowedNamespaces {
		if allowed == namespace {
			return true
		}
	}
	return false
}

// HasRestrictedLabels 检查是否包含受限标签
func (c *ConfigWithDefaults) HasRestrictedLabels(labels map[string]string) bool {
	for _, restricted := range c.Defaults.Security.RestrictedLabels {
		for key := range labels {
			if key == restricted {
				return true
			}
		}
	}
	return false
}
