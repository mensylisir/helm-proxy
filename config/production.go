package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ProductionConfig 生产环境优化配置
type ProductionConfig struct {
	// 部署相关
	DefaultTimeout int    `yaml:"default_timeout" env:"DEFAULT_TIMEOUT"`
	DefaultWait    bool   `yaml:"default_wait" env:"DEFAULT_WAIT"`
	MaxRetries     int    `yaml:"max_retries" env:"MAX_RETRIES"`
	RetryDelay     string `yaml:"retry_delay" env:"RETRY_DELAY"`

	// 命名空间验证
	ValidateNamespace bool `yaml:"validate_namespace" env:"VALIDATE_NAMESPACE"`

	// 端口验证
	ValidateNodePort bool   `yaml:"validate_nodeport" env:"VALIDATE_NODEPORT"`
	NodePortRange    string `yaml:"nodeport_range" env:"NODEPORT_RANGE"`

	// 密码安全
	RequireStrongPassword bool `yaml:"require_strong_password" env:"REQUIRE_STRONG_PASSWORD"`
	PasswordMinLength     int  `yaml:"password_min_length" env:"PASSWORD_MIN_LENGTH"`

	// 仓库验证
	ValidateExternalId bool `yaml:"validate_external_id" env:"VALIDATE_EXTERNAL_ID"`

	// 资源限制
	MaxConcurrentDeploys int `yaml:"max_concurrent_deploys" env:"MAX_CONCURRENT_DEPLOYS"`

	// 日志级别
	LogLevel string `yaml:"log_level" env:"LOG_LEVEL"`
}

// DefaultProductionConfig 返回生产环境默认配置
func DefaultProductionConfig() *ProductionConfig {
	return &ProductionConfig{
		DefaultTimeout:        300,
		DefaultWait:           false,
		MaxRetries:            3,
		RetryDelay:            "30s",
		ValidateNamespace:     true,
		ValidateNodePort:      true,
		NodePortRange:         "30000-32767",
		RequireStrongPassword: true,
		// ⚠️  密码最小长度：统一为12（与api/production.go保持一致）
		PasswordMinLength:     12,
		ValidateExternalId:    true,
		MaxConcurrentDeploys:  5,
		LogLevel:              "info",
	}
}

// ValidateNodePortRange 验证NodePort是否在有效范围内
func (p *ProductionConfig) ValidateNodePortRange(nodePort string) error {
	if !p.ValidateNodePort {
		return nil
	}

	// 解析端口范围
	parts := strings.Split(p.NodePortRange, "-")
	if len(parts) != 2 {
		return fmt.Errorf("invalid nodeport range format: %s", p.NodePortRange)
	}

	minPort, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid min port in range: %v", err)
	}

	maxPort, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid max port in range: %v", err)
	}

	// 验证端口
	port, err := strconv.Atoi(nodePort)
	if err != nil {
		return fmt.Errorf("invalid nodeport: %s", nodePort)
	}

	if port < minPort || port > maxPort {
		return fmt.Errorf("nodeport %d out of range [%d-%d]", port, minPort, maxPort)
	}

	return nil
}

// ValidatePassword 验证密码强度
func (p *ProductionConfig) ValidatePassword(password string) error {
	if !p.RequireStrongPassword {
		return nil
	}

	if len(password) < p.PasswordMinLength {
		return fmt.Errorf("password too short, minimum length is %d", p.PasswordMinLength)
	}

	// 检查是否包含大小写字母、数字和特殊字符
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return fmt.Errorf("password must contain uppercase, lowercase, numbers, and special characters")
	}

	return nil
}

// ValidateExternalIdFormat 验证externalId格式
func (p *ProductionConfig) ValidateExternalIdFormat(externalId string) error {
	if !p.ValidateExternalId {
		return nil
	}

	// 检查格式：catalog://?catalog=<仓库名>&template=<模板名>&version=<版本>
	if !strings.HasPrefix(externalId, "catalog://") {
		return fmt.Errorf("externalId must start with 'catalog://'")
	}

	if !strings.Contains(externalId, "catalog=") {
		return fmt.Errorf("externalId must contain 'catalog=' parameter")
	}

	if !strings.Contains(externalId, "template=") {
		return fmt.Errorf("externalId must contain 'template=' parameter")
	}

	return nil
}
