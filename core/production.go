package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mensylisir/helm-proxy/config"
	"github.com/mensylisir/helm-proxy/model"
	"go.uber.org/zap"
)

// ProductionValidator 生产环境验证器
type ProductionValidator struct {
	cfg    *config.ProductionConfig
	logger *zap.Logger
}

// NewProductionValidator 创建生产环境验证器
func NewProductionValidator(cfg *config.ProductionConfig, logger *zap.Logger) *ProductionValidator {
	return &ProductionValidator{
		cfg:    cfg,
		logger: logger,
	}
}

// ValidateRancherRequest 验证Rancher请求的完整性和安全性
func (v *ProductionValidator) ValidateRancherRequest(req *model.RancherRequest) error {
	v.logger.Info("Validating Rancher request",
		zap.String("name", req.Name),
		zap.String("namespace", req.TargetNamespace),
		zap.String("projectId", req.ProjectID))

	// 1. 基础字段验证
	if err := v.validateBasicFields(req); err != nil {
		return err
	}

	// 2. 命名空间验证
	if err := v.validateNamespace(req.TargetNamespace); err != nil {
		return err
	}

	// 3. ExternalId验证
	if err := v.validateExternalId(req.ExternalID); err != nil {
		return err
	}

	// 4. 应用参数验证
	if err := v.validateApplicationParameters(req); err != nil {
		return err
	}

	// 5. 安全参数验证
	if err := v.validateSecurityParameters(req.Answers); err != nil {
		return err
	}

	v.logger.Info("Request validation passed", zap.String("name", req.Name))
	return nil
}

func (v *ProductionValidator) validateBasicFields(req *model.RancherRequest) error {
	// 必填字段验证
	if req.Name == "" {
		return fmt.Errorf("application name is required")
	}

	if req.TargetNamespace == "" {
		return fmt.Errorf("target namespace is required")
	}

	if req.ExternalID == "" {
		return fmt.Errorf("externalId is required")
	}

	// 字段长度限制（防止过长字段）
	if len(req.Name) > 63 {
		return fmt.Errorf("application name too long, maximum 63 characters")
	}

	if len(req.TargetNamespace) > 63 {
		return fmt.Errorf("namespace name too long, maximum 63 characters")
	}

	// 字符集验证（只允许字母、数字、连字符和下划线）
	if !isValidDNSLabel(req.Name) {
		return fmt.Errorf("application name contains invalid characters, only alphanumeric and hyphens allowed")
	}

	if !isValidDNSLabel(req.TargetNamespace) {
		return fmt.Errorf("namespace name contains invalid characters, only alphanumeric and hyphens allowed")
	}

	// 项目ID格式验证（可选字段，兼容不同场景）
	if req.ProjectID != "" {
		// 允许的格式：
		// 1. clusterId:projectId (完整格式)
		// 2. clusterId (简化格式，从URL参数获取)
		if !strings.Contains(req.ProjectID, ":") {
			// 如果不包含冒号，检查是否是有效的clusterId格式
			if !isValidDNSLabel(req.ProjectID) {
				return fmt.Errorf("projectId must be in format 'clusterId:projectId' or a valid clusterId")
			}
		} else {
			// 如果包含冒号，验证两部分
			parts := strings.Split(req.ProjectID, ":")
			if len(parts) != 2 {
				return fmt.Errorf("projectId must be in format 'clusterId:projectId'")
			}
			if !isValidDNSLabel(parts[0]) || !isValidDNSLabel(parts[1]) {
				return fmt.Errorf("clusterId and projectId must be valid DNS labels")
			}
		}
	}

	return nil
}

func (v *ProductionValidator) validateNamespace(namespace string) error {
	if !v.cfg.ValidateNamespace {
		return nil
	}

	// Kubernetes命名空间命名规则
	if len(namespace) == 0 || len(namespace) > 63 {
		return fmt.Errorf("namespace name length must be between 1 and 63 characters")
	}

	// 验证字符集
	if !isValidDNSLabel(namespace) {
		return fmt.Errorf("namespace name contains invalid characters")
	}

	// 检查保留字
	reservedNames := []string{"kube-system", "kube-public", "kube-node-lease", "default", "kube-public"}
	for _, reserved := range reservedNames {
		if namespace == reserved {
			return fmt.Errorf("namespace '%s' is reserved", namespace)
		}
	}

	return nil
}

func (v *ProductionValidator) validateExternalId(externalId string) error {
	// 验证格式
	if err := v.cfg.ValidateExternalIdFormat(externalId); err != nil {
		return fmt.Errorf("invalid externalId format: %v", err)
	}

	// 解析并验证各个组件
	parts := strings.Split(externalId, "&")
	if len(parts) < 3 {
		return fmt.Errorf("externalId must contain at least catalog, template, and version parameters")
	}

	for _, part := range parts {
		if strings.Contains(part, "catalog=") {
			catalog := strings.TrimPrefix(part, "catalog://?catalog=")
			if catalog == "" {
				return fmt.Errorf("catalog name cannot be empty")
			}
			if !isValidDNSLabel(catalog) {
				return fmt.Errorf("catalog name contains invalid characters")
			}
		}

		if strings.Contains(part, "template=") {
			template := strings.TrimPrefix(part, "template=")
			if template == "" {
				return fmt.Errorf("template name cannot be empty")
			}
			if !isValidDNSLabel(template) {
				return fmt.Errorf("template name contains invalid characters")
			}
		}

		if strings.Contains(part, "version=") {
			version := strings.TrimPrefix(part, "version=")
			if version == "" {
				return fmt.Errorf("version cannot be empty")
			}
			// 版本号格式验证（简单版本号）
			if !isValidVersion(version) {
				return fmt.Errorf("invalid version format")
			}
		}
	}

	return nil
}

func (v *ProductionValidator) validateApplicationParameters(req *model.RancherRequest) error {
	// 验证answers中的参数
	for key, value := range req.Answers {
		// NodePort验证
		if key == "service.nodePort" {
			if err := v.cfg.ValidateNodePortRange(value); err != nil {
				return fmt.Errorf("invalid nodeport: %v", err)
			}
		}

		// 路径验证
		if key == "path" {
			if !strings.HasPrefix(value, "/") {
				return fmt.Errorf("path must start with '/'")
			}
			if len(value) > 100 {
				return fmt.Errorf("path too long, maximum 100 characters")
			}
		}
	}

	// 验证超时时间
	if req.Timeout < 30 || req.Timeout > 3600 {
		return fmt.Errorf("timeout must be between 30 and 3600 seconds")
	}

	return nil
}

func (v *ProductionValidator) validateSecurityParameters(answers map[string]string) error {
	// 验证密码强度
	if adminPassword, exists := answers["adminPassword"]; exists {
		if err := v.cfg.ValidatePassword(adminPassword); err != nil {
			return fmt.Errorf("adminPassword validation failed: %v", err)
		}
	}

	if dmPassword, exists := answers["dm.dmRootPassword"]; exists {
		if err := v.cfg.ValidatePassword(dmPassword); err != nil {
			return fmt.Errorf("dm.dmRootPassword validation failed: %v", err)
		}
	}

	return nil
}

// 辅助函数：验证DNS标签格式
func isValidDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}

	for i, char := range label {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			(char == '-' && i != 0)) {
			return false
		}
	}
	return true
}

// 辅助函数：验证版本号格式
func isValidVersion(version string) bool {
	if len(version) == 0 || len(version) > 50 {
		return false
	}

	for _, char := range version {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

// ProductionDeploymentHandler 生产环境部署处理器
type ProductionDeploymentHandler struct {
	validator *ProductionValidator
	logger    *zap.Logger
	cfg       *config.ProductionConfig
}

// NewProductionDeploymentHandler 创建生产环境部署处理器
func NewProductionDeploymentHandler(validator *ProductionValidator, cfg *config.ProductionConfig, logger *zap.Logger) *ProductionDeploymentHandler {
	return &ProductionDeploymentHandler{
		validator: validator,
		logger:    logger,
		cfg:       cfg,
	}
}

// ExecuteWithRetry 带重试的生产环境部署
func (h *ProductionDeploymentHandler) ExecuteWithRetry(ctx context.Context, deployFunc func(context.Context) error, operationName string) error {
	maxRetries := h.cfg.MaxRetries
	retryDelay, _ := time.ParseDuration(h.cfg.RetryDelay)

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		h.logger.Info("Executing operation",
			zap.String("operation", operationName),
			zap.Int("attempt", attempt),
			zap.Int("maxRetries", maxRetries))

		err := deployFunc(ctx)
		if err == nil {
			h.logger.Info("Operation completed successfully",
				zap.String("operation", operationName),
				zap.Int("attempt", attempt))
			return nil
		}

		lastErr = err
		h.logger.Warn("Operation failed",
			zap.String("operation", operationName),
			zap.Int("attempt", attempt),
			zap.Error(err))

		// 如果是最后一次尝试，返回错误
		if attempt >= maxRetries {
			break
		}

		// 等待重试
		select {
		case <-ctx.Done():
			return fmt.Errorf("operation cancelled: %v", ctx.Err())
		case <-time.After(retryDelay):
			continue
		}
	}

	return fmt.Errorf("%s failed after %d attempts: %v", operationName, maxRetries, lastErr)
}

// ValidateNamespaceExists 验证命名空间是否存在（可选实现）
func (h *ProductionDeploymentHandler) ValidateNamespaceExists(ctx context.Context, namespace string) error {
	if !h.cfg.ValidateNamespace {
		return nil
	}

	// 这里可以添加实际的Kubernetes API调用来验证命名空间
	// 由于复杂性，生产环境通常会预创建命名空间

	h.logger.Info("Namespace validation skipped (configure K8s client for validation)",
		zap.String("namespace", namespace))

	return nil
}
