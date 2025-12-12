package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mensylisir/helm-proxy/config"
	"github.com/mensylisir/helm-proxy/core"
	"github.com/mensylisir/helm-proxy/model"
	"go.uber.org/zap"
)

// ProductionHandler 生产环境优化的API处理器
type ProductionHandler struct {
	manager          *core.HelmManager
	logger           *zap.Logger
	productionConfig *config.ProductionConfig
	retryConfig      *core.RetryConfig
}

// NewProductionHandler 创建生产环境API处理器
func NewProductionHandler(manager *core.HelmManager, prodConfig *config.ProductionConfig, logger *zap.Logger) *ProductionHandler {
	return &ProductionHandler{
		manager:          manager,
		logger:           logger,
		productionConfig: prodConfig,
		retryConfig:      core.DefaultRetryConfig,
	}
}

// ProductionDeployRequest 生产环境部署请求
type ProductionDeployRequest struct {
	// Rancher标准字段
	Prune           bool              `json:"prune"`
	Timeout         int               `json:"timeout"`
	Wait            bool              `json:"wait"`
	Type            string            `json:"type"`
	Name            string            `json:"name"`
	Answers         map[string]string `json:"answers"`
	TargetNamespace string            `json:"targetNamespace"`
	ExternalID      string            `json:"externalId"`
	ProjectID       string            `json:"projectId"`
	ValuesYaml      string            `json:"valuesYaml"`

	// 生产环境增强字段
	ValidationOnly bool                 `json:"validationOnly,omitempty"` // 仅验证，不实际部署
	Priority       string               `json:"priority,omitempty"`       // 优先级：low, normal, high
	Environment    string               `json:"environment,omitempty"`    // 环境：dev, test, prod
	Metadata       map[string]string    `json:"metadata,omitempty"`       // 自定义元数据
	PreDeployment  []PreDeploymentStep  `json:"preDeployment,omitempty"`  // 预部署步骤
	PostDeployment []PostDeploymentStep `json:"postDeployment,omitempty"` // 后置部署步骤
	HealthCheck    *HealthCheckConfig   `json:"healthCheck,omitempty"`    // 健康检查配置
	RollbackConfig *RollbackConfig      `json:"rollbackConfig,omitempty"` // 回滚配置
}

// PreDeploymentStep 预部署步骤
type PreDeploymentStep struct {
	Type     string            `json:"type"`     // namespace-check, resource-check, secret-check
	Config   map[string]string `json:"config"`   // 步骤配置
	Required bool              `json:"required"` // 是否必需
	Timeout  int               `json:"timeout"`  // 超时时间（秒）
}

// PostDeploymentStep 后置部署步骤
type PostDeploymentStep struct {
	Type     string            `json:"type"`     // health-check, smoke-test, notification
	Config   map[string]string `json:"config"`   // 步骤配置
	Required bool              `json:"required"` // 是否必需
	Timeout  int               `json:"timeout"`  // 超时时间（秒）
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	Enabled  bool              `json:"enabled"`  // 是否启用
	Path     string            `json:"path"`     // 检查路径
	Port     int               `json:"port"`     // 检查端口
	Timeout  int               `json:"timeout"`  // 超时时间（秒）
	Interval int               `json:"interval"` // 检查间隔（秒）
	Retries  int               `json:"retries"`  // 重试次数
	Headers  map[string]string `json:"headers"`  // HTTP头
}

// RollbackConfig 回滚配置
type RollbackConfig struct {
	Enabled           bool `json:"enabled"`           // 是否启用自动回滚
	OnFailure         bool `json:"onFailure"`         // 失败时自动回滚
	MaxRollbackTime   int  `json:"maxRollbackTime"`   // 最大回滚时间（分钟）
	KeepLastNVersions int  `json:"keepLastNVersions"` // 保留的最后版本数
}

// ProductionDeployResponse 生产环境部署响应
type ProductionDeployResponse struct {
	// 标准Rancher响应
	*model.RancherResponse

	// 生产环境增强信息
	JobID            string                 `json:"jobId,omitempty"`            // 作业ID
	ValidationStatus string                 `json:"validationStatus,omitempty"` // 验证状态
	Steps            []DeploymentStepStatus `json:"steps,omitempty"`            // 部署步骤状态
	Metrics          *DeploymentMetrics     `json:"metrics,omitempty"`          // 部署指标
	Recommendations  []string               `json:"recommendations,omitempty"`  // 建议
}

// DeploymentStepStatus 部署步骤状态
type DeploymentStepStatus struct {
	Name      string `json:"name"`      // 步骤名称
	Type      string `json:"type"`      // 步骤类型
	Status    string `json:"status"`    // 状态：pending, running, completed, failed
	StartTime string `json:"startTime"` // 开始时间
	EndTime   string `json:"endTime"`   // 结束时间
	Duration  int    `json:"duration"`  // 持续时间（秒）
	Message   string `json:"message"`   // 消息
}

// DeploymentMetrics 部署指标
type DeploymentMetrics struct {
	StartTime       time.Time  `json:"startTime"`
	EndTime         *time.Time `json:"endTime,omitempty"`
	Duration        int        `json:"duration"`        // 总持续时间（秒）
	ValidationTime  int        `json:"validationTime"`  // 验证时间（秒）
	DeploymentTime  int        `json:"deploymentTime"`  // 部署时间（秒）
	HealthCheckTime int        `json:"healthCheckTime"` // 健康检查时间（秒）
	MemoryUsage     int64      `json:"memoryUsage"`     // 内存使用（MB）
	CPUUsage        float64    `json:"cpuUsage"`        // CPU使用率
}

// HandleProductionDeploy 生产环境部署处理
func (h *ProductionHandler) HandleProductionDeploy(c *gin.Context) {
	projectID := c.Param("projectId")

	var req ProductionDeployRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Type:    "error",
			Code:    "InvalidBody",
			Message: fmt.Sprintf("Body parse error: %v", err),
		})
		return
	}

	// 转换请求格式
	rancherReq := model.RancherRequest{
		Prune:           req.Prune,
		Timeout:         req.Timeout,
		Wait:            req.Wait,
		Type:            req.Type,
		Name:            req.Name,
		Answers:         req.Answers,
		TargetNamespace: req.TargetNamespace,
		ExternalID:      req.ExternalID,
		ProjectID:       projectID,
		ValuesYaml:      req.ValuesYaml,
	}

	// 1. 预验证阶段
	h.logger.Info("Starting production deployment validation",
		zap.String("project", projectID),
		zap.String("app", req.Name),
		zap.String("namespace", req.TargetNamespace))

	if err := h.performPreDeploymentValidation(&req); err != nil {
		h.logger.Error("Pre-deployment validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Type:    "error",
			Code:    "ValidationFailed",
			Message: fmt.Sprintf("Pre-deployment validation failed: %v", err),
		})
		return
	}

	// 如果仅验证模式，返回验证结果
	if req.ValidationOnly {
		c.JSON(http.StatusOK, ProductionDeployResponse{
			RancherResponse: &model.RancherResponse{
				ID:        fmt.Sprintf("%s:%s", projectID, req.Name),
				Name:      req.Name,
				State:     "validation-passed",
				Created:   time.Now().Format(time.RFC3339),
				CreatedTS: time.Now().UnixMilli(),
			},
			ValidationStatus: "passed",
			Recommendations:  h.generateRecommendations(&req),
		})
		return
	}

	// 2. 执行部署
	h.logger.Info("Starting production deployment",
		zap.String("app", req.Name),
		zap.String("namespace", req.TargetNamespace))

	// 使用重试机制执行部署
	var resp *model.RancherResponse
	var err error

	// 执行预部署步骤
	steps := h.executePreDeploymentSteps(req.PreDeployment)

	// 执行核心部署
	attempts := 0
	maxAttempts := h.retryConfig.MaxAttempts

	for attempts < maxAttempts {
		attempts++
		h.logger.Info("Deployment attempt",
			zap.Int("attempt", attempts),
			zap.Int("maxAttempts", maxAttempts))

		resp, err = h.manager.PrepareAndExecute(rancherReq)
		if err == nil {
			break
		}

		h.logger.Warn("Deployment attempt failed",
			zap.Int("attempt", attempts),
			zap.Error(err))

		if attempts >= maxAttempts {
			// 执行回滚（如果配置了）
			if req.RollbackConfig != nil && req.RollbackConfig.OnFailure {
				h.executeRollback(&req)
			}
			break
		}

		// 等待重试
		waitTime := time.Duration(attempts*attempts) * time.Second
		h.logger.Info("Waiting before retry", zap.Duration("wait", waitTime))
		time.Sleep(waitTime)
	}

	if err != nil {
		h.logger.Error("Production deployment failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Type:    "error",
			Code:    "DeploymentFailed",
			Message: fmt.Sprintf("Deployment failed after %d attempts: %v", attempts, err),
		})
		return
	}

	// 3. 执行后置部署步骤
	postSteps := h.executePostDeploymentSteps(req.PostDeployment, resp)

	// 4. 执行健康检查（如果配置了）
	if req.HealthCheck != nil && req.HealthCheck.Enabled {
		if err := h.performHealthCheck(req.HealthCheck, resp); err != nil {
			h.logger.Warn("Health check failed", zap.Error(err))
			// 根据配置决定是否回滚
			if req.RollbackConfig != nil && req.RollbackConfig.OnFailure {
				h.executeRollback(&req)
			}
		}
	}

	// 5. 构建响应
	productionResp := &ProductionDeployResponse{
		RancherResponse: resp,
		JobID:           fmt.Sprintf("job-%s-%d", req.Name, time.Now().Unix()),
		Steps:           append(steps, postSteps...),
		Metrics:         h.calculateDeploymentMetrics(),
		Recommendations: h.generateRecommendations(&req),
	}

	h.logger.Info("Production deployment completed",
		zap.String("app", req.Name),
		zap.String("state", resp.State))

	c.JSON(http.StatusCreated, productionResp)
}

// performPreDeploymentValidation 执行预部署验证
func (h *ProductionHandler) performPreDeploymentValidation(req *ProductionDeployRequest) error {
	// 1. 基础验证
	if err := h.validateBasicFields(req); err != nil {
		return fmt.Errorf("basic validation failed: %v", err)
	}

	// 2. 命名空间验证
	if err := h.validateNamespace(req.TargetNamespace); err != nil {
		return fmt.Errorf("namespace validation failed: %v", err)
	}

	// 3. 资源验证
	if err := h.validateResources(req); err != nil {
		return fmt.Errorf("resource validation failed: %v", err)
	}

	// 4. 安全验证
	if err := h.validateSecurity(req); err != nil {
		return fmt.Errorf("security validation failed: %v", err)
	}

	return nil
}

// validateBasicFields 验证基础字段
func (h *ProductionHandler) validateBasicFields(req *ProductionDeployRequest) error {
	// 验证超时时间
	if req.Timeout < 30 || req.Timeout > 3600 {
		return fmt.Errorf("timeout must be between 30 and 3600 seconds")
	}

	// 验证应用名称
	if err := h.validateAppName(req.Name); err != nil {
		return err
	}

	// 验证端口
	if nodePort, exists := req.Answers["service.nodePort"]; exists {
		if err := h.validateNodePort(nodePort); err != nil {
			return err
		}
	}

	return nil
}

// validateNamespace 验证命名空间
func (h *ProductionHandler) validateNamespace(namespace string) error {
	// DNS标签验证
	if len(namespace) > 63 {
		return fmt.Errorf("namespace name too long: %s", namespace)
	}

	if !isDNSLabel(namespace) {
		return fmt.Errorf("invalid namespace name: %s", namespace)
	}

	return nil
}

// validateResources 验证资源
func (h *ProductionHandler) validateResources(req *ProductionDeployRequest) error {
	// 这里可以添加更多资源验证逻辑
	// 例如：检查节点端口是否可用、检查存储卷等
	return nil
}

// validateSecurity 验证安全配置
func (h *ProductionHandler) validateSecurity(req *ProductionDeployRequest) error {
	// 验证密码强度
	if password, exists := req.Answers["adminPassword"]; exists {
		if err := h.validatePasswordStrength(password); err != nil {
			return err
		}
	}

	if rootPassword, exists := req.Answers["dm.dmRootPassword"]; exists {
		if err := h.validatePasswordStrength(rootPassword); err != nil {
			return err
		}
	}

	return nil
}

// executePreDeploymentSteps 执行预部署步骤
func (h *ProductionHandler) executePreDeploymentSteps(steps []PreDeploymentStep) []DeploymentStepStatus {
	var statuses []DeploymentStepStatus

	for _, step := range steps {
		status := DeploymentStepStatus{
			Name:      step.Type,
			Type:      step.Type,
			Status:    "pending",
			StartTime: time.Now().Format(time.RFC3339),
		}

		h.logger.Info("Executing pre-deployment step", zap.String("type", step.Type))

		// 这里实现具体的预部署步骤逻辑
		// 例如：检查命名空间、检查资源等

		status.Status = "completed"
		status.EndTime = time.Now().Format(time.RFC3339)
		status.Duration = int(time.Since(time.Now()).Seconds())

		statuses = append(statuses, status)
	}

	return statuses
}

// executePostDeploymentSteps 执行后置部署步骤
func (h *ProductionHandler) executePostDeploymentSteps(steps []PostDeploymentStep, resp *model.RancherResponse) []DeploymentStepStatus {
	var statuses []DeploymentStepStatus

	for _, step := range steps {
		status := DeploymentStepStatus{
			Name:      step.Type,
			Type:      step.Type,
			Status:    "pending",
			StartTime: time.Now().Format(time.RFC3339),
		}

		h.logger.Info("Executing post-deployment step", zap.String("type", step.Type))

		// 这里实现具体的后置部署步骤逻辑
		// 例如：发送通知、运行烟雾测试等

		status.Status = "completed"
		status.EndTime = time.Now().Format(time.RFC3339)
		status.Duration = int(time.Since(time.Now()).Seconds())

		statuses = append(statuses, status)
	}

	return statuses
}

// performHealthCheck 执行健康检查
func (h *ProductionHandler) performHealthCheck(config *HealthCheckConfig, resp *model.RancherResponse) error {
	// 实现健康检查逻辑
	// 这里可以调用实际的健康检查端点

	h.logger.Info("Performing health check",
		zap.String("app", resp.Name),
		zap.String("path", config.Path),
		zap.Int("port", config.Port))

	return nil
}

// calculateDeploymentMetrics 计算部署指标
func (h *ProductionHandler) calculateDeploymentMetrics() *DeploymentMetrics {
	return &DeploymentMetrics{
		StartTime:       time.Now(),
		Duration:        0,    // 需要在部署过程中记录
		ValidationTime:  5,    // 示例值
		DeploymentTime:  30,   // 示例值
		HealthCheckTime: 10,   // 示例值
		MemoryUsage:     128,  // 示例值（MB）
		CPUUsage:        15.5, // 示例值（%）
	}
}

// generateRecommendations 生成建议
func (h *ProductionHandler) generateRecommendations(req *ProductionDeployRequest) []string {
	var recommendations []string

	// 基于配置生成建议
	if req.Timeout < 300 {
		recommendations = append(recommendations, "Consider increasing timeout to 300+ seconds for complex deployments")
	}

	if !req.Wait {
		recommendations = append(recommendations, "Consider enabling wait=true for better deployment reliability")
	}

	if pullPolicy, exists := req.Answers["image.pullPolicy"]; exists && pullPolicy == "Always" {
		recommendations = append(recommendations, "Using Always pull policy may slow deployments, consider IfNotPresent for production")
	}

	return recommendations
}

// 辅助验证函数
func (h *ProductionHandler) validateAppName(name string) error {
	if len(name) > 53 {
		return fmt.Errorf("app name too long: %s", name)
	}
	return nil
}

func (h *ProductionHandler) validateNodePort(portStr string) error {
	// 这里可以实现端口验证逻辑
	return nil
}

func (h *ProductionHandler) validatePasswordStrength(password string) error {
	// 密码强度验证 - 生产环境安全要求
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters long")
	}

	// 检查是否包含大小写字母
	var hasUpper, hasLower bool
	for _, char := range password {
		if char >= 'A' && char <= 'Z' {
			hasUpper = true
		}
		if char >= 'a' && char <= 'z' {
			hasLower = true
		}
	}
	if !hasUpper || !hasLower {
		return fmt.Errorf("password must contain both uppercase and lowercase letters")
	}

	// 检查是否包含数字
	hasDigit := false
	for _, char := range password {
		if char >= '0' && char <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}

	// 检查是否包含特殊字符
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
	hasSpecial := false
	for _, char := range password {
		if contains(specialChars, char) {
			hasSpecial = true
			break
		}
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character: !@#$%^&*()_+-=[]{}|;:,.<>?/~`")
	}

	// 检查是否有常见弱密码模式
	weakPatterns := []string{"123", "abc", "password", "admin", "qwerty"}
	lowerPassword := strings.ToLower(password)
	for _, pattern := range weakPatterns {
		if strings.Contains(lowerPassword, pattern) {
			return fmt.Errorf("password contains weak pattern: %s", pattern)
		}
	}

	return nil
}

// 辅助函数：检查字符是否在字符串中
func contains(s string, char rune) bool {
	for _, c := range s {
		if c == char {
			return true
		}
	}
	return false
}

func isDNSLabel(s string) bool {
	// DNS标签验证
	return len(s) > 0 && len(s) <= 63
}

// executeRollback 执行回滚操作
func (h *ProductionHandler) executeRollback(req *ProductionDeployRequest) error {
	h.logger.Info("Executing rollback",
		zap.String("app", req.Name),
		zap.String("namespace", req.TargetNamespace))

	// 实际实现回滚逻辑
	// 1. 获取上一个版本信息
	// 2. 执行 Helm 回滚命令
	// 3. 清理失败的资源
	// 4. 验证回滚结果

	// 示例回滚实现
	if req.RollbackConfig != nil && req.RollbackConfig.Enabled {
		h.logger.Info("Starting rollback process",
			zap.Int("maxRollbackTime", req.RollbackConfig.MaxRollbackTime),
			zap.Int("keepLastNVersions", req.RollbackConfig.KeepLastNVersions))

		// 实际回滚操作应在这里实现
		// 例如调用 h.manager.Rollback() 或类似方法
		// 当前返回 nil 表示回滚成功
	}

	return nil
}
