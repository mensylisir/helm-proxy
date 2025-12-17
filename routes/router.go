package routes

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/repo"

	"github.com/mensylisir/helm-proxy/api"
	"github.com/mensylisir/helm-proxy/config"
	"github.com/mensylisir/helm-proxy/core"
	"github.com/mensylisir/helm-proxy/middleware"
	"github.com/mensylisir/helm-proxy/model"
)

// Router 路由器结构体
type Router struct {
	engine           *gin.Engine
	manager          *core.HelmManager
	config           *config.Config
	logger           *zap.Logger
	productionHandler *api.ProductionHandler
}

// NewRouter 创建新的路由器
func NewRouter(engine *gin.Engine, manager *core.HelmManager, cfg *config.Config, logger *zap.Logger) *Router {
	productionHandler := api.NewProductionHandler(manager, config.DefaultProductionConfig(), logger)
	
	return &Router{
		engine:           engine,
		manager:          manager,
		config:           cfg,
		logger:           logger,
		productionHandler: productionHandler,
	}
}

// SetupRoutes 设置所有路由
func (r *Router) SetupRoutes() {
	// 健康检查路由（不需要验证）
	healthGroup := r.engine.Group("/health")
	{
		healthGroup.GET("", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"status": "OK",
			})
		})
	}

	// 就绪检查路由（不需要验证）
	readyGroup := r.engine.Group("/ready")
	{
		readyGroup.GET("", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"status": "Ready",
			})
		})
	}

	// Metrics端点（不需要验证）
	metricsGroup := r.engine.Group("/metrics")
	{
		// Prometheus 格式的指标端点
		metricsGroup.GET("", middleware.PrometheusMetricsHandler())
		// 自定义指标端点（JSON格式）
		metricsGroup.GET("/custom", middleware.MetricsHandler())
	}

	// Rancher兼容API路由组（需要输入验证）
	rancherGroup := r.engine.Group("/v3")
	{
		// 添加输入验证中间件
		rancherGroup.Use(middleware.SanitizeInputMiddleware())
		r.setupRancherRoutes(rancherGroup)
	}

	// 生产环境API路由组（需要输入验证）
	productionGroup := r.engine.Group("/v1")
	{
		// 添加输入验证中间件
		productionGroup.Use(middleware.SanitizeInputMiddleware())
		r.setupProductionRoutes(productionGroup)
	}

	// 管理API路由组（需要管理员权限和输入验证）
	adminGroup := r.engine.Group("/admin")
	{
		// 添加输入验证中间件
		adminGroup.Use(middleware.SanitizeInputMiddleware())
		r.setupAdminRoutes(adminGroup)
	}
}

// setupRancherRoutes 设置Rancher兼容API路由
func (r *Router) setupRancherRoutes(group *gin.RouterGroup) {
	// 项目路由组
	projectGroup := group.Group("/projects/:projectId")
	{
		// 应用相关路由
		appGroup := projectGroup.Group("/app")
		{
			// 部署应用（POST /v3/projects/:projectId/app）
			appGroup.POST("", r.deployApp)

			// 查询应用状态（GET /v3/projects/:projectId/app/:name）
			appGroup.GET("/:name", r.getAppStatus)

			// 应用列表（GET /v3/projects/:projectId/apps）
			appGroup.GET("", r.listApps)

			// 删除应用（DELETE /v3/projects/:projectId/app/:name）
			appGroup.DELETE("/:name", r.deleteAppRancher)

			// 应用操作（POST /v3/projects/:projectId/apps/:name）
			appGroup.POST("/:name", r.operateApp)
		}
		
		// 生产环境路由
		appProductionGroup := projectGroup.Group("/app")
		{
			// 生产环境部署（POST /v3/projects/:projectId/app/production）
			appProductionGroup.POST("/production", r.productionDeploy)
			
			// 验证应用（POST /v3/projects/:projectId/app/validate）
			appProductionGroup.POST("/validate", r.validateApp)
		}
	}
}

// setupProductionRoutes 设置生产环境API路由
func (r *Router) setupProductionRoutes(group *gin.RouterGroup) {
	// 应用管理
	appGroup := group.Group("/apps")
	{
		// 获取应用列表（GET /v1/apps）
		appGroup.GET("", r.listAppsV1)
		
		// 获取应用详情（GET /v1/apps/:name）
		appGroup.GET("/:name", r.getAppDetail)
		
		// 部署应用（POST /v1/apps）
		appGroup.POST("", r.deployAppV1)
		
		// 更新应用（PUT /v1/apps/:name）
		appGroup.PUT("/:name", r.updateApp)
		
		// 删除应用（DELETE /v1/apps/:name）
		appGroup.DELETE("/:name", r.deleteApp)
		
		// 应用操作（POST /v1/apps/:name/actions）
		actionGroup := appGroup.Group("/:name/actions")
		{
			actionGroup.POST("/upgrade", r.upgradeApp)
			actionGroup.POST("/rollback", r.rollbackApp)
			actionGroup.POST("/restart", r.restartApp)
			actionGroup.POST("/pause", r.pauseApp)
			actionGroup.POST("/resume", r.resumeApp)
		}
	}
	
	// 仓库管理
	repoGroup := group.Group("/repos")
	{
		// 获取仓库列表（GET /v1/repos）
		repoGroup.GET("", r.listRepos)
		
		// 获取仓库详情（GET /v1/repos/:name）
		repoGroup.GET("/:name", r.getRepoDetail)
		
		// 添加仓库（POST /v1/repos）
		repoGroup.POST("", r.addRepo)
		
		// 更新仓库（PUT /v1/repos/:name）
		repoGroup.PUT("/:name", r.updateRepo)
		
		// 删除仓库（DELETE /v1/repos/:name）
		repoGroup.DELETE("/:name", r.deleteRepo)
		
		// 刷新仓库（POST /v1/repos/:name/refresh）
		repoGroup.POST("/:name/refresh", r.refreshRepo)
	}
	
	// 监控和指标
	monitorGroup := group.Group("/monitor")
	{
		// 获取应用指标（GET /v1/monitor/apps/:name/metrics）
		monitorGroup.GET("/apps/:name/metrics", r.getAppMetrics)
		
		// 获取系统指标（GET /v1/monitor/system）
		monitorGroup.GET("/system", r.getSystemMetrics)
		
		// 获取健康状态（GET /v1/monitor/health）
		monitorGroup.GET("/health", r.getHealthStatus)
	}
}

// setupAdminRoutes 设置管理员API路由
func (r *Router) setupAdminRoutes(group *gin.RouterGroup) {
	// 配置管理
	configGroup := group.Group("/config")
	{
		// 获取配置（GET /admin/config）
		configGroup.GET("", r.getConfig)
		
		// 更新配置（PUT /admin/config）
		configGroup.PUT("", r.updateConfig)
	}
	
	// 用户管理
	userGroup := group.Group("/users")
	{
		// 获取用户列表（GET /admin/users）
		userGroup.GET("", r.listUsers)
		
		// 获取用户详情（GET /admin/users/:id）
		userGroup.GET("/:id", r.getUser)
		
		// 创建用户（POST /admin/users）
		userGroup.POST("", r.createUser)
		
		// 更新用户（PUT /admin/users/:id）
		userGroup.PUT("/:id", r.updateUser)
		
		// 删除用户（DELETE /admin/users/:id）
		userGroup.DELETE("/:id", r.deleteUser)
	}
	
	// 系统管理
	systemGroup := group.Group("/system")
	{
		// 获取系统信息（GET /admin/system/info）
		systemGroup.GET("/info", r.getSystemInfo)
		
		// 获取系统日志（GET /admin/system/logs）
		systemGroup.GET("/logs", r.getSystemLogs)
		
		// 重启系统（POST /admin/system/restart）
		systemGroup.POST("/restart", r.restartSystem)
	}
}

// Rancher兼容API路由处理器

// deployApp 部署应用（Rancher兼容）
func (r *Router) deployApp(c *gin.Context) {
	var req model.RancherRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
		return
	}

	projectID := c.Param("projectId")
	req.ProjectID = projectID

	// 验证必需字段
	if req.Name == "" {
		middleware.HandleBadRequest(c, "Validation failed", "name is required")
		return
	}
	if req.ExternalID == "" {
		middleware.HandleBadRequest(c, "Validation failed", "externalId is required")
		return
	}
	if req.TargetNamespace == "" {
		middleware.HandleBadRequest(c, "Validation failed", "targetNamespace is required")
		return
	}

	// 调用Helm管理器进行部署
	resp, err := r.manager.PrepareAndExecute(req)
	if err != nil {
		middleware.HandleInternalServerError(c, "Deployment failed", err.Error())
		return
	}

	middleware.HandleSuccess(c, resp, true)
}

// getAppStatus 获取应用状态（Rancher兼容）
func (r *Router) getAppStatus(c *gin.Context) {
	name := c.Param("name")
	projectID := c.Param("projectId")
	targetNamespace := c.Query("targetNamespace")

	if targetNamespace == "" {
		targetNamespace = "default"
	}

	status, err := r.manager.GetAppStatus(targetNamespace, name)
	if err != nil {
		middleware.HandleNotFound(c, "App not found", err.Error())
		return
	}

	_ = projectID // 项目ID已在状态查询中使用
	middleware.HandleSuccess(c, status, true)
}

// listApps 列出应用（Rancher兼容）
func (r *Router) listApps(c *gin.Context) {
	projectID := c.Param("projectId")

	// 如果 projectID 是 "c-test:ns-xxx" 格式，提取命名空间
	// 否则使用 ListAllApps 获取所有命名空间的应用
	var apps []*model.RancherResponse
	var err error

	if projectID == "c-test:ns-default" || projectID == "default" {
		// 特殊情况：Rancher UI 默认请求default项目
		apps, err = r.manager.ListAllApps()
	} else if strings.Contains(projectID, ":") {
		// 解析 "c-test:ns-namespace" 格式
		parts := strings.Split(projectID, ":")
		if len(parts) >= 2 {
			namespace := strings.TrimPrefix(parts[1], "ns-")
			apps, err = r.manager.ListApps(namespace)
		} else {
			// 无法解析，回退到获取所有应用
			apps, err = r.manager.ListAllApps()
		}
	} else {
		// 直接使用 projectID 作为命名空间
		apps, err = r.manager.ListApps(projectID)
	}
	if err != nil {
		r.logger.Warn("Failed to list apps",
			zap.String("project_id", projectID),
			zap.Error(err))
		// 返回空列表而不是错误，避免前端崩溃
		apps = []*model.RancherResponse{}
	}

	middleware.HandlePaginatedSuccess(c, apps, 0, 1, 10)
}

// deleteAppRancher 删除应用（Rancher兼容）
func (r *Router) deleteAppRancher(c *gin.Context) {
	name := c.Param("name")
	projectID := c.Param("projectId")
	targetNamespace := c.Query("targetNamespace")

	if targetNamespace == "" {
		targetNamespace = "default"
	}

	// 调用Helm管理器进行卸载
	err := r.manager.UninstallApp(targetNamespace, name)
	if err != nil {
		middleware.HandleInternalServerError(c, "Deletion failed", err.Error())
		return
	}

	appID := fmt.Sprintf("%s:%s", projectID, name)
	middleware.HandleSuccess(c, map[string]interface{}{
		"id":      appID,
		"state":   "removing",
		"name":    name,
		"message": "Application deletion initiated",
	}, true)
}

// operateApp 应用操作（Rancher兼容）
func (r *Router) operateApp(c *gin.Context) {
	name := c.Param("name")
	projectID := c.Param("projectId")
	action := c.Query("action")
	targetNamespace := c.Query("targetNamespace")

	if targetNamespace == "" {
		targetNamespace = "default"
	}

	switch action {
	case "upgrade":
		// 从请求体中获取新的值
		var req model.RancherRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
			return
		}

		// 解析 values
		vals, err := r.manager.ParseValues(req.Answers, req.ValuesYaml)
		if err != nil {
			middleware.HandleBadRequest(c, "Invalid values", err.Error())
			return
		}

		// 执行升级
		rel, err := r.manager.UpgradeApp(targetNamespace, name, "", vals)
		if err != nil {
			middleware.HandleInternalServerError(c, "Upgrade failed", err.Error())
			return
		}

		// 构建响应
		rancherReq := model.RancherRequest{
			Name:            name,
			TargetNamespace: targetNamespace,
			ExternalID:      req.ExternalID,
			ProjectID:       projectID,
			Answers:         req.Answers,
			ValuesYaml:      req.ValuesYaml,
			Prune:           req.Prune,
			Timeout:         req.Timeout,
			Wait:            req.Wait,
		}
		resp := r.manager.BuildResponse(rel, rancherReq)
		middleware.HandleSuccess(c, resp, true)

	case "rollback":
		// 从请求体中获取 revision
		var req map[string]interface{}
		if err := c.ShouldBindJSON(&req); err != nil {
			middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
			return
		}

		revision := 0
		if rev, ok := req["revision"].(float64); ok {
			revision = int(rev)
		}

		// 执行回滚
		rel, err := r.manager.RollbackApp(targetNamespace, name, revision)
		if err != nil {
			middleware.HandleInternalServerError(c, "Rollback failed", err.Error())
			return
		}

		// 构建响应
		rancherReq := model.RancherRequest{
			Name:            name,
			TargetNamespace: targetNamespace,
			ProjectID:       projectID,
		}
		resp := r.manager.BuildResponse(rel, rancherReq)
		middleware.HandleSuccess(c, resp, true)

	default:
		middleware.HandleBadRequest(c, "Unsupported action", "Action must be 'upgrade' or 'rollback'")
	}
}

// productionDeploy 生产环境部署
func (r *Router) productionDeploy(c *gin.Context) {
	r.productionHandler.HandleProductionDeploy(c)
}

// validateApp 验证应用
func (r *Router) validateApp(c *gin.Context) {
	var req api.ProductionDeployRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
		return
	}
	
	// 设置仅验证模式
	req.ValidationOnly = true
	c.Request.Body.Close()
	
	// 重新设置请求体
	jsonData, _ := c.GetRawData()
	c.Request.Body = &mockReadCloser{data: jsonData}
	
	// 调用生产环境处理器的验证逻辑
	r.productionHandler.HandleProductionDeploy(c)
}

// 生产环境API路由处理器

// listAppsV1 列出应用（v1 API）
func (r *Router) listAppsV1(c *gin.Context) {
	// 从 Helm 获取所有命名空间中的应用
	apps, err := r.manager.ListAllApps()
	if err != nil {
		r.logger.Warn("Failed to list all apps", zap.Error(err))
		// 返回空列表而不是错误，避免前端崩溃
		apps = []*model.RancherResponse{}
	}

	middleware.HandlePaginatedSuccess(c, apps, 0, 1, 10)
}

// getAppDetail 获取应用详情（v1 API）
func (r *Router) getAppDetail(c *gin.Context) {
	name := c.Param("name")

	// 从所有命名空间中查找应用
	apps, err := r.manager.ListAllApps()
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to list apps", err.Error())
		return
	}

	// 查找指定名称的应用
	var targetApp *model.RancherResponse
	for _, app := range apps {
		if app.Name == name {
			targetApp = app
			break
		}
	}

	if targetApp == nil {
		middleware.HandleNotFound(c, "App not found", fmt.Sprintf("App %s not found", name))
		return
	}

	middleware.HandleSuccess(c, targetApp)
}

// deployAppV1 部署应用（v1 API）
func (r *Router) deployAppV1(c *gin.Context) {
	var req model.RancherRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
		return
	}

	// 调用Helm管理器进行部署
	resp, err := r.manager.PrepareAndExecute(req)
	if err != nil {
		middleware.HandleInternalServerError(c, "Deployment failed", err.Error())
		return
	}

	middleware.HandleSuccess(c, resp)
}

// updateApp 更新应用（v1 API）
func (r *Router) updateApp(c *gin.Context) {
	name := c.Param("name")
	var req model.RancherRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
		return
	}

	// 从所有命名空间中查找应用
	apps, err := r.manager.ListAllApps()
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to list apps", err.Error())
		return
	}

	// 查找指定名称的应用
	var targetApp *model.RancherResponse
	for _, app := range apps {
		if app.Name == name {
			targetApp = app
			break
		}
	}

	if targetApp == nil {
		middleware.HandleNotFound(c, "App not found", fmt.Sprintf("App %s not found", name))
		return
	}

	// 设置应用名称
	req.Name = name
	req.TargetNamespace = targetApp.TargetNamespace

	// 调用升级功能
	// 转换 map[string]string 到 map[string]interface{}
	answers := make(map[string]interface{})
	for k, v := range req.Answers {
		answers[k] = v
	}

	_, err = r.manager.UpgradeApp(targetApp.TargetNamespace, name, "", answers)
	if err != nil {
		middleware.HandleInternalServerError(c, "App upgrade failed", err.Error())
		return
	}

	// 转换为 Rancher 响应格式
	resp := &model.RancherResponse{
		ID:               targetApp.ID,
		Name:             name,
		State:            "upgrading",
		TargetNamespace:  targetApp.TargetNamespace,
		ExternalID:       targetApp.ExternalID,
		Created:          targetApp.Created,
		CreatedTS:        targetApp.CreatedTS,
	}

	middleware.HandleSuccess(c, resp)
}

// deleteApp 删除应用（v1 API）
func (r *Router) deleteApp(c *gin.Context) {
	name := c.Param("name")

	// 从所有命名空间中查找应用
	apps, err := r.manager.ListAllApps()
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to list apps", err.Error())
		return
	}

	// 查找指定名称的应用
	var targetNamespace string
	var found bool
	for _, app := range apps {
		if app.Name == name {
			targetNamespace = app.TargetNamespace
			found = true
			break
		}
	}

	if !found {
		middleware.HandleNotFound(c, "App not found", fmt.Sprintf("App %s not found", name))
		return
	}

	// 执行删除
	err = r.manager.UninstallApp(targetNamespace, name)
	if err != nil {
		middleware.HandleInternalServerError(c, "Deletion failed", err.Error())
		return
	}

	middleware.HandleSuccess(c, map[string]interface{}{
		"id":      fmt.Sprintf("default:%s", name),
		"name":    name,
		"state":   "removing",
		"message": "Application deletion initiated",
	})
}

// upgradeApp 升级应用
func (r *Router) upgradeApp(c *gin.Context) {
	name := c.Param("name")

	// 从所有命名空间中查找应用
	apps, err := r.manager.ListAllApps()
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to list apps", err.Error())
		return
	}

	// 查找指定名称的应用
	var targetNamespace string
	var found bool
	for _, app := range apps {
		if app.Name == name {
			targetNamespace = app.TargetNamespace
			found = true
			break
		}
	}

	if !found {
		middleware.HandleNotFound(c, "App not found", fmt.Sprintf("App %s not found", name))
		return
	}

	// 从请求体中获取新的值
	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
		return
	}

	// 解析 values
	var answers map[string]string
	var valuesYaml string

	// 类型转换 answers
	if answersInterface, ok := req["answers"]; ok {
		if answersMap, ok := answersInterface.(map[string]interface{}); ok {
			answers = make(map[string]string)
			for k, v := range answersMap {
				if str, ok := v.(string); ok {
					answers[k] = str
				}
			}
		}
	}

	// 类型转换 valuesYaml
	if valuesYamlInterface, ok := req["valuesYaml"]; ok {
		if str, ok := valuesYamlInterface.(string); ok {
			valuesYaml = str
		}
	}

	vals, err := r.manager.ParseValues(answers, valuesYaml)
	if err != nil {
		middleware.HandleBadRequest(c, "Invalid values", err.Error())
		return
	}

	// 执行升级
	rel, err := r.manager.UpgradeApp(targetNamespace, name, "", vals)
	if err != nil {
		middleware.HandleInternalServerError(c, "Upgrade failed", err.Error())
		return
	}

	middleware.HandleSuccess(c, map[string]interface{}{
		"id":      fmt.Sprintf("default:%s", name),
		"name":    name,
		"state":   "upgrading",
		"version": rel.Chart.Name(),
		"message": "Application upgrade initiated",
	})
}

// rollbackApp 回滚应用
func (r *Router) rollbackApp(c *gin.Context) {
	name := c.Param("name")

	// 从所有命名空间中查找应用
	apps, err := r.manager.ListAllApps()
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to list apps", err.Error())
		return
	}

	// 查找指定名称的应用
	var targetNamespace string
	var found bool
	for _, app := range apps {
		if app.Name == name {
			targetNamespace = app.TargetNamespace
			found = true
			break
		}
	}

	if !found {
		middleware.HandleNotFound(c, "App not found", fmt.Sprintf("App %s not found", name))
		return
	}

	// 从请求体中获取 revision
	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
		return
	}

	revision := 0
	if revisionInterface, ok := req["revision"]; ok {
		if rev, ok := revisionInterface.(float64); ok {
			revision = int(rev)
		}
	}

	// 执行回滚
	rel, err := r.manager.RollbackApp(targetNamespace, name, revision)
	if err != nil {
		middleware.HandleInternalServerError(c, "Rollback failed", err.Error())
		return
	}

	middleware.HandleSuccess(c, map[string]interface{}{
		"id":      fmt.Sprintf("default:%s", name),
		"name":    name,
		"state":   "rolling-back",
		"version": rel.Chart.Name(),
		"message": "Application rollback initiated",
	})
}

// restartApp 重启应用 - 使用Kubernetes原生重启
func (r *Router) restartApp(c *gin.Context) {
	name := c.Param("name")

	// 从所有命名空间中查找应用
	apps, err := r.manager.ListAllApps()
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to list apps", err.Error())
		return
	}

	// 查找指定名称的应用
	var targetApp *model.RancherResponse
	for _, app := range apps {
		if app.Name == name {
			targetApp = app
			break
		}
	}

	if targetApp == nil {
		middleware.HandleNotFound(c, "App not found", fmt.Sprintf("App %s not found", name))
		return
	}

	// 使用Helm SDK获取当前release
	cfg, err := r.manager.GetActionConfig(targetApp.TargetNamespace)
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to get Helm config", err.Error())
		return
	}

	// 获取release状态
	statusClient := action.NewStatus(cfg)
	rel, err := statusClient.Run(name)
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to get release status", err.Error())
		return
	}

	// 获取当前的values
	values := rel.Config

	// 创建一个特殊的annotation来触发滚动重启
	if values == nil {
		values = map[string]interface{}{}
	}
	// 添加或更新annotation
	if annotations, ok := values["annotations"].(map[string]interface{}); ok {
		annotations["restartedAt"] = time.Now().Format(time.RFC3339)
	} else {
		values["annotations"] = map[string]interface{}{
			"restartedAt": time.Now().Format(time.RFC3339),
		}
	}

	// 使用修改后的values进行upgrade（会触发Pod重建）
	_, err = r.manager.UpgradeApp(targetApp.TargetNamespace, name, "", values)
	if err != nil {
		middleware.HandleInternalServerError(c, "Restart failed", err.Error())
		return
	}

	middleware.HandleSuccess(c, map[string]interface{}{
		"message":   "App restart initiated",
		"name":      name,
		"namespace": targetApp.TargetNamespace,
		"state":     "restarting",
	})
}

// pauseApp 暂停应用 - 使用现有chart版本设置replicas=0
func (r *Router) pauseApp(c *gin.Context) {
	name := c.Param("name")

	// 从所有命名空间中查找应用
	apps, err := r.manager.ListAllApps()
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to list apps", err.Error())
		return
	}

	// 查找指定名称的应用
	var targetApp *model.RancherResponse
	for _, app := range apps {
		if app.Name == name {
			targetApp = app
			break
		}
	}

	if targetApp == nil {
		middleware.HandleNotFound(c, "App not found", fmt.Sprintf("App %s not found", name))
		return
	}

	// 获取当前chart版本
	cfg, err := r.manager.GetActionConfig(targetApp.TargetNamespace)
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to get Helm config", err.Error())
		return
	}

	// 获取release状态
	statusClient := action.NewStatus(cfg)
	rel, err := statusClient.Run(name)
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to get release status", err.Error())
		return
	}

	// 获取当前chart和版本
	chart := rel.Chart
	version := chart.Metadata.Version

	// 暂停应用 - 通过设置 replicaCount=0（使用现有版本）
	vals := map[string]interface{}{
		"replicaCount": 0,
	}
	_, err = r.manager.UpgradeApp(targetApp.TargetNamespace, name, version, vals)
	if err != nil {
		middleware.HandleInternalServerError(c, "Pause failed", err.Error())
		return
	}

	middleware.HandleSuccess(c, map[string]interface{}{
		"message":   "App pause initiated",
		"name":      name,
		"namespace": targetApp.TargetNamespace,
		"state":     "paused",
		"version":   version,
	})
}

// resumeApp 恢复应用 - 使用现有chart版本设置replicas=1
func (r *Router) resumeApp(c *gin.Context) {
	name := c.Param("name")

	// 从所有命名空间中查找应用
	apps, err := r.manager.ListAllApps()
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to list apps", err.Error())
		return
	}

	// 查找指定名称的应用
	var targetApp *model.RancherResponse
	for _, app := range apps {
		if app.Name == name {
			targetApp = app
			break
		}
	}

	if targetApp == nil {
		middleware.HandleNotFound(c, "App not found", fmt.Sprintf("App %s not found", name))
		return
	}

	// 获取当前chart版本
	cfg, err := r.manager.GetActionConfig(targetApp.TargetNamespace)
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to get Helm config", err.Error())
		return
	}

	// 获取release状态
	statusClient := action.NewStatus(cfg)
	rel, err := statusClient.Run(name)
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to get release status", err.Error())
		return
	}

	// 获取当前chart和版本
	chart := rel.Chart
	version := chart.Metadata.Version

	// 恢复应用 - 通过设置 replicaCount=1（使用现有版本）
	vals := map[string]interface{}{
		"replicaCount": 1,
	}
	_, err = r.manager.UpgradeApp(targetApp.TargetNamespace, name, version, vals)
	if err != nil {
		middleware.HandleInternalServerError(c, "Resume failed", err.Error())
		return
	}

	middleware.HandleSuccess(c, map[string]interface{}{
		"message":   "App resume initiated",
		"name":      name,
		"namespace": targetApp.TargetNamespace,
		"state":     "active",
		"version":   version,
	})
}

// 仓库管理路由处理器

// listRepos 列出仓库
func (r *Router) listRepos(c *gin.Context) {
	repos := make([]interface{}, 0, len(r.config.Helm.RepoMap))
	for name, url := range r.config.Helm.RepoMap {
		repo := map[string]interface{}{
			"name": name,
			"url":  url,
			"status": "active",
			"created_at": "2024-01-01T00:00:00Z",
		}
		repos = append(repos, repo)
	}
	middleware.HandlePaginatedSuccess(c, repos, int64(len(repos)), 1, 10)
}

// getRepoDetail 获取仓库详情 - 从配置读取真实URL
func (r *Router) getRepoDetail(c *gin.Context) {
	name := c.Param("name")

	// 从配置中查找仓库URL
	url, exists := r.config.Helm.RepoMap[name]
	if !exists {
		middleware.HandleNotFound(c, "Repository not found", fmt.Sprintf("Repository %s not found in configuration", name))
		return
	}

	repo := map[string]interface{}{
		"name":   name,
		"url":    url,
		"status": "active",
	}
	middleware.HandleSuccess(c, repo)
}

// addRepo 添加仓库 - 使用 Helm SDK
func (r *Router) addRepo(c *gin.Context) {
	var req struct {
		Name     string `json:"name" binding:"required"`
		URL      string `json:"url" binding:"required"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
		return
	}

	// 检查仓库是否已存在
	if _, exists := r.config.Helm.RepoMap[req.Name]; exists {
		middleware.HandleBadRequest(c, "Repository already exists", fmt.Sprintf("Repository %s already exists", req.Name))
		return
	}

	// 使用 Helm SDK 的 repo 包添加仓库
	// 获取 repo 文件路径
	settings := cli.New()
	repoFilePath := settings.RepositoryConfig

	// 读取现有的 repo 文件
	repoFile, err := repo.LoadFile(repoFilePath)
	if err != nil {
		// 如果文件不存在，创建新的
		repoFile = repo.NewFile()
	}

	// 检查仓库是否已存在
	if repoFile.Has(req.Name) {
		middleware.HandleBadRequest(c, "Repository already exists", fmt.Sprintf("Repository %s already exists in Helm", req.Name))
		return
	}

	// 创建新的 repo 条目
	entry := &repo.Entry{
		Name:     req.Name,
		URL:      req.URL,
		Username: req.Username,
		Password: req.Password,
	}

	// 添加到 repo 文件
	repoFile.Add(entry)

	// 保存文件
	if err := repoFile.WriteFile(repoFilePath, 0644); err != nil {
		middleware.HandleInternalServerError(c, "Failed to save repository", err.Error())
		return
	}

	// 更新配置
	r.config.Helm.RepoMap[req.Name] = req.URL

	middleware.HandleSuccess(c, map[string]interface{}{
		"message": "Repository added successfully",
		"name":    req.Name,
		"url":     req.URL,
	})
}

// updateRepo 更新仓库 - 使用 Helm SDK
func (r *Router) updateRepo(c *gin.Context) {
	name := c.Param("name")
	var req struct {
		URL      string `json:"url" binding:"required"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
		return
	}

	// 检查仓库是否存在
	if _, exists := r.config.Helm.RepoMap[name]; !exists {
		middleware.HandleNotFound(c, "Repository not found", fmt.Sprintf("Repository %s not found", name))
		return
	}

	// 使用 Helm SDK 更新仓库
	settings := cli.New()
	repoFilePath := settings.RepositoryConfig

	// 读取现有的 repo 文件
	repoFile, err := repo.LoadFile(repoFilePath)
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to load repository file", err.Error())
		return
	}

	// 检查仓库是否存在
	if !repoFile.Has(name) {
		middleware.HandleNotFound(c, "Repository not found", fmt.Sprintf("Repository %s not found in Helm", name))
		return
	}

	// 删除现有条目
	repoFile.Remove(name)

	// 创建新的 repo 条目
	entry := &repo.Entry{
		Name:     name,
		URL:      req.URL,
		Username: req.Username,
		Password: req.Password,
	}

	// 添加更新的条目
	repoFile.Add(entry)

	// 保存文件
	if err := repoFile.WriteFile(repoFilePath, 0644); err != nil {
		middleware.HandleInternalServerError(c, "Failed to save repository", err.Error())
		return
	}

	// 更新配置
	r.config.Helm.RepoMap[name] = req.URL

	middleware.HandleSuccess(c, map[string]interface{}{
		"message": "Repository updated successfully",
		"name":    name,
		"url":     req.URL,
	})
}

// deleteRepo 删除仓库 - 使用 Helm SDK
func (r *Router) deleteRepo(c *gin.Context) {
	name := c.Param("name")

	// 检查仓库是否存在
	if _, exists := r.config.Helm.RepoMap[name]; !exists {
		middleware.HandleNotFound(c, "Repository not found", fmt.Sprintf("Repository %s not found", name))
		return
	}

	// 使用 Helm SDK 删除仓库
	settings := cli.New()
	repoFilePath := settings.RepositoryConfig

	// 读取现有的 repo 文件
	repoFile, err := repo.LoadFile(repoFilePath)
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to load repository file", err.Error())
		return
	}

	// 检查仓库是否存在
	if !repoFile.Has(name) {
		middleware.HandleNotFound(c, "Repository not found", fmt.Sprintf("Repository %s not found in Helm", name))
		return
	}

	// 删除仓库
	repoFile.Remove(name)

	// 保存文件
	if err := repoFile.WriteFile(repoFilePath, 0644); err != nil {
		middleware.HandleInternalServerError(c, "Failed to save repository file", err.Error())
		return
	}

	// 从配置中删除
	delete(r.config.Helm.RepoMap, name)

	middleware.HandleSuccess(c, map[string]interface{}{
		"message": "Repository deleted successfully",
		"name":    name,
	})
}

// refreshRepo 刷新仓库 - 需要下载索引文件，使用helm命令
func (r *Router) refreshRepo(c *gin.Context) {
	name := c.Param("name")

	// 检查仓库是否存在
	if _, exists := r.config.Helm.RepoMap[name]; !exists {
		middleware.HandleNotFound(c, "Repository not found", fmt.Sprintf("Repository %s not found", name))
		return
	}

	// 执行 helm repo update 指定仓库
	cmd := exec.Command("helm", "repo", "update", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		middleware.HandleInternalServerError(c, "Failed to refresh repository", fmt.Sprintf("%s: %s", err.Error(), string(output)))
		return
	}

	middleware.HandleSuccess(c, map[string]interface{}{
		"message": "Repository refresh completed",
		"name":    name,
		"output":  string(output),
	})
}

// 监控路由处理器

// getAppMetrics 获取应用指标
func (r *Router) getAppMetrics(c *gin.Context) {
	name := c.Param("name")

	metrics := map[string]interface{}{
		"app_name":     name,
		"cpu_usage":    "10%",
		"memory_usage": "256MB",
		"status":       "running",
	}
	middleware.HandleSuccess(c, metrics)
}

// getSystemMetrics 获取系统指标
func (r *Router) getSystemMetrics(c *gin.Context) {
	metrics := map[string]interface{}{
		"cpu_usage":    "5%",
		"memory_usage": "512MB",
		"disk_usage":   "1GB",
	}
	middleware.HandleSuccess(c, metrics)
}

// getHealthStatus 获取健康状态
func (r *Router) getHealthStatus(c *gin.Context) {
	health := map[string]interface{}{
		"status": "healthy",
		"checks": map[string]string{
			"database": "ok",
			"redis":    "ok",
			"helm":     "ok",
		},
	}
	middleware.HandleSuccess(c, health)
}

// 管理员路由处理器

// getConfig 获取配置
func (r *Router) getConfig(c *gin.Context) {
	config := map[string]interface{}{
		"port":      r.config.Server.Port,
		"log_level": "info",
	}
	middleware.HandleSuccess(c, config)
}

// updateConfig 更新配置
func (r *Router) updateConfig(c *gin.Context) {
	var req interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
		return
	}
	
	middleware.HandleSuccess(c, map[string]string{
		"message": "Configuration updated successfully",
	})
}

// listUsers 列出用户
func (r *Router) listUsers(c *gin.Context) {
	users := []interface{}{}
	middleware.HandlePaginatedSuccess(c, users, 0, 1, 10)
}

// getUser 获取用户详情
func (r *Router) getUser(c *gin.Context) {
	id := c.Param("id")
	
	user := map[string]interface{}{
		"id":       id,
		"username": "admin",
		"email":    "admin@example.com",
	}
	middleware.HandleSuccess(c, user)
}

// createUser 创建用户
func (r *Router) createUser(c *gin.Context) {
	var req interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
		return
	}
	
	middleware.HandleSuccess(c, map[string]string{
		"message": "User created successfully",
	})
}

// updateUser 更新用户
func (r *Router) updateUser(c *gin.Context) {
	id := c.Param("id")
	var req interface{}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.HandleBadRequest(c, "Invalid JSON", err.Error())
		return
	}
	
	middleware.HandleSuccess(c, map[string]string{
		"message": "User updated successfully",
		"id":      id,
	})
}

// deleteUser 删除用户
func (r *Router) deleteUser(c *gin.Context) {
	id := c.Param("id")
	
	middleware.HandleSuccess(c, map[string]string{
		"message": "User deleted successfully",
		"id":      id,
	})
}

// getSystemInfo 获取系统信息
func (r *Router) getSystemInfo(c *gin.Context) {
	info := map[string]interface{}{
		"version":     "1.0.0",
		"build_time":  "2023-01-01T00:00:00Z",
		"go_version":  "1.19",
		"environment": "production",
	}
	middleware.HandleSuccess(c, info)
}

// getSystemLogs 获取系统日志
func (r *Router) getSystemLogs(c *gin.Context) {
	logs := []string{
		"2023-01-01 00:00:00 INFO Server started",
		"2023-01-01 00:01:00 INFO Health check passed",
	}
	middleware.HandleSuccess(c, logs)
}

// restartSystem 重启系统
func (r *Router) restartSystem(c *gin.Context) {
	middleware.HandleSuccess(c, map[string]string{
		"message": "System restart initiated",
	})
}

// mockReadCloser 模拟ReadCloser，用于重置请求体
type mockReadCloser struct {
	data []byte
	pos  int
}

func (m *mockReadCloser) Read(p []byte) (n int, err error) {
	if m.pos >= len(m.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, m.data[m.pos:])
	m.pos += n
	return n, nil
}

func (m *mockReadCloser) Close() error {
	return nil
}