package core

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/strvals"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/google/uuid"
	"github.com/mensylisir/helm-proxy/config"
	"github.com/mensylisir/helm-proxy/model"
	"gopkg.in/yaml.v3"
)

// DeploymentJob 部署作业结构体
type DeploymentJob struct {
	*JobItem   // 嵌入 JobItem 结构体
	Manager    *HelmManager
	Request    *model.RancherRequest
	DeployFunc func(context.Context) (*release.Release, error)
	ProjectID  string
	AppID      string
}

// Process 实现 JobProcessor 接口
func (job *DeploymentJob) Process() {
	// 防止主请求结束后 context 取消，使用 Background
	_, err := job.DeployFunc(context.Background())
	if err != nil {
		job.Manager.logger.Error("Async deployment failed",
			zap.Error(err),
			zap.String("name", job.Request.Name),
			zap.String("app_id", job.AppID))
	} else {
		job.Manager.logger.Info("Async deployment success",
			zap.String("name", job.Request.Name),
			zap.String("app_id", job.AppID))
	}
}

// GetPriority 实现 JobProcessor 接口
func (job *DeploymentJob) GetPriority() int {
	// 部署作业的优先级，默认中等优先级
	return int(PriorityNormal)
}

// handleAsyncDeployment 处理异步部署，使用 Goroutine
func (m *HelmManager) handleAsyncDeployment(req *model.RancherRequest, doDeploy func(context.Context) (*release.Release, error)) (*model.RancherResponse, error) {
	// 生成项目ID和应用ID
	projectID := req.ProjectID
	if projectID == "" {
		projectID = "default"
	}
	appID := fmt.Sprintf("%s:%s", projectID, req.Name)

	// 创建上下文和取消函数
	ctx, cancel := context.WithCancel(context.Background())

	// 在 Goroutine 中异步执行部署
	go func() {
		defer cancel()
		_, err := doDeploy(ctx)
		if err != nil {
			m.logger.Error("Async deployment failed",
				zap.String("app_id", appID),
				zap.Error(err))
		} else {
			m.logger.Info("Async deployment completed",
				zap.String("app_id", appID))
		}
	}()

	// 构造成功的响应
	return &model.RancherResponse{
		ID:                   appID,
		BaseType:             "app",
		Type:                 "app",
		Name:                 req.Name,
		State:                "installing", // Rancher UI 会识别这个状态
		TargetNamespace:      req.TargetNamespace,
		ExternalID:           req.ExternalID,
		ProjectID:            projectID,
		Prune:                req.Prune,
		Timeout:              req.Timeout,
		Wait:                 req.Wait,
		ValuesYaml:           req.ValuesYaml,
		Answers:              req.Answers,
		Created:              time.Now().Format(time.RFC3339),
		CreatedTS:            time.Now().UnixMilli(),
		UUID:                 uuid.New().String(),
		Labels:               map[string]string{"cattle.io/creator": "norman"},
		Annotations:          map[string]string{},
		Transitioning:        "yes",
		TransitioningMessage: "Installing application asynchronously",
		AppRevisionID:        "",
		MultiClusterAppID:    "",
		NamespaceID:          "",
		CreatorID:            "user-helm-proxy",
		Links: map[string]string{
			"self":     fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s", projectID, appID),
			"update":   fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s", projectID, appID),
			"remove":   fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s", projectID, appID),
			"revision": fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s/revision", projectID, appID),
		},
		ActionLinks: map[string]string{
			"upgrade":  fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s?action=upgrade", projectID, appID),
			"rollback": fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s?action=rollback", projectID, appID),
		},
	}, nil
}

// HelmManager Helm 管理器
type HelmManager struct {
	cfg                 *config.Config
	logger              *zap.Logger
	keyLock             *sync.Map
	settings            *cli.EnvSettings
	productionValidator *ProductionValidator
	productionConfig    *config.ProductionConfig
	chartCache          *ChartCache
}

// ChartCache Chart 缓存结构体
type ChartCache struct {
	sync.RWMutex
	cache   map[string]*ChartEntry
	maxSize int
	ttl     time.Duration
}

// ChartEntry Chart 缓存条目
type ChartEntry struct {
	ChartPath string
	DownloadedAt time.Time
	Version    string
	ChartName  string
}

// NewChartCache 创建新的Chart缓存
func NewChartCache(maxSize int, ttl time.Duration) *ChartCache {
	return &ChartCache{
		cache:   make(map[string]*ChartEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Get 从缓存中获取Chart
func (c *ChartCache) Get(key string) (*ChartEntry, bool) {
	c.RLock()
	defer c.RUnlock()

	entry, exists := c.cache[key]
	if !exists {
		return nil, false
	}

	// 检查TTL
	if time.Since(entry.DownloadedAt) > c.ttl {
		return nil, false
	}

	return entry, true
}

// Set 将Chart放入缓存
func (c *ChartCache) Set(key string, entry *ChartEntry) {
	c.Lock()
	defer c.Unlock()

	// 检查缓存大小，如果超过限制则清理旧条目
	if len(c.cache) >= c.maxSize {
		c.cleanup()
	}

	c.cache[key] = entry
}

// cleanup 清理过期的缓存条目
func (c *ChartCache) cleanup() {
	now := time.Now()
	for key, entry := range c.cache {
		if now.Sub(entry.DownloadedAt) > c.ttl {
			delete(c.cache, key)
		}
	}

	// 如果清理后仍然超过大小限制，删除最旧的条目
	if len(c.cache) >= c.maxSize {
		var oldestKey string
		var oldestTime time.Time
		for key, entry := range c.cache {
			if oldestKey == "" || entry.DownloadedAt.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.DownloadedAt
			}
		}
		if oldestKey != "" {
			delete(c.cache, oldestKey)
		}
	}
}

// Clear 清空缓存
func (c *ChartCache) Clear() {
	c.Lock()
	defer c.Unlock()
	c.cache = make(map[string]*ChartEntry)
}

// NewManager 构造函数
func NewManager(cfg *config.Config, logger *zap.Logger) *HelmManager {
	settings := cli.New()

	// 创建生产环境配置和验证器
	prodConfig := config.DefaultProductionConfig()
	validator := NewProductionValidator(prodConfig, logger)

	// 创建Chart缓存（最大500个条目，TTL 2小时）
	chartCache := NewChartCache(500, 2*time.Hour)

	return &HelmManager{
		cfg:                 cfg,
		logger:              logger,
		keyLock:             &sync.Map{},
		settings:            settings,
		productionValidator: validator,
		productionConfig:    prodConfig,
		chartCache:          chartCache,
	}
}

// NewManagerWithProduction 创建带有生产环境优化的管理器
func NewManagerWithProduction(cfg *config.Config, prodConfig *config.ProductionConfig, logger *zap.Logger) *HelmManager {
	settings := cli.New()

	var validator *ProductionValidator
	if prodConfig != nil {
		validator = NewProductionValidator(prodConfig, logger)
	}

	// 创建Chart缓存（最大500个条目，TTL 2小时）
	chartCache := NewChartCache(500, 2*time.Hour)

	return &HelmManager{
		cfg:                 cfg,
		logger:              logger,
		keyLock:             &sync.Map{},
		settings:            settings,
		productionValidator: validator,
		productionConfig:    prodConfig,
		chartCache:          chartCache,
	}
}

// PrepareAndExecute 负责解析参数、加锁、决定同步还是异步
func (m *HelmManager) PrepareAndExecute(req model.RancherRequest) (*model.RancherResponse, error) {
	startTime := time.Now()

	// 获取 Prometheus 指标实例
	promMetrics := GetPrometheusMetrics()

	// 记录 Helm 操作开始
	promMetrics.RecordHelmOperationStart("deployment")

	// 1. 生产环境验证（如果启用）
	if m.productionValidator != nil {
		if err := m.productionValidator.ValidateRancherRequest(&req); err != nil {
			m.logger.Error("Production validation failed", zap.Error(err))
			// 记录验证失败
			promMetrics.RecordHelmFailure("deployment", "validation_failed")
			promMetrics.RecordHelmOperationEnd("deployment")
			return nil, fmt.Errorf("validation failed: %v", err)
		}
	}

	// 2. 获取锁 (Namespace + Name)
	lockKey := fmt.Sprintf("%s/%s", req.TargetNamespace, req.Name)
	muRaw, _ := m.keyLock.LoadOrStore(lockKey, &sync.Mutex{})
	mu := muRaw.(*sync.Mutex)

	// 尝试加锁，避免同一应用并发部署
	mu.Lock()
	defer mu.Unlock()

	m.logger.Info("Processing deployment", zap.String("name", req.Name), zap.String("ns", req.TargetNamespace))

	// 3. 解析 ExternalID (catalog://...)
	chartURL, version, err := m.resolveChart(req.ExternalID)
	if err != nil {
		promMetrics.RecordHelmFailure("deployment", "invalid_external_id")
		promMetrics.RecordHelmOperationEnd("deployment")
		return nil, fmt.Errorf("invalid externalId: %v", err)
	}

	// 提取 Chart 名称用于指标
	chartName := m.extractChartName(req.ExternalID)

	// 4. 处理参数 (Answers -> Map)
	vals, err := m.ParseValues(req.Answers, req.ValuesYaml)
	if err != nil {
		promMetrics.RecordHelmFailure("deployment", "parse_values_failed")
		promMetrics.RecordHelmOperationEnd("deployment")
		return nil, fmt.Errorf("failed to parse answers: %v", err)
	}

	// 4. 定义具体的执行函数
	doDeploy := func(ctx context.Context) (*release.Release, error) {
		cfg, err := m.getActionConfig(req.TargetNamespace)
		if err != nil {
			return nil, err
		}

		// 检查历史版本判断是 Install 还是 Upgrade
		histClient := action.NewHistory(cfg)
		histClient.Max = 1
		_, err = histClient.Run(req.Name)
		isUpgrade := (err == nil)

		// 下载 Chart
		cp, err := m.downloadChart(chartURL, version, cfg)
		if err != nil {
			return nil, err
		}
		loadedChart, err := loader.Load(cp)
		if err != nil {
			return nil, err
		}

		if isUpgrade {
			client := action.NewUpgrade(cfg)
			client.Namespace = req.TargetNamespace
			client.Version = version
			client.Timeout = time.Duration(req.Timeout) * time.Second
			client.Wait = req.Wait
			client.Atomic = true // 生产环境必须 Atomic
			return client.Run(req.Name, loadedChart, vals)
		} else {
			client := action.NewInstall(cfg)
			client.ReleaseName = req.Name
			client.Namespace = req.TargetNamespace
			client.Version = version
			client.Timeout = time.Duration(req.Timeout) * time.Second
			client.Wait = req.Wait
			client.CreateNamespace = true
			client.Atomic = true
			return client.Run(loadedChart, vals)
		}
	}

	// 5. 执行模式：同步或异步
	var resp *model.RancherResponse
	if req.Wait {
		// 同步：直接执行
		rel, err := doDeploy(context.Background())
		if err != nil {
			duration := time.Since(startTime)
			promMetrics.RecordDeploymentFailure(req.TargetNamespace, chartName, err.Error())
			promMetrics.RecordHelmOperation("deployment", "failed", duration)
			promMetrics.RecordHelmOperationEnd("deployment")
			return nil, err
		}
		resp = m.BuildResponse(rel, req)
		duration := time.Since(startTime)
		promMetrics.RecordDeployment(req.TargetNamespace, chartName, "active", duration)
		promMetrics.RecordHelmOperation("deployment", "success", duration)
		promMetrics.RecordHelmOperationEnd("deployment")
		return resp, nil
	} else {
		// 异步：使用 Job Queue 处理，立即返回 Active/Installing 状态
		resp, err = m.handleAsyncDeployment(&req, doDeploy)
		duration := time.Since(startTime)
		if err != nil {
			promMetrics.RecordDeploymentFailure(req.TargetNamespace, chartName, err.Error())
			promMetrics.RecordHelmOperation("deployment", "failed", duration)
		} else {
			promMetrics.RecordDeployment(req.TargetNamespace, chartName, resp.State, duration)
			promMetrics.RecordHelmOperation("deployment", "success", duration)
		}
		promMetrics.RecordHelmOperationEnd("deployment")
		return resp, err
	}
}

// GetAppStatus 查询应用的真实状态
func (m *HelmManager) GetAppStatus(namespace, name string) (*model.RancherResponse, error) {
	// 1. 初始化 Helm 配置
	cfg, err := m.getActionConfig(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get action config: %v", err)
	}

	// 2. 使用 Helm SDK 获取状态
	client := action.NewStatus(cfg)
	rel, err := client.Run(name)
	if err != nil {
		// 如果 Helm 返回 "not found" 错误，说明这个 release 不存在
		if strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("release %s not found in namespace %s", name, namespace)
		}
		return nil, fmt.Errorf("failed to get status: %v", err)
	}

	// 3. 构造真实状态返回
	projectID := "default" // 默认项目ID
	appID := fmt.Sprintf("%s:%s", projectID, name)

	// 根据 Helm release 状态转换为 Rancher 兼容的状态
	state := m.mapHelmStateToRancher(rel)
	transitioning := "no"
	transitioningMessage := ""

	if state == "installing" || state == "upgrading" {
		transitioning = "yes"
		transitioningMessage = fmt.Sprintf("Application is %s", state)
	}

	return &model.RancherResponse{
		ID:                   appID,
		BaseType:             "app",
		Type:                 "app",
		Name:                 rel.Name,
		State:                state,
		TargetNamespace:      rel.Namespace,
		ExternalID:           "", // 查询时通常不带这个字段
		ProjectID:            projectID,
		Created:              rel.Info.FirstDeployed.Format(time.RFC3339),
		CreatedTS:            rel.Info.FirstDeployed.UnixMilli(),
		UUID:                 uuid.New().String(),
		Labels:               map[string]string{"cattle.io/creator": "norman"},
		Annotations:          map[string]string{},
		Transitioning:        transitioning,
		TransitioningMessage: transitioningMessage,
		CreatorID:            "user-helm-proxy",
		Links: map[string]string{
			"self":     fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s", projectID, appID),
			"update":   fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s", projectID, appID),
			"remove":   fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s", projectID, appID),
			"revision": fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s/revision", projectID, appID),
		},
		ActionLinks: map[string]string{
			"upgrade":  fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s?action=upgrade", projectID, appID),
			"rollback": fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s?action=rollback", projectID, appID),
		},
		// 可以添加更多详细信息
		Prune:   false, // 默认值
		Timeout: 300,   // 默认超时
		Wait:    true,  // 默认等待
		Answers: map[string]string{},
	}, nil
}

// ListApps 列出指定命名空间中的所有应用
func (m *HelmManager) ListApps(namespace string) ([]*model.RancherResponse, error) {
	// 1. 初始化 Helm 配置
	cfg, err := m.getActionConfig(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get action config: %v", err)
	}

	// 2. 使用 Helm SDK 列出所有 releases
	listClient := action.NewList(cfg)
	listClient.All = true  // 获取所有 releases，包括已卸载的
	// 注意：也可以使用 listClient.Deployed = true 只获取已部署的

	releases, err := listClient.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to list releases: %v", err)
	}

	// 3. 构建响应列表
	var apps []*model.RancherResponse
	for _, rel := range releases {
		app, err := m.GetAppStatus(namespace, rel.Name)
		if err != nil {
			m.logger.Warn("Failed to get status for release",
				zap.String("release", rel.Name),
				zap.String("namespace", namespace),
				zap.Error(err))
			continue
		}
		apps = append(apps, app)
	}

	return apps, nil
}

// ListAllApps 列出所有命名空间中的应用
func (m *HelmManager) ListAllApps() ([]*model.RancherResponse, error) {
	// 获取所有命名空间
	namespaces, err := m.getAllNamespaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get namespaces: %v", err)
	}

	var allApps []*model.RancherResponse
	for _, ns := range namespaces {
		apps, err := m.ListApps(ns)
		if err != nil {
			m.logger.Warn("Failed to list apps in namespace",
				zap.String("namespace", ns),
				zap.Error(err))
			continue
		}
		allApps = append(allApps, apps...)
	}

	return allApps, nil
}

// getAllNamespaces 获取所有命名空间
func (m *HelmManager) getAllNamespaces() ([]string, error) {
	// 这里简化处理，实际应该查询 Kubernetes API
	// 为演示目的，返回常用命名空间列表
	return []string{
		"default",
		"kube-system",
		"kube-public",
		"cattle-system",
		"cattle-prometheus",
		"fleet-system",
	}, nil
}

// mapHelmStateToRancher 将 Helm release 状态转换为 Rancher 兼容的状态
func (m *HelmManager) mapHelmStateToRancher(rel *release.Release) string {
	switch rel.Info.Status {
	case release.StatusDeployed:
		return "active"
	case release.StatusFailed:
		return "error"
	case release.StatusUninstalling:
		return "removing"
	case release.StatusPendingInstall, release.StatusPendingUpgrade:
		return "installing"
	case release.StatusUninstalled:
		return "removed"
	default:
		// 对于其他未知状态，返回安装中（让前端继续轮询）
		return "installing"
	}
}

// getActionConfig 初始化 K8s 连接
func (m *HelmManager) getActionConfig(namespace string) (*action.Configuration, error) {
	actionConfig := new(action.Configuration)

	// 使用 K8s 标准库加载配置 (InCluster 或 ~/.kube/config)
	cf := genericclioptions.NewConfigFlags(true)

	// 绑定 namespace
	cf.Namespace = &namespace

	if err := actionConfig.Init(cf, namespace, m.cfg.Helm.Driver, func(format string, v ...interface{}) {
		// 将 Helm 内部日志重定向到 Zap
		m.logger.Debug(fmt.Sprintf(format, v...))
	}); err != nil {
		return nil, err
	}
	return actionConfig, nil
}

// resolveChart 解析 externalId
// 示例: catalog://?catalog=jrhelm&template=jianren-saas&version=0.1.54
func (m *HelmManager) resolveChart(externalID string) (string, string, error) {
	cleanID := strings.Replace(externalID, "catalog://", "http://dummy", 1)
	u, err := url.Parse(cleanID)
	if err != nil {
		return "", "", err
	}
	q := u.Query()
	catalog := q.Get("catalog")
	template := q.Get("template")
	version := q.Get("version")

	baseURL, ok := m.cfg.Helm.RepoMap[catalog]
	if !ok {
		// 如果未配置映射，尝试直接使用 catalog 名字（假设已添加 helm repo add）
		// 为了稳定，建议强制配置映射
		return "", "", fmt.Errorf("unknown catalog registry: %s", catalog)
	}

	// 构建 chart reference，支持两种模式：
	// 1. 如果配置了具体的仓库 URL，使用完整的 chart reference
	// 2. 否则使用简单的 repo/chart 格式，让 Helm 处理

	var chartRef string
	if strings.HasPrefix(baseURL, "http://") || strings.HasPrefix(baseURL, "https://") {
		// 高级模式：构建完整的 chart URL
		// 支持 ChartMuseum、Harbor 等 HTTP 仓库
		if version != "" {
			// 区分公共仓库和私有仓库的文件路径
			// 私有仓库（如 Harbor/ChartMuseum）通常直接将 charts 放在 repository 路径下，不需要 /charts/ 中间层
			if strings.Contains(baseURL, "repository/helm") {
				// 私有仓库格式：http://host:port/repository/helm/podinfo-6.5.4.tgz
				chartRef = fmt.Sprintf("%s/%s-%s.tgz", baseURL, template, version)
			} else {
				// 公共仓库格式：http://host/charts/podinfo-6.5.4.tgz
				chartRef = fmt.Sprintf("%s/charts/%s-%s.tgz", baseURL, template, version)
			}
		} else {
			chartRef = fmt.Sprintf("%s/%s", baseURL, template)
		}
	} else {
		// 简单模式：直接返回 RepoName/ChartName 让 Helm 处理
		// 这需要预先通过 helm repo add 添加仓库
		chartRef = fmt.Sprintf("%s/%s", catalog, template)
		if version != "" {
			chartRef = fmt.Sprintf("%s --version %s", chartRef, version)
		}
	}

	return chartRef, version, nil
}

// extractChartName 从 externalId 中提取 chart 名称（用于指标）
func (m *HelmManager) extractChartName(externalID string) string {
	cleanID := strings.Replace(externalID, "catalog://", "http://dummy", 1)
	u, err := url.Parse(cleanID)
	if err != nil {
		return "unknown"
	}
	q := u.Query()
	template := q.Get("template")
	if template == "" {
		return "unknown"
	}
	return template
}

// downloadChart 定位和下载 Chart（带缓存）
func (m *HelmManager) downloadChart(chartRef, version string, cfg *action.Configuration) (string, error) {
	// 生成缓存键
	cacheKey := fmt.Sprintf("%s:%s", chartRef, version)

	// 先从缓存中查找
	if entry, found := m.chartCache.Get(cacheKey); found {
		m.logger.Debug("Chart cache hit",
			zap.String("chart", chartRef),
			zap.String("version", version),
			zap.String("path", entry.ChartPath))

		// 验证缓存的Chart路径是否仍然存在
		if _, err := os.Stat(entry.ChartPath); err == nil {
			return entry.ChartPath, nil
		}
		// 如果路径不存在，则重新下载
		m.logger.Warn("Cached chart path not found, re-downloading",
			zap.String("path", entry.ChartPath))
	}

	m.logger.Debug("Chart cache miss, downloading",
		zap.String("chart", chartRef),
		zap.String("version", version))

	client := action.NewInstall(cfg)
	client.ChartPathOptions.Version = version

	// 支持私有仓库认证 - 从环境变量获取认证信息
	if username := os.Getenv("HELM_USERNAME"); username != "" {
		client.ChartPathOptions.Username = username
		m.logger.Debug("Using Helm username from environment",
			zap.String("username", username))
	}
	if password := os.Getenv("HELM_PASSWORD"); password != "" {
		client.ChartPathOptions.Password = password
		m.logger.Debug("Using Helm password from environment")
	}

	cp, err := client.ChartPathOptions.LocateChart(chartRef, m.settings)
	if err != nil {
		return "", err
	}

	// 将下载的Chart放入缓存
	entry := &ChartEntry{
		ChartPath:   cp,
		DownloadedAt: time.Now(),
		Version:     version,
		ChartName:   chartRef,
	}
	m.chartCache.Set(cacheKey, entry)

	m.logger.Info("Chart downloaded and cached",
		zap.String("chart", chartRef),
		zap.String("version", version),
		zap.String("path", cp))

	return cp, nil
}

// ParseValues 解析values参数
func (m *HelmManager) ParseValues(answers map[string]string, valuesYaml string) (map[string]interface{}, error) {
	base := map[string]interface{}{}

	// 1. 处理 YAML - 使用 yaml.Unmarshal 而不是 strvals.ParseInto
	if valuesYaml != "" {
		if err := yaml.Unmarshal([]byte(valuesYaml), &base); err != nil {
			return nil, fmt.Errorf("failed to parse values.yaml: %v", err)
		}
	}
	// 智能推断：设置了 nodePort 但没设置 type，自动设置为 NodePort
	hasNodePort := false
	hasServiceType := false

	// 检查 answers 中是否包含相关键
	for k := range answers {
		if k == "service.nodePort" {
			hasNodePort = true
		}
		if k == "service.type" {
			hasServiceType = true
		}
	}

	// 检查 base (valuesYaml) 中是否已有相关配置
	if serviceMap, ok := base["service"].(map[string]interface{}); ok {
		if _, exists := serviceMap["nodePort"]; exists {
			hasNodePort = true
		}
		if _, exists := serviceMap["type"]; exists {
			hasServiceType = true
		}
	}

	// 自动推断
	if hasNodePort && !hasServiceType {
		if err := strvals.ParseInto("service.type=NodePort", base); err != nil {
			return nil, err
		}
		m.logger.Debug("Auto-inferred service.type=NodePort based on nodePort setting")
	}

	// 2. 处理 Answers (点分键值对)
	for k, v := range answers {
		if err := strvals.ParseInto(fmt.Sprintf("%s=%s", k, v), base); err != nil {
			return nil, err
		}
	}
	return base, nil
}

// BuildResponse 构建响应
func (m *HelmManager) BuildResponse(rel *release.Release, req model.RancherRequest) *model.RancherResponse {
	projectID := req.ProjectID
	if projectID == "" {
		projectID = "default"
	}

	appID := fmt.Sprintf("%s:%s", projectID, req.Name)

	// 计算状态
	state := "active"
	transitioning := "no"
	if rel.Info.Status.String() == "pending-install" || rel.Info.Status.String() == "pending-upgrade" {
		state = "installing"
		transitioning = "yes"
	}

	// 生成时间戳
	createdTS := time.Now().UnixMilli()

	return &model.RancherResponse{
		ID:                   appID,
		BaseType:             "app",
		Type:                 "app",
		Name:                 rel.Name,
		State:                state,
		TargetNamespace:      rel.Namespace,
		ExternalID:           req.ExternalID,
		ProjectID:            projectID,
		Prune:                req.Prune,
		Timeout:              req.Timeout,
		Wait:                 req.Wait,
		ValuesYaml:           req.ValuesYaml,
		Answers:              req.Answers,
		Created:              time.Now().Format(time.RFC3339),
		CreatedTS:            createdTS,
		UUID:                 uuid.New().String(),
		Labels:               map[string]string{"cattle.io/creator": "norman"},
		Annotations:          map[string]string{},
		Transitioning:        transitioning,
		TransitioningMessage: "",
		AppRevisionID:        "",
		MultiClusterAppID:    "",
		NamespaceID:          "",
		CreatorID:            "user-helm-proxy",
		Links: map[string]string{
			"self":     fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s", projectID, appID),
			"update":   fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s", projectID, appID),
			"remove":   fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s", projectID, appID),
			"revision": fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s/revision", projectID, appID),
		},
		ActionLinks: map[string]string{
			"upgrade":  fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s?action=upgrade", projectID, appID),
			"rollback": fmt.Sprintf("https://192.168.82.192:8443/v3/project/%s/apps/%s?action=rollback", projectID, appID),
		},
	}
}

// UninstallApp 卸载应用
func (m *HelmManager) UninstallApp(namespace, name string) error {
	startTime := time.Now()

	// 获取 Prometheus 指标实例
	promMetrics := GetPrometheusMetrics()

	// 记录 Helm 操作开始
	promMetrics.RecordHelmOperationStart("uninstall")

	// 获取锁 (Namespace + Name)
	lockKey := fmt.Sprintf("%s/%s", namespace, name)
	muRaw, _ := m.keyLock.LoadOrStore(lockKey, &sync.Mutex{})
	mu := muRaw.(*sync.Mutex)

	// 尝试加锁，避免同一应用并发操作
	mu.Lock()
	defer mu.Unlock()

	m.logger.Info("Uninstalling application", zap.String("name", name), zap.String("ns", namespace))

	// 初始化 Helm 配置
	cfg, err := m.getActionConfig(namespace)
	if err != nil {
		promMetrics.RecordHelmFailure("uninstall", "config_failed")
		promMetrics.RecordHelmOperationEnd("uninstall")
		return fmt.Errorf("failed to get action config: %v", err)
	}

	// 创建卸载客户端
	client := action.NewUninstall(cfg)
	client.Timeout = time.Duration(m.cfg.Helm.Timeout) * time.Second

	// 执行卸载
	_, err = client.Run(name)
	if err != nil {
		duration := time.Since(startTime)
		promMetrics.RecordHelmFailure("uninstall", err.Error())
		promMetrics.RecordHelmOperation("uninstall", "failed", duration)
		promMetrics.RecordHelmOperationEnd("uninstall")
		return fmt.Errorf("failed to uninstall release: %v", err)
	}

	// 记录成功
	duration := time.Since(startTime)
	promMetrics.RecordHelmOperation("uninstall", "success", duration)
	promMetrics.RecordHelmOperationEnd("uninstall")

	m.logger.Info("Application uninstalled successfully", zap.String("name", name), zap.String("ns", namespace), zap.Duration("duration", duration))
	return nil
}

// UpgradeApp 升级应用
func (m *HelmManager) UpgradeApp(namespace, name, version string, values map[string]interface{}) (*release.Release, error) {
	startTime := time.Now()

	// 获取 Prometheus 指标实例
	promMetrics := GetPrometheusMetrics()

	// 记录 Helm 操作开始
	promMetrics.RecordHelmOperationStart("upgrade")

	// 获取锁 (Namespace + Name)
	lockKey := fmt.Sprintf("%s/%s", namespace, name)
	muRaw, _ := m.keyLock.LoadOrStore(lockKey, &sync.Mutex{})
	mu := muRaw.(*sync.Mutex)

	// 尝试加锁，避免同一应用并发操作
	mu.Lock()
	defer mu.Unlock()

	m.logger.Info("Upgrading application", zap.String("name", name), zap.String("ns", namespace), zap.String("version", version))

	// 初始化 Helm 配置
	cfg, err := m.getActionConfig(namespace)
	if err != nil {
		promMetrics.RecordHelmFailure("upgrade", "config_failed")
		promMetrics.RecordHelmOperationEnd("upgrade")
		return nil, fmt.Errorf("failed to get action config: %v", err)
	}

	// 获取当前 release 信息
	statusClient := action.NewStatus(cfg)
	rel, err := statusClient.Run(name)
	if err != nil {
		promMetrics.RecordHelmFailure("upgrade", "not_found")
		promMetrics.RecordHelmOperationEnd("upgrade")
		return nil, fmt.Errorf("release not found: %v", err)
	}

	// 解析 ExternalID 获取 chart 信息
	var externalID string
	if rel.Chart != nil && rel.Chart.Metadata != nil {
		// 从 chart metadata 构建 externalId
		// 这里简化处理，实际应该从存储的 externalId 获取
		chartName := rel.Chart.Metadata.Name
		if version == "" {
			version = rel.Chart.Metadata.Version
		}
		// 需要从 repo map 中找到匹配的 catalog 名称
		// 这里假设使用第一个匹配的仓库
		var catalogName string
		for name, url := range m.cfg.Helm.RepoMap {
			if strings.Contains(url, "repository/helm") || strings.Contains(url, chartName) {
				catalogName = name
				break
			}
		}
		if catalogName != "" {
			externalID = fmt.Sprintf("catalog://?catalog=%s&template=%s&version=%s", catalogName, chartName, version)
		}
	}

	// 解析 externalId 获取 chart URL
	var chartURL string
	if externalID != "" {
		chartURL, _, err = m.resolveChart(externalID)
		if err != nil {
			promMetrics.RecordHelmFailure("upgrade", "invalid_external_id")
			promMetrics.RecordHelmOperationEnd("upgrade")
			return nil, fmt.Errorf("invalid externalId: %v", err)
		}
	} else {
		// 回退：使用当前 chart
		chartURL = rel.Chart.Name()
	}

	// 下载 chart
	cp, err := m.downloadChart(chartURL, version, cfg)
	if err != nil {
		promMetrics.RecordHelmFailure("upgrade", "chart_download_failed")
		promMetrics.RecordHelmOperationEnd("upgrade")
		return nil, fmt.Errorf("failed to download chart: %v", err)
	}

	loadedChart, err := loader.Load(cp)
	if err != nil {
		promMetrics.RecordHelmFailure("upgrade", "chart_load_failed")
		promMetrics.RecordHelmOperationEnd("upgrade")
		return nil, fmt.Errorf("failed to load chart: %v", err)
	}

	// 创建升级客户端
	client := action.NewUpgrade(cfg)
	client.Namespace = namespace
	client.Timeout = time.Duration(m.cfg.Helm.Timeout) * time.Second
	client.Atomic = true // 生产环境必须 Atomic
	client.Wait = true   // 升级默认等待完成

	// 执行升级
	rel, err = client.Run(name, loadedChart, values)
	if err != nil {
		duration := time.Since(startTime)
		promMetrics.RecordHelmFailure("upgrade", err.Error())
		promMetrics.RecordHelmOperation("upgrade", "failed", duration)
		promMetrics.RecordHelmOperationEnd("upgrade")
		return nil, fmt.Errorf("failed to upgrade release: %v", err)
	}

	// 记录成功
	duration := time.Since(startTime)
	promMetrics.RecordHelmOperation("upgrade", "success", duration)
	promMetrics.RecordHelmOperationEnd("upgrade")

	m.logger.Info("Application upgraded successfully", zap.String("name", name), zap.String("ns", namespace), zap.Duration("duration", duration))
	return rel, nil
}

// RollbackApp 回滚应用
func (m *HelmManager) RollbackApp(namespace, name string, revision int) (*release.Release, error) {
	startTime := time.Now()

	// 获取 Prometheus 指标实例
	promMetrics := GetPrometheusMetrics()

	// 记录 Helm 操作开始
	promMetrics.RecordHelmOperationStart("rollback")

	// 获取锁 (Namespace + Name)
	lockKey := fmt.Sprintf("%s/%s", namespace, name)
	muRaw, _ := m.keyLock.LoadOrStore(lockKey, &sync.Mutex{})
	mu := muRaw.(*sync.Mutex)

	// 尝试加锁，避免同一应用并发操作
	mu.Lock()
	defer mu.Unlock()

	m.logger.Info("Rolling back application", zap.String("name", name), zap.String("ns", namespace), zap.Int("revision", revision))

	// 初始化 Helm 配置
	cfg, err := m.getActionConfig(namespace)
	if err != nil {
		promMetrics.RecordHelmFailure("rollback", "config_failed")
		promMetrics.RecordHelmOperationEnd("rollback")
		return nil, fmt.Errorf("failed to get action config: %v", err)
	}

	// 创建回滚客户端
	client := action.NewRollback(cfg)
	client.Timeout = time.Duration(m.cfg.Helm.Timeout) * time.Second
	client.Wait = true   // 回滚默认等待完成
	client.Recreate = true

	if revision > 0 {
		client.Version = revision
	}

	// 执行回滚
	err = client.Run(name)
	if err != nil {
		duration := time.Since(startTime)
		promMetrics.RecordHelmFailure("rollback", err.Error())
		promMetrics.RecordHelmOperation("rollback", "failed", duration)
		promMetrics.RecordHelmOperationEnd("rollback")
		return nil, fmt.Errorf("failed to rollback release: %v", err)
	}

	// 获取回滚后的状态
	statusClient := action.NewStatus(cfg)
	rel, err := statusClient.Run(name)
	if err != nil {
		promMetrics.RecordHelmFailure("rollback", "status_check_failed")
		promMetrics.RecordHelmOperationEnd("rollback")
		return nil, fmt.Errorf("failed to get status after rollback: %v", err)
	}

	// 记录成功
	duration := time.Since(startTime)
	promMetrics.RecordHelmOperation("rollback", "success", duration)
	promMetrics.RecordHelmOperationEnd("rollback")

	m.logger.Info("Application rolled back successfully", zap.String("name", name), zap.String("ns", namespace), zap.Duration("duration", duration))
	return rel, nil
}
