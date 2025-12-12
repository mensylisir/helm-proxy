package core

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"log"
)

// ShutdownHandler 优雅关闭处理器
type ShutdownHandler struct {
	ctx           context.Context
	cancel        context.CancelFunc
	sigChan       chan os.Signal
	wg            sync.WaitGroup
	shutdownCh    chan struct{}
	isShutting    bool
	mu            sync.RWMutex
	shutdownHooks []ShutdownHook
	timeout       time.Duration
	logger        *log.Logger
}

// ShutdownHook 关闭钩子函数
type ShutdownHook struct {
	Name  string
	Func  func(context.Context) error
	Order int
}

// NewShutdownHandler 创建关闭处理器
func NewShutdownHandler(timeout time.Duration) *ShutdownHandler {
	ctx, cancel := context.WithCancel(context.Background())
	handler := &ShutdownHandler{
		ctx:        ctx,
		cancel:     cancel,
		sigChan:    make(chan os.Signal, 1),
		shutdownCh: make(chan struct{}),
		timeout:    timeout,
		logger:     log.New(os.Stdout, "[Shutdown] ", log.LstdFlags|log.Lshortfile),
	}

	// 注册信号处理
	signal.Notify(handler.sigChan,
		syscall.SIGTERM, // 优雅关闭信号
		syscall.SIGINT,  // 中断信号 (Ctrl+C)
		syscall.SIGQUIT, // 退出信号
		syscall.SIGHUP,  // 挂起信号（重新加载配置）
	)

	go handler.handleSignals()
	return handler
}

// AddShutdownHook 添加关闭钩子
func (h *ShutdownHandler) AddShutdownHook(name string, order int, fn func(context.Context) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.shutdownHooks = append(h.shutdownHooks, ShutdownHook{
		Name:  name,
		Func:  fn,
		Order: order,
	})
}

// handleSignals 处理信号
func (h *ShutdownHandler) handleSignals() {
	defer close(h.shutdownCh)

	for {
		select {
		case sig := <-h.sigChan:
			h.logger.Printf("接收到信号: %v", sig)

			switch sig {
			case syscall.SIGHUP:
				h.logger.Println("接收到SIGHUP信号，准备重新加载配置")
				// 重新加载配置的逻辑（如果需要）
				continue
			default:
				h.logger.Printf("开始优雅关闭流程，超时时间: %v", h.timeout)
				h.initiateShutdown()
				return
			}
		case <-h.ctx.Done():
			h.logger.Println("接收到上下文取消信号，开始关闭流程")
			h.initiateShutdown()
			return
		}
	}
}

// initiateShutdown 启动关闭流程
func (h *ShutdownHandler) initiateShutdown() {
	h.mu.Lock()
	if h.isShutting {
		h.mu.Unlock()
		return
	}
	h.isShutting = true
	h.mu.Unlock()

	// 取消所有上下文中止操作
	h.cancel()

	// 执行关闭钩子
	if err := h.executeShutdownHooks(); err != nil {
		h.logger.Printf("关闭钩子执行错误: %v", err)
	}

	// 等待所有操作完成
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.wg.Wait()
	}()

	// 设置超时
	select {
	case <-done:
		h.logger.Println("所有操作已完成，优雅关闭成功")
	case <-time.After(h.timeout):
		h.logger.Printf("关闭超时 (%v)，强制退出", h.timeout)
		os.Exit(1)
	}
}

// executeShutdownHooks 执行关闭钩子
func (h *ShutdownHandler) executeShutdownHooks() error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.shutdownHooks) == 0 {
		return nil
	}

	// 按顺序排序钩子
	hooks := make([]ShutdownHook, len(h.shutdownHooks))
	copy(hooks, h.shutdownHooks)
	quicksortHooks(hooks, 0, len(hooks)-1)

	h.logger.Printf("开始执行 %d 个关闭钩子", len(hooks))

	for i, hook := range hooks {
		h.logger.Printf("执行关闭钩子 %d/%d: %s", i+1, len(hooks), hook.Name)

		ctx, cancel := context.WithTimeout(context.Background(), h.timeout/2)
		if err := hook.Func(ctx); err != nil {
			cancel()
			h.logger.Printf("关闭钩子 %s 执行失败: %v", hook.Name, err)
			continue
		}
		cancel()
	}

	return nil
}

// quicksortHooks 对关闭钩子按顺序排序
func quicksortHooks(hooks []ShutdownHook, low, high int) {
	if low < high {
		pivot := partition(hooks, low, high)
		quicksortHooks(hooks, low, pivot-1)
		quicksortHooks(hooks, pivot+1, high)
	}
}

func partition(hooks []ShutdownHook, low, high int) int {
	pivot := hooks[high].Order
	i := low - 1
	for j := low; j < high; j++ {
		if hooks[j].Order <= pivot {
			i++
			hooks[i], hooks[j] = hooks[j], hooks[i]
		}
	}
	hooks[i+1], hooks[high] = hooks[high], hooks[i+1]
	return i + 1
}

// AddOperation 添加一个运行中的操作
func (h *ShutdownHandler) AddOperation(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.wg.Add(1)
}

// CompleteOperation 标记操作完成
func (h *ShutdownHandler) CompleteOperation() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.wg.Done()
}

// ShutdownCh 获取关闭通道
func (h *ShutdownHandler) ShutdownCh() <-chan struct{} {
	return h.shutdownCh
}

// IsShuttingDown 检查是否正在关闭
func (h *ShutdownHandler) IsShuttingDown() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.isShutting
}

// ForceShutdown 强制关闭（用于紧急情况）
func (h *ShutdownHandler) ForceShutdown() {
	h.logger.Println("执行强制关闭")
	os.Exit(1)
}

// CreateContextWithShutdown 创建包含关闭检查的上下文
func (h *ShutdownHandler) CreateContextWithShutdown(parent context.Context) context.Context {
	ctx, cancel := context.WithCancel(parent)

	go func() {
		select {
		case <-h.shutdownCh:
			cancel()
		case <-h.ctx.Done():
			cancel()
		}
	}()

	return ctx
}

// ShutdownHealthChecker 健康检查器接口
type ShutdownHealthChecker interface {
	Health() map[string]interface{}
}

// ShutdownManager 关闭管理器（应用程序生命周期管理器）
type ShutdownManager struct {
	handlers   []*ShutdownHandler
	mu         sync.RWMutex
	registered bool
	logger     *log.Logger
}

// 全局关闭管理器实例
var globalShutdownManager *ShutdownManager
var shutdownOnce sync.Once

// GetGlobalShutdownManager 获取全局关闭管理器
func GetGlobalShutdownManager() *ShutdownManager {
	shutdownOnce.Do(func() {
		globalShutdownManager = NewShutdownManager()
	})
	return globalShutdownManager
}

// NewShutdownManager 创建关闭管理器
func NewShutdownManager() *ShutdownManager {
	return &ShutdownManager{
		handlers: []*ShutdownHandler{},
		logger:   log.New(os.Stdout, "[ShutdownManager] ", log.LstdFlags|log.Lshortfile),
	}
}

// RegisterHandler 注册关闭处理器
func (m *ShutdownManager) RegisterHandler(timeout time.Duration) *ShutdownHandler {
	m.mu.Lock()
	defer m.mu.Unlock()

	handler := NewShutdownHandler(timeout)
	m.handlers = append(m.handlers, handler)

	return handler
}

// Shutdown 启动关闭流程
func (m *ShutdownManager) Shutdown() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.handlers) == 0 {
		return
	}

	// 等待所有处理器完成
	for _, handler := range m.handlers {
		<-handler.shutdownCh
	}
}

// IsRegistered 检查是否已注册
func (m *ShutdownManager) IsRegistered() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.registered
}

// RegisterApplication 注册应用程序
func (m *ShutdownManager) RegisterApplication(name string, version string, buildTime string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registered = true

	log.Printf("应用程序 %s (版本: %s, 构建时间: %s) 已注册到关闭管理器", name, version, buildTime)
}

// WaitForShutdown 等待关闭信号
func WaitForShutdown() {
	GetGlobalShutdownManager().Shutdown()
}

// SetupGracefulShutdown 设置优雅关闭
func SetupGracefulShutdown(name, version, buildTime string, timeout time.Duration) *ShutdownHandler {
	manager := GetGlobalShutdownManager()
	manager.RegisterApplication(name, version, buildTime)

	handler := manager.RegisterHandler(timeout)

	// 添加默认的关闭钩子
	handler.AddShutdownHook("cleanup_temp_files", 1, cleanupTempFiles)
	handler.AddShutdownHook("close_connections", 2, closeAllConnections)
	handler.AddShutdownHook("save_state", 3, saveApplicationState)

	return handler
}

// cleanupTempFiles 清理临时文件
func cleanupTempFiles(ctx context.Context) error {
	// 清理临时文件的逻辑
	log.Println("清理临时文件...")
	// 这里可以实现临时文件清理逻辑
	return nil
}

// closeAllConnections 关闭所有连接
func closeAllConnections(ctx context.Context) error {
	// 关闭数据库连接、HTTP客户端等
	log.Println("关闭所有连接...")
	// 这里可以实现连接清理逻辑
	return nil
}

// saveApplicationState 保存应用状态
func saveApplicationState(ctx context.Context) error {
	// 保存应用状态（如果需要）
	log.Println("保存应用状态...")
	// 这里可以实现状态保存逻辑
	return nil
}

// ContextWithTimeout 创建带超时和关闭检查的上下文
func ContextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	handler := GetGlobalShutdownManager().RegisterHandler(timeout)
	return handler.CreateContextWithShutdown(context.Background()), func() {
		handler.cancel()
	}
}
