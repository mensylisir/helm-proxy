package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/mensylisir/helm-proxy/config"
	"github.com/mensylisir/helm-proxy/core"
	"github.com/mensylisir/helm-proxy/middleware"
	"github.com/mensylisir/helm-proxy/routes"
)

// Server HTTP服务器结构体
type Server struct {
	config     *config.Config
	logger     *zap.Logger
	manager    *core.HelmManager
	engine     *gin.Engine
	router     *routes.Router
}

// NewServer 创建新的HTTP服务器
func NewServer(cfg *config.Config, logger *zap.Logger) *Server {
	// 初始化Helm管理器
	manager := core.NewManagerWithProduction(cfg, config.DefaultProductionConfig(), logger)
	
	// 创建Gin引擎
	engine := gin.New()
	
	// 创建服务器实例
	server := &Server{
		config:  cfg,
		logger:  logger,
		manager: manager,
		engine:  engine,
		router:  routes.NewRouter(engine, manager, cfg, logger),
	}
	
	return server
}

// SetupMiddleware 设置中间件
func (s *Server) SetupMiddleware() {
	// 恢复中间件
	s.engine.Use(gin.Recovery())

	// 请求ID生成器（最先执行）
	s.engine.Use(middleware.RequestIDGenerator())

	// 审计日志中间件（在早期记录所有请求）
	s.engine.Use(middleware.AuditMiddleware(s.logger))

	// 结构化日志中间件
	s.engine.Use(middleware.StructuredLogger(s.logger))

	// 性能监控中间件
	s.engine.Use(middleware.PerformanceMonitor(s.logger))

	// 安全日志中间件
	s.engine.Use(middleware.SecurityLogger(s.logger))

	// CORS中间件 - 使用生产环境配置
	corsConfig := middleware.GetProductionCORSConfig()
	s.engine.Use(middleware.CORSMiddleware(corsConfig))

	// 限流中间件
	if s.config.Security.RateLimit.Enabled {
		rateLimiter := middleware.NewTokenBucketRateLimiter(
			s.config.Security.RateLimit.Rate,
			s.config.Security.RateLimit.Burst,
		)
		s.engine.Use(middleware.RateLimit(rateLimiter, func(c *gin.Context) string {
			return c.ClientIP()
		}))
	}

	// 输入验证中间件
	s.engine.Use(middleware.SanitizeInputMiddleware())

	// 错误处理中间件
	s.engine.Use(middleware.ErrorHandlingMiddleware())
}

// SetupRoutes 设置路由
func (s *Server) SetupRoutes() {
	s.router.SetupRoutes()
}

// Start 启动服务器
func (s *Server) Start() error {
	// 设置中间件
	s.SetupMiddleware()
	
	// 设置路由
	s.SetupRoutes()
	
	// 健康检查端点
	s.engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "OK",
			"timestamp": time.Now().Unix(),
			"version":   "1.0.0",
		})
	})
	
	// Metrics端点
	s.engine.GET("/metrics", middleware.MetricsHandler())
	
	// 性能摘要端点
	s.engine.GET("/performance", middleware.PerformanceSummaryHandler())
	
	// 启动服务器
	addr := ":" + s.config.Server.Port
	s.logger.Info("Starting Helm Proxy server", zap.String("address", addr))
	
	// 创建HTTP服务器
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.engine,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	// 启动服务器的goroutine
	go func() {
		s.logger.Info("Server started successfully", zap.String("address", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Fatal("Server failed to start", zap.Error(err))
		}
	}()
	
	// 等待中断信号以优雅地关闭服务器
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	s.logger.Info("Shutting down server...")
	
	// 关闭服务器
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := srv.Shutdown(ctx); err != nil {
		s.logger.Error("Server forced to shutdown", zap.Error(err))
		return err
	}
	
	s.logger.Info("Server exited")
	return nil
}

// StartWithGracefulShutdown 启动服务器并支持优雅关闭
func (s *Server) StartWithGracefulShutdown() error {
	// 设置中间件
	s.SetupMiddleware()

	// 设置路由
	s.SetupRoutes()
	
	// 启动服务器
	addr := ":" + s.config.Server.Port
	s.logger.Info("Starting Helm Proxy server with graceful shutdown", zap.String("address", addr))
	
	// 创建HTTP服务器
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.engine,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	// 启动服务器的goroutine
	go func() {
		s.logger.Info("Server started successfully", zap.String("address", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Fatal("Server failed to start", zap.Error(err))
		}
	}()
	
	// 优雅关闭处理
	return s.gracefulShutdown(srv)
}

// gracefulShutdown 优雅关闭服务器
func (s *Server) gracefulShutdown(srv *http.Server) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	s.logger.Info("Shutting down server gracefully...")
	
	// 通知服务器停止接受新请求
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// 优雅关闭服务器
	if err := srv.Shutdown(ctx); err != nil {
		s.logger.Error("Server forced to shutdown", zap.Error(err))
		return fmt.Errorf("server forced to shutdown: %v", err)
	}

	s.logger.Info("Server shutdown complete")
	return nil
}

// GetEngine 获取Gin引擎（用于测试）
func (s *Server) GetEngine() *gin.Engine {
	return s.engine
}