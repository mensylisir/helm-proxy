package main

import (
	"flag"
	"fmt"

	"go.uber.org/zap"

	"github.com/mensylisir/helm-proxy/config"
	"github.com/mensylisir/helm-proxy/server"
)

var (
	showVersion = flag.Bool("version", false, "Show version information")
	configFile  = flag.String("config", "", "Configuration file path")
	port        = flag.String("port", "", "Server port")
	logLevel    = flag.String("log-level", "", "Log level (debug, info, warn, error)")
)

func main() {
	// 解析命令行参数
	flag.Parse()
	
	// 显示版本信息
	if *showVersion {
		fmt.Println("Helm Proxy v1.0.0")
		return
	}
	
	// 1. 加载配置
	cfg, err := config.LoadWithOptions(*configFile, *port, *logLevel)
	if err != nil {
		panic(fmt.Sprintf("Failed to load configuration: %v", err))
	}
	
	// 2. 初始化日志（基于配置）
	var logger *zap.Logger
	
	// 根据配置创建不同级别的日志
	switch cfg.Monitoring.LogLevel {
	case "debug":
		logger, err = zap.NewDevelopment()
	case "warn":
		logger, err = zap.NewProduction()
		zap.ReplaceGlobals(logger)
		logger = logger.Named("helm-proxy")
	case "error":
		logger, err = zap.NewProduction()
		zap.ReplaceGlobals(logger)
		logger = logger.Named("helm-proxy")
	default: // "info" 和其他值
		logger, err = zap.NewProduction()
	}
	
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}
	defer logger.Sync()
	
	// 设置全局日志配置
	zap.ReplaceGlobals(logger)
	
	logger.Info("Starting Helm Proxy", 
		zap.String("port", cfg.Server.Port), 
		zap.Any("repos", cfg.Helm.RepoMap),
		zap.String("log_level", cfg.Monitoring.LogLevel))
	
	// 3. 创建并启动服务器
	srv := server.NewServer(cfg, logger)
	
	// 启动服务器（支持优雅关闭）
	if err := srv.StartWithGracefulShutdown(); err != nil {
		logger.Fatal("Server failed to start", zap.Error(err))
	}
}
