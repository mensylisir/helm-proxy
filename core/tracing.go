package core

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.uber.org/zap"

	"github.com/mensylisir/helm-proxy/config"
)

// TracingProvider 链路追踪提供者
type TracingProvider struct {
	tp          *tracesdk.TracerProvider
	shutdown    func(context.Context) error
	serviceName string
	logger      *zap.Logger
}

// InitTracing 初始化链路追踪
func InitTracing(config *config.TracingConfig, logger *zap.Logger) (*TracingProvider, error) {
	if !config.Enabled {
		logger.Info("Tracing is disabled")
		return nil, nil
	}

	var tp *tracesdk.TracerProvider
	var shutdown func(context.Context) error
	var err error

	// 创建资源
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(config.ServiceName),
			semconv.ServiceVersion("1.0.0"),
			attribute.String("environment", "production"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// 创建tracer provider（暂时使用默认provider，后续可配置exporter）
	tp = tracesdk.NewTracerProvider(
		tracesdk.WithResource(res),
		tracesdk.WithSampler(tracesdk.TraceIDRatioBased(config.SampleRate)),
	)

	// 设置全局tracer provider
	otel.SetTracerProvider(tp)

	// 设置文本map propagator（用于trace传播）
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)

	// 设置关闭函数
	shutdown = func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()

		if err := tp.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown tracer provider: %w", err)
		}
		return nil
	}

	tpProvider := &TracingProvider{
		tp:          tp,
		shutdown:    shutdown,
		serviceName: config.ServiceName,
		logger:      logger,
	}

	logger.Info("Tracing initialized successfully",
		zap.String("service", config.ServiceName),
		zap.Float64("sample_rate", config.SampleRate),
		zap.String("note", "Exporter configuration needed for Jaeger/Zipkin output"),
	)

	return tpProvider, nil
}

// Shutdown 关闭tracer provider
func (tp *TracingProvider) Shutdown(ctx context.Context) error {
	if tp == nil || tp.shutdown == nil {
		return nil
	}
	return tp.shutdown(ctx)
}

// GetTracer 获取tracer
func (tp *TracingProvider) GetTracer(name string) interface{} {
	return otel.Tracer(name)
}

// ServiceName 获取服务名
func (tp *TracingProvider) ServiceName() string {
	if tp == nil {
		return ""
	}
	return tp.serviceName
}

// RecordCustomEvent 记录自定义事件
func (tp *TracingProvider) RecordCustomEvent(
	ctx context.Context,
	eventName string,
	attributes map[string]interface{},
) {
	if tp == nil {
		return
	}

	_, span := otel.Tracer(tp.serviceName).Start(ctx, fmt.Sprintf("event.%s", eventName))

	for key, value := range attributes {
		span.SetAttributes(attribute.String(key, fmt.Sprintf("%v", value)))
	}

	span.End()
}

// RecordHelmOperation 记录Helm操作到追踪
func (tp *TracingProvider) RecordHelmOperation(
	ctx context.Context,
	operation string,
	namespace string,
	releaseName string,
	chartName string,
	duration time.Duration,
	err error,
) {
	if tp == nil {
		return
	}

	_, span := otel.Tracer(tp.serviceName).Start(ctx, fmt.Sprintf("helm.%s", operation))

	span.SetAttributes(
		attribute.String("helm.operation", operation),
		attribute.String("k8s.namespace", namespace),
		attribute.String("helm.release", releaseName),
		attribute.String("helm.chart", chartName),
		attribute.Float64("duration_ms", float64(duration.Nanoseconds())/1e6),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(2, err.Error()) // 2 = Error status
	} else {
		span.SetStatus(1, "OK") // 1 = Ok status
	}

	span.End()
}

// RecordK8sOperation 记录K8s操作到追踪
func (tp *TracingProvider) RecordK8sOperation(
	ctx context.Context,
	resourceType string,
	operation string,
	namespace string,
	resourceName string,
	duration time.Duration,
	err error,
) {
	if tp == nil {
		return
	}

	_, span := otel.Tracer(tp.serviceName).Start(ctx, fmt.Sprintf("k8s.%s.%s", resourceType, operation))

	span.SetAttributes(
		attribute.String("k8s.resource_type", resourceType),
		attribute.String("k8s.operation", operation),
		attribute.String("k8s.namespace", namespace),
		attribute.String("k8s.resource_name", resourceName),
		attribute.Float64("duration_ms", float64(duration.Nanoseconds())/1e6),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(2, err.Error())
	} else {
		span.SetStatus(1, "OK")
	}

	span.End()
}

// GetTraceID 获取trace ID
func (tp *TracingProvider) GetTraceID(ctx context.Context) string {
	if tp == nil {
		return ""
	}

	spanCtx := trace.SpanContextFromContext(ctx)
	return spanCtx.TraceID().String()
}

// AddTraceAttributes 添加trace属性
func (tp *TracingProvider) AddTraceAttributes(ctx context.Context, attributes map[string]interface{}) {
	if tp == nil {
		return
	}

	_, span := otel.Tracer(tp.serviceName).Start(ctx, "add.attributes")

	for key, value := range attributes {
		span.SetAttributes(attribute.String(key, fmt.Sprintf("%v", value)))
	}

	span.End()
}