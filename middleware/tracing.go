package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TracingConfig 链路追踪配置
type TracingConfig struct {
	Enabled         bool   `json:"enabled"`
	ServiceName     string `json:"service_name"`
	CollectorURL    string `json:"collector_url"`
	JaegerEndpoint  string `json:"jaeger_endpoint"`
	ZipkinEndpoint  string `json:"zipkin_endpoint"`
	SampleRate      float64 `json:"sample_rate"`
	Propagation     string  `json:"propagation"` // "jaeger", "b3", "w3c"
}

// DefaultTracingConfig 默认链路追踪配置
var DefaultTracingConfig = &TracingConfig{
	Enabled:        false,
	ServiceName:    "helm-proxy",
	CollectorURL:   "http://localhost:14268/api/traces",
	JaegerEndpoint: "http://localhost:14268/api/traces",
	ZipkinEndpoint: "http://localhost:9411/api/v2/spans",
	SampleRate:     0.1,
	Propagation:    "jaeger",
}

// TraceCarrier trace传播载体
type TraceCarrier struct {
	traceID string
	spanID  string
	sampled bool
}

// GetTraceID 获取trace ID
func (tc *TraceCarrier) GetTraceID() string {
	return tc.traceID
}

// GetSpanID 获取span ID
func (tc *TraceCarrier) GetSpanID() string {
	return tc.spanID
}

// IsSampled 是否采样
func (tc *TraceCarrier) IsSampled() bool {
	return tc.sampled
}

// SetTraceID 设置trace ID
func (tc *TraceCarrier) SetTraceID(traceID string) {
	tc.traceID = traceID
}

// SetSpanID 设置span ID
func (tc *TraceCarrier) SetSpanID(spanID string) {
	tc.spanID = spanID
}

// SetSampled 设置采样
func (tc *TraceCarrier) SetSampled(sampled bool) {
	tc.sampled = sampled
}

// TracingMiddleware 链路追踪中间件
func TracingMiddleware(serviceName string, tracer trace.Tracer, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 跳过追踪的路径
		if isSkippedPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		// 创建或从请求头提取span
		ctx := c.Request.Context()
		spanName := fmt.Sprintf("%s %s", c.Request.Method, c.FullPath())

		// 创建新的span或从请求中提取
		ctx, span := tracer.Start(ctx, spanName,
			trace.WithAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.url", c.Request.URL.Path),
				attribute.String("http.scheme", c.Request.URL.Scheme),
				attribute.String("http.host", c.Request.Host),
				attribute.String("net.protocol.version", c.Request.Proto),
				attribute.String("user_agent", c.GetHeader("User-Agent")),
				attribute.String("client_ip", c.ClientIP()),
			),
		)

		// 记录请求开始时间
		startTime := time.Now()

		// 将trace信息存储到gin上下文中
		spanCtx := span.SpanContext()
		c.Set("trace_id", spanCtx.TraceID().String())
		c.Set("span_id", spanCtx.SpanID().String())

		// 继续处理请求
		c.Next()

		// 计算执行时间
		duration := time.Since(startTime)

		// 结束span并记录结果
		statusCode := c.Writer.Status()

		// 设置span属性
		span.SetAttributes(
			attribute.Int("http.status_code", statusCode),
			attribute.Int("http.response.size", c.Writer.Size()),
			attribute.String("http.status_text", http.StatusText(statusCode)),
			attribute.Float64("duration_ms", float64(duration.Nanoseconds())/1e6),
		)

		// 记录错误信息
		if len(c.Errors) > 0 {
			span.RecordError(c.Errors.Last().Err)
			span.SetStatus(codes.Error, c.Errors.Last().Error())
		} else if statusCode >= 400 {
			span.SetStatus(codes.Error, http.StatusText(statusCode))
		} else {
			span.SetStatus(codes.Ok, "OK")
		}

		// 记录到结构化日志
		logger.Info("Request traced",
			zap.String("trace_id", spanCtx.TraceID().String()),
			zap.String("span_id", spanCtx.SpanID().String()),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status_code", statusCode),
			zap.Duration("duration", duration),
		)

		// 结束span
		span.End()
	}
}

// GinContextCarrier gin上下文载体
type GinContextCarrier struct {
	*gin.Context
}

// Get 读取header值
func (gcc GinContextCarrier) Get(key string) string {
	return gcc.GetHeader(key)
}

// Set 设置header值
func (gcc GinContextCarrier) Set(key string, value string) {
	gcc.Header(key, value)
}

// Keys 返回所有key
func (gcc GinContextCarrier) Keys() []string {
	return []string{} // Gin不直接支持，但不需要实现
}

// StartHelmOperationSpan 开始Helm操作span
func StartHelmOperationSpan(
	ctx context.Context,
	tracer trace.Tracer,
	operation string,
	namespace string,
	releaseName string,
	chartName string,
) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("helm.%s", operation)

	ctx, span := tracer.Start(ctx, spanName,
		trace.WithAttributes(
			attribute.String("helm.operation", operation),
			attribute.String("k8s.namespace", namespace),
			attribute.String("helm.release", releaseName),
			attribute.String("helm.chart", chartName),
			attribute.String("service.name", "helm-proxy"),
		),
	)

	return ctx, span
}

// RecordHelmOperationError 记录Helm操作错误
func RecordHelmOperationError(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}

// FinishHelmOperationSpan 结束Helm操作span
func FinishHelmOperationSpan(span trace.Span, err error, startTime time.Time) {
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("duration_ms", float64(duration.Nanoseconds())/1e6),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "OK")
	}

	span.End()
}

// GetTraceIDFromContext 从上下文中获取trace ID
func GetTraceIDFromContext(ctx context.Context) string {
	spanCtx := trace.SpanContextFromContext(ctx)
	return spanCtx.TraceID().String()
}

// GetSpanIDFromContext 从上下文中获取span ID
func GetSpanIDFromContext(ctx context.Context) string {
	spanCtx := trace.SpanContextFromContext(ctx)
	return spanCtx.SpanID().String()
}

// InjectTraceHeaders 注入trace头到HTTP请求
func InjectTraceHeaders(ctx context.Context, req *http.Request) {
	// 使用全局tracer注入trace信息
	otel.GetTextMapPropagator().Inject(ctx, HTTPHeaderCarrier(req.Header))
}

// HTTPHeaderCarrier HTTP头部载体
type HTTPHeaderCarrier http.Header

// Get 读取header值
func (hc HTTPHeaderCarrier) Get(key string) string {
	return http.Header(hc).Get(key)
}

// Set 设置header值
func (hc HTTPHeaderCarrier) Set(key string, value string) {
	http.Header(hc).Set(key, value)
}

// Keys 返回所有key
func (hc HTTPHeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(hc))
	for k := range hc {
		keys = append(keys, k)
	}
	return keys
}