package telemetry

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type Config struct {
	Enabled        bool
	Endpoint       string
	Insecure       bool
	SampleRatio    float64
	ExportTimeout  time.Duration
	ServiceVersion string
}

type Shutdown func(context.Context) error

func Setup(ctx context.Context, config Config) (Shutdown, error) {
	if !config.Enabled {
		return func(context.Context) error { return nil }, nil
	}
	endpoint, err := validateEndpoint(config.Endpoint, config.Insecure)
	if err != nil {
		return nil, err
	}
	if math.IsNaN(config.SampleRatio) || math.IsInf(config.SampleRatio, 0) || config.SampleRatio <= 0 || config.SampleRatio > 1 {
		return nil, fmt.Errorf("OpenTelemetry sample ratio must be greater than zero and no more than one")
	}
	if config.ExportTimeout <= 0 {
		config.ExportTimeout = 5 * time.Second
	}

	options := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(endpoint),
		otlptracehttp.WithTimeout(config.ExportTimeout),
	}
	if config.Insecure {
		options = append(options, otlptracehttp.WithInsecure())
	}
	exporter, err := otlptracehttp.New(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("initialize OTLP HTTP trace exporter: %w", err)
	}

	serviceResource := resource.NewSchemaless(
		attribute.String("service.name", "kubeathrix-api"),
		attribute.String("service.version", config.ServiceVersion),
	)
	mergedResource, err := resource.Merge(resource.Default(), serviceResource)
	if err != nil {
		return nil, fmt.Errorf("build OpenTelemetry resource: %w", err)
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(mergedResource),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(config.SampleRatio))),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	return provider.Shutdown, nil
}

func Instrument(next http.Handler) http.Handler {
	withTraceHeader := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spanContext := trace.SpanContextFromContext(r.Context())
		if spanContext.IsValid() {
			w.Header().Set("X-Trace-ID", spanContext.TraceID().String())
		}
		next.ServeHTTP(w, r)
	})
	return otelhttp.NewHandler(withTraceHeader, "kubeathrix.http")
}

func validateEndpoint(raw string, insecure bool) (string, error) {
	endpoint := strings.TrimSpace(raw)
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("a valid absolute OTLP HTTP endpoint is required when tracing is enabled")
	}
	expectedScheme := "https"
	if insecure {
		expectedScheme = "http"
	}
	if parsed.Scheme != expectedScheme {
		return "", fmt.Errorf("OTLP HTTP endpoint must use %s for the configured transport mode", expectedScheme)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("OTLP HTTP endpoint must not contain credentials or a fragment")
	}
	return parsed.String(), nil
}
