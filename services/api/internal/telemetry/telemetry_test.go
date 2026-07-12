package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestOTLPHTTPExportAndTracePropagation(t *testing.T) {
	var exports atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" || r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Errorf("unexpected OTLP request: %s %s %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		payload, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil || len(payload) == 0 {
			t.Errorf("empty OTLP payload: %v", err)
		}
		exports.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	shutdown, err := Setup(context.Background(), Config{
		Enabled: true, Endpoint: collector.URL, Insecure: true, SampleRatio: 1,
		ExportTimeout: time.Second, ServiceVersion: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = shutdown(context.Background())
		otel.SetTracerProvider(noop.NewTracerProvider())
	}()

	handler := Instrument(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := w.Header().Get("X-Trace-ID"); len(got) != 32 {
			t.Errorf("response did not expose a trace id: %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "https://kubeathrix.example/api/health", nil)
	request.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("X-Trace-ID") != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace context was not propagated: %d %#v", response.Code, response.Header())
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	if exports.Load() != 1 {
		t.Fatalf("expected one OTLP export, got %d", exports.Load())
	}
}

func TestTracingConfigurationFailsClosed(t *testing.T) {
	tests := []Config{
		{Enabled: true, Endpoint: "", SampleRatio: 1},
		{Enabled: true, Endpoint: "http://collector:4318", SampleRatio: 1},
		{Enabled: true, Endpoint: "https://user:password@collector.example", SampleRatio: 1},
		{Enabled: true, Endpoint: "https://collector.example#fragment", SampleRatio: 1},
		{Enabled: true, Endpoint: "https://collector.example", SampleRatio: 0},
	}
	for _, config := range tests {
		if _, err := Setup(context.Background(), config); err == nil {
			t.Fatalf("expected invalid tracing configuration to fail: %+v", config)
		}
	}
	if _, err := validateEndpoint("https://collector.example/otlp", false); err != nil {
		t.Fatal(err)
	}
}
