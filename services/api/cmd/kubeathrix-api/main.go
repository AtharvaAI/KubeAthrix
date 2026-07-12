package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/adapters"
	"github.com/atharvaai/kubeathrix/services/api/internal/auth"
	"github.com/atharvaai/kubeathrix/services/api/internal/cluster"
	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/findings"
	"github.com/atharvaai/kubeathrix/services/api/internal/httpapi"
	"github.com/atharvaai/kubeathrix/services/api/internal/postgres"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
	"github.com/atharvaai/kubeathrix/services/api/internal/telemetry"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	startupContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var repository store.Repository = store.NewMemoryStore(store.WithIntegrations(integrationsFromEnv()))
	databaseConfigured := false
	if databaseURL := os.Getenv("DATABASE_URL"); databaseURL != "" {
		pgStore, err := postgres.New(startupContext, databaseURL, repository)
		if err != nil {
			logger.Error("failed to initialize postgres adapter", "error", err)
			os.Exit(1)
		}
		defer pgStore.Close()
		repository = pgStore
		databaseConfigured = true
	}

	var clusterInspector httpapi.ClusterInspector
	var nativeSource adapters.NativeSource
	if os.Getenv("KUBEATHRIX_CLUSTER_INSPECTOR") != "false" {
		inspector, err := cluster.NewInspector()
		if err != nil {
			logger.Warn("cluster inspector disabled", "error", err)
		} else {
			clusterInspector = inspector
			nativeSource = inspector
		}
	}

	var adapterManager httpapi.AdapterManager
	if os.Getenv("KUBEATHRIX_ADAPTERS_ENABLED") != "false" {
		if manager, err := adapters.NewManager(nativeSource); err != nil {
			logger.Warn("external report adapters unavailable", "error", err)
		} else {
			adapterManager = manager
		}
	}

	chaosExecutionEnabled := os.Getenv("KUBEATHRIX_CHAOS_EXECUTION") == "true"
	chaosRunner := cluster.NewChaosPreflightRunner(os.Getenv("KUBEATHRIX_CHAOS_NAMESPACE_ALLOWLIST"))
	if chaosExecutionEnabled {
		if !databaseConfigured {
			logger.Error("chaos execution requires durable Postgres persistence")
			os.Exit(1)
		}
		if strings.TrimSpace(os.Getenv("KUBEATHRIX_CHAOS_NAMESPACE_ALLOWLIST")) == "" {
			logger.Error("chaos execution requires a non-empty namespace allowlist")
			os.Exit(1)
		}
		runner, err := cluster.NewChaosRunner()
		if err != nil {
			logger.Error("chaos execution configuration failed closed", "error", err)
			os.Exit(1)
		}
		chaosRunner = runner
		if err := chaosRunner.Health(startupContext); err != nil {
			logger.Error("Chaos Mesh API validation failed closed", "error", err)
			os.Exit(1)
		}
	}
	chaosManager := cluster.NewChaosManager(repository, chaosRunner, chaosExecutionEnabled, logger)

	allowMemoryWorkflows := os.Getenv("KUBEATHRIX_INSECURE_MEMORY_WORKFLOWS") == "true"
	var workflowClient httpapi.WorkflowClient
	if allowMemoryWorkflows {
		logger.Warn("INSECURE in-memory workflow mode is enabled; remediation state is not backed by Kubernetes CRDs")
	} else {
		client, err := cluster.NewWorkflowClient(envOrDefault("POD_NAMESPACE", "kubeathrix"))
		if err != nil {
			logger.Error("Kubernetes workflow client failed closed", "error", err)
			os.Exit(1)
		}
		workflowClient = client
	}

	insecureDevAuth := os.Getenv("KUBEATHRIX_INSECURE_DEV_AUTH") == "true"
	var authenticator auth.Verifier
	if insecureDevAuth {
		logger.Warn("INSECURE development authentication is enabled; every request has administrator privileges")
	} else {
		issuer := os.Getenv("OIDC_ISSUER_URL")
		clientID := os.Getenv("OIDC_CLIENT_ID")
		verifier, err := auth.NewOIDCVerifier(startupContext, auth.OIDCConfig{IssuerURL: issuer, ClientID: clientID})
		if err != nil {
			logger.Error("authentication configuration failed closed", "error", err)
			os.Exit(1)
		}
		authenticator = verifier
	}

	tracingEnabled := os.Getenv("KUBEATHRIX_OTEL_TRACING_ENABLED") == "true"
	traceSampleRatio, traceExportTimeout := 0.1, 5*time.Second
	if tracingEnabled {
		var parseErr error
		traceSampleRatio, parseErr = strictFloatEnv("KUBEATHRIX_OTEL_SAMPLE_RATIO", traceSampleRatio)
		if parseErr == nil {
			traceExportTimeout, parseErr = strictDurationEnv("KUBEATHRIX_OTEL_EXPORT_TIMEOUT", traceExportTimeout)
		}
		if parseErr != nil {
			logger.Error("OpenTelemetry tracing configuration failed closed", "error", parseErr)
			os.Exit(1)
		}
	}
	shutdownTracing, err := telemetry.Setup(startupContext, telemetry.Config{
		Enabled:        tracingEnabled,
		Endpoint:       os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		Insecure:       os.Getenv("KUBEATHRIX_OTEL_INSECURE") == "true",
		SampleRatio:    traceSampleRatio,
		ExportTimeout:  traceExportTimeout,
		ServiceVersion: "0.2.0",
	})
	if err != nil {
		logger.Error("OpenTelemetry tracing configuration failed closed", "error", err)
		os.Exit(1)
	}

	server := httpapi.NewServer(repository, httpapi.Config{
		InsecureDevAuth:      insecureDevAuth,
		OIDCIssuerURL:        os.Getenv("OIDC_ISSUER_URL"),
		OIDCClientID:         os.Getenv("OIDC_CLIENT_ID"),
		Authenticator:        authenticator,
		ClusterID:            envOrDefault("KUBEATHRIX_CLUSTER_ID", "default"),
		MaxRequestBytes:      int64Env("KUBEATHRIX_MAX_REQUEST_BYTES", 1<<20),
		RateLimitPerMinute:   intEnv("KUBEATHRIX_RATE_LIMIT_PER_MINUTE", 120),
		Logger:               logger,
		ClusterInspector:     clusterInspector,
		ChaosManager:         chaosManager,
		WorkflowClient:       workflowClient,
		AllowMemoryWorkflows: allowMemoryWorkflows,
		AdapterManager:       adapterManager,
		RiskConfig:           mustRiskConfig(logger, os.Getenv("KUBEATHRIX_RISK_CONFIG_JSON")),
		FindingExpiry:        durationEnv("KUBEATHRIX_FINDING_EXPIRY", 24*time.Hour),
	})

	addr := ":8080"
	if fromEnv := os.Getenv("PORT"); fromEnv != "" {
		addr = ":" + fromEnv
	}

	handler := server.Routes()
	if tracingEnabled {
		handler = telemetry.Instrument(handler)
	}
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	stopContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	chaosManager.StartReconciler(stopContext)
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- httpServer.ListenAndServe()
	}()
	logger.Info("starting kubeathrix api", "addr", addr, "cluster_id", envOrDefault("KUBEATHRIX_CLUSTER_ID", "default"), "insecure_dev_auth", insecureDevAuth)
	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("api server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	case <-stopContext.Done():
		logger.Info("shutdown signal received")
	}
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		_ = httpServer.Close()
	}
	if err := shutdownTracing(shutdownContext); err != nil {
		logger.Error("OpenTelemetry trace shutdown failed", "error", err)
	}
}

func mustRiskConfig(logger *slog.Logger, raw string) findings.Config {
	config, err := findings.ParseConfig(raw)
	if err != nil {
		logger.Error("invalid risk configuration", "error", err)
		os.Exit(1)
	}
	return config
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func intEnv(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func int64Env(name string, fallback int64) int64 {
	value, err := strconv.ParseInt(os.Getenv(name), 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func strictFloatEnv(name string, fallback float64) (float64, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number: %w", name, err)
	}
	return parsed, nil
}

func strictDurationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration", name)
	}
	return parsed, nil
}

func integrationsFromEnv() []core.Integration {
	return []core.Integration{
		integrationFromEnv("Trivy Operator", "scanner", "KUBEATHRIX_ENGINE_TRIVY_OPERATOR"),
		integrationFromEnv("Kyverno", "policy", "KUBEATHRIX_ENGINE_KYVERNO"),
		integrationFromEnv("Kubescape", "scanner", "KUBEATHRIX_ENGINE_KUBESCAPE"),
		integrationFromEnv("Falco", "runtime", "KUBEATHRIX_ENGINE_FALCO"),
		integrationFromEnv("Tetragon", "runtime", "KUBEATHRIX_ENGINE_TETRAGON"),
		integrationFromEnv("Chaos Mesh", "verification", "KUBEATHRIX_ENGINE_CHAOS_MESH"),
		integrationFromEnv("LitmusChaos", "verification", "KUBEATHRIX_ENGINE_LITMUS"),
	}
}

func integrationFromEnv(name, integrationType, envName string) core.Integration {
	enabled := os.Getenv(envName) == "true"
	status := "disabled"
	if enabled {
		status = "configured"
	}
	return core.Integration{Name: name, Type: integrationType, Enabled: enabled, Status: status}
}
