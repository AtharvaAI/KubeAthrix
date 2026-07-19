package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/adapters"
	"github.com/atharvaai/kubeathrix/services/api/internal/agent"
	"github.com/atharvaai/kubeathrix/services/api/internal/ai"
	"github.com/atharvaai/kubeathrix/services/api/internal/auth"
	"github.com/atharvaai/kubeathrix/services/api/internal/cluster"
	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/findings"
	"github.com/atharvaai/kubeathrix/services/api/internal/httpapi"
	"github.com/atharvaai/kubeathrix/services/api/internal/managedresources"
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

	var managedResourceSource httpapi.ManagedResourceSource
	if boolEnv("KUBEATHRIX_MANAGED_EXTERNAL_RESOURCES_ENABLED", false) {
		managedConfig, err := managedresources.ParseConfig(os.Getenv("KUBEATHRIX_MANAGED_EXTERNAL_RESOURCES_JSON"))
		if err != nil {
			logger.Error("managed resource discovery configuration failed closed", "error", err)
			os.Exit(1)
		}
		if !managedConfig.Enabled {
			logger.Error("managed resource discovery requires an enabled, non-empty allowlist")
			os.Exit(1)
		}
		discovery, err := managedresources.NewDiscoveryFromKubeConfig(managedConfig, nil)
		if err != nil {
			logger.Error("managed resource discovery initialization failed closed", "error", err)
			os.Exit(1)
		}
		cached := &managedResourceCache{source: discovery, now: time.Now, ttl: 30 * time.Second}
		managedResourceSource = cached
		adapterManager = &managedAdapterManager{base: adapterManager, source: cached, config: managedConfig, now: time.Now}
		logger.Info("managed resource discovery enabled", "allowlist_entries", len(managedConfig.Allowlist), "access", "read-only", "cloud_api_access", false)
	}

	var aiAdvisor httpapi.AIAdvisor
	if os.Getenv("KUBEATHRIX_AI_ENABLED") == "true" {
		advisor, err := ai.NewOpenAICompatibleAdvisor(ai.Config{
			Enabled:                 true,
			Provider:                envOrDefault("KUBEATHRIX_AI_PROVIDER", "openai-compatible"),
			Endpoint:                envOrDefault("KUBEATHRIX_AI_ENDPOINT", "https://api.openai.com/v1/chat/completions"),
			Model:                   os.Getenv("KUBEATHRIX_AI_MODEL"),
			APIKey:                  os.Getenv("KUBEATHRIX_AI_API_KEY"),
			Timeout:                 durationEnv("KUBEATHRIX_AI_TIMEOUT", 20*time.Second),
			AllowInsecureHTTP:       boolEnv("KUBEATHRIX_AI_ALLOW_INSECURE_HTTP", false),
			EndpointHostAllowlist:   csvEnv("KUBEATHRIX_AI_ENDPOINT_HOST_ALLOWLIST"),
			ExcludedSources:         csvEnv("KUBEATHRIX_AI_EXCLUDED_SOURCES"),
			ExcludedNamespaces:      csvEnv("KUBEATHRIX_AI_EXCLUDED_NAMESPACES"),
			MaxInputBytes:           intEnv("KUBEATHRIX_AI_MAX_INPUT_BYTES", 64<<10),
			MaxOutputTokens:         intEnv("KUBEATHRIX_AI_MAX_OUTPUT_TOKENS", 700),
			CircuitBreakerThreshold: intEnv("KUBEATHRIX_AI_CIRCUIT_BREAKER_THRESHOLD", 3),
			CircuitBreakerCooldown:  durationEnv("KUBEATHRIX_AI_CIRCUIT_BREAKER_COOLDOWN", 30*time.Second),
		}, nil)
		if err != nil {
			logger.Warn("ai decision support disabled", "error", err)
		} else {
			aiAdvisor = advisor
			logger.Info("ai decision support enabled", "provider", envOrDefault("KUBEATHRIX_AI_PROVIDER", "openai-compatible"), "model", os.Getenv("KUBEATHRIX_AI_MODEL"))
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

	var providerSecrets httpapi.ProviderSecretWriter
	if boolEnv("KUBEATHRIX_PROVIDER_SECRET_MANAGEMENT", true) {
		secretStore, err := cluster.NewProviderSecretStore()
		if err != nil {
			logger.Warn("provider secret management disabled", "error", err)
		} else {
			providerSecrets = secretStore
		}
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
		ServiceVersion: "0.3.0", // x-release-please-version
	})
	if err != nil {
		logger.Error("OpenTelemetry tracing configuration failed closed", "error", err)
		os.Exit(1)
	}

	clusterID := envOrDefault("KUBEATHRIX_CLUSTER_ID", "default")
	server := httpapi.NewServer(repository, httpapi.Config{
		InsecureDevAuth:      insecureDevAuth,
		OIDCIssuerURL:        os.Getenv("OIDC_ISSUER_URL"),
		OIDCClientID:         os.Getenv("OIDC_CLIENT_ID"),
		Authenticator:        authenticator,
		ClusterID:            clusterID,
		MaxRequestBytes:      int64Env("KUBEATHRIX_MAX_REQUEST_BYTES", 1<<20),
		RateLimitPerMinute:   intEnv("KUBEATHRIX_RATE_LIMIT_PER_MINUTE", 120),
		Logger:               logger,
		ClusterInspector:     clusterInspector,
		ChaosManager:         chaosManager,
		WorkflowClient:       workflowClient,
		AllowMemoryWorkflows: allowMemoryWorkflows,
		AdapterManager:       adapterManager,
		ManagedResources:     managedResourceSource,
		AIAdvisor:            aiAdvisor,
		ProviderSecrets:      providerSecrets,
		ProviderSecretNS:     envOrDefault("POD_NAMESPACE", "kubeathrix"),
		AutonomyMode:         envOrDefault("KUBEATHRIX_AUTONOMY_MODE", "recommend"),
		RuntimeIdentity:      envOrDefault("KUBEATHRIX_RUNTIME_IDENTITY", "api/"+clusterID),
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
	if os.Getenv("KUBEATHRIX_AI_AGENT_ENABLED") == "true" {
		if aiAdvisor == nil {
			logger.Error("ai agent requires ai.enabled=true with a valid model and API key")
			os.Exit(1)
		}
		aiAgent, err := agent.New(agent.Config{
			Enabled:             true,
			Actor:               envOrDefault("KUBEATHRIX_AI_AGENT_ACTOR", agent.DefaultActor),
			Interval:            durationEnv("KUBEATHRIX_AI_AGENT_INTERVAL", time.Minute),
			MinRiskScore:        intEnv("KUBEATHRIX_AI_AGENT_MIN_RISK_SCORE", 60),
			MaxFindingsPerCycle: intEnv("KUBEATHRIX_AI_AGENT_MAX_FINDINGS_PER_CYCLE", 10),
			AutoPlan:            boolEnv("KUBEATHRIX_AI_AGENT_AUTO_PLAN", true),
			AutoExecuteTierA:    boolEnv("KUBEATHRIX_AI_AGENT_AUTO_EXECUTE_TIER_A", false),
			NotificationTimeout: durationEnv("KUBEATHRIX_AI_AGENT_NOTIFICATION_TIMEOUT", 5*time.Second),
			NotificationWebhook: os.Getenv("KUBEATHRIX_NOTIFICATION_WEBHOOK_URL"),
		}, agent.Dependencies{
			Repository:     repository,
			Advisor:        aiAdvisor,
			WorkflowClient: workflowClient,
			SnapshotSource: clusterInspector,
			AdapterManager: adapterManager,
			Logger:         logger,
		})
		if err != nil {
			logger.Error("failed to initialize ai agent", "error", err)
			os.Exit(1)
		}
		aiAgent.Start(stopContext)
	}
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

func boolEnv(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return strings.EqualFold(value, "true") || value == "1" || strings.EqualFold(value, "yes")
}

func csvEnv(name string) []string {
	values := strings.Split(os.Getenv(name), ",")
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
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
		integrationFromEnv("OpenAI Agent", "ai", "KUBEATHRIX_AI_AGENT_ENABLED"),
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

type managedResourceDiscoverer interface {
	Discover(ctx context.Context) (managedresources.Snapshot, error)
}

type managedResourceCache struct {
	source managedResourceDiscoverer
	now    func() time.Time
	ttl    time.Duration

	mu       sync.Mutex
	snapshot managedresources.Snapshot
	cachedAt time.Time
	inflight chan struct{}
}

func (c *managedResourceCache) Discover(ctx context.Context) (managedresources.Snapshot, error) {
	for {
		c.mu.Lock()
		if !c.cachedAt.IsZero() && c.now().Sub(c.cachedAt) < c.ttl {
			snapshot := cloneManagedSnapshot(c.snapshot)
			c.mu.Unlock()
			return snapshot, nil
		}
		if c.inflight != nil {
			inflight := c.inflight
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return managedresources.Snapshot{}, ctx.Err()
			case <-inflight:
				continue
			}
		}
		c.inflight = make(chan struct{})
		c.mu.Unlock()
		break
	}
	snapshot, err := c.source.Discover(ctx)
	c.mu.Lock()
	if err == nil {
		c.snapshot = cloneManagedSnapshot(snapshot)
		c.cachedAt = c.now()
	} else if !c.cachedAt.IsZero() {
		snapshot = cloneManagedSnapshot(c.snapshot)
		snapshot.Warnings = append(snapshot.Warnings, managedresources.Warning{
			APIGroup: "kubeathrix.io", Version: "v1", Resource: "managedresources",
			Code: "stale_snapshot", Message: "The latest refresh failed; this is the last successful bounded snapshot.",
		})
		c.snapshot = cloneManagedSnapshot(snapshot)
		c.cachedAt = c.now()
		err = nil
	}
	close(c.inflight)
	c.inflight = nil
	c.mu.Unlock()
	return snapshot, err
}

func cloneManagedSnapshot(snapshot managedresources.Snapshot) managedresources.Snapshot {
	clone := snapshot
	clone.Resources = append([]managedresources.Resource(nil), snapshot.Resources...)
	clone.Relationships = append([]managedresources.Relationship(nil), snapshot.Relationships...)
	clone.Findings = append([]core.Finding(nil), snapshot.Findings...)
	clone.Warnings = append([]managedresources.Warning(nil), snapshot.Warnings...)
	return clone
}

type managedAdapterManager struct {
	base   httpapi.AdapterManager
	source managedResourceDiscoverer
	config managedresources.Config
	now    func() time.Time
}

func (m *managedAdapterManager) Collect(ctx context.Context) adapters.Collection {
	collection := adapters.Collection{}
	if m.base != nil {
		collection = m.base.Collect(ctx)
	}
	snapshot, err := m.source.Discover(ctx)
	status, health := "online", "healthy"
	setupGaps := make([]string, 0, len(snapshot.Warnings))
	errorState := ""
	if err != nil {
		status, health = "error", "unhealthy"
		errorState = err.Error()
		setupGaps = append(setupGaps, "Inspect the Kubernetes API connection and the exact managed-resource allowlist.")
	} else if len(snapshot.Warnings) > 0 {
		status, health = "degraded", "degraded"
		for _, warning := range snapshot.Warnings {
			setupGaps = append(setupGaps, warning.APIGroup+"/"+warning.Version+" "+warning.Resource+": "+warning.Message)
		}
	}
	versions, permissions := managedResourceCapabilities(m.config)
	lastSeen := "never"
	if !snapshot.ObservedAt.IsZero() {
		lastSeen = snapshot.ObservedAt.UTC().Format(time.RFC3339)
	}
	const integrationName = "Kubernetes-managed external resources"
	collection.Integrations = append(collection.Integrations, core.Integration{Name: integrationName, Type: "managed-resource", Enabled: true, Status: status})
	collection.Health = append(collection.Health, core.IntegrationHealth{
		Name: integrationName, Type: "managed-resource", Enabled: true, Status: status, Health: health,
		DataLastSeen: lastSeen, Permissions: permissions, SupportedVersions: versions, SetupGaps: setupGaps,
		ErrorState: errorState, FindingsCount: len(snapshot.Findings), CheckedAt: m.now().UTC(),
	})
	seen := make(map[string]struct{}, len(collection.Findings)+len(snapshot.Findings))
	for _, finding := range collection.Findings {
		seen[finding.ID] = struct{}{}
	}
	for _, finding := range snapshot.Findings {
		if _, exists := seen[finding.ID]; exists {
			continue
		}
		seen[finding.ID] = struct{}{}
		collection.Findings = append(collection.Findings, finding)
	}
	sort.Slice(collection.Integrations, func(i, j int) bool { return collection.Integrations[i].Name < collection.Integrations[j].Name })
	sort.Slice(collection.Health, func(i, j int) bool { return collection.Health[i].Name < collection.Health[j].Name })
	sort.Slice(collection.Findings, func(i, j int) bool {
		if collection.Findings[i].RiskScore == collection.Findings[j].RiskScore {
			return collection.Findings[i].ID < collection.Findings[j].ID
		}
		return collection.Findings[i].RiskScore > collection.Findings[j].RiskScore
	})
	return collection
}

func managedResourceCapabilities(config managedresources.Config) ([]string, []string) {
	versions := make([]string, 0, len(config.Allowlist))
	permissions := []string{}
	for _, entry := range config.Allowlist {
		versions = append(versions, entry.APIGroup+"/"+entry.Version)
		for _, resource := range entry.Resources {
			permissions = append(permissions, "list "+entry.APIGroup+"/"+entry.Version+" "+resource)
		}
	}
	return versions, permissions
}
