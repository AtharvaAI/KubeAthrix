package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/cluster"
	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/httpapi"
	"github.com/atharvaai/kubeathrix/services/api/internal/postgres"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var repository store.Repository = store.NewMemoryStore(store.WithIntegrations(integrationsFromEnv()))
	if databaseURL := os.Getenv("DATABASE_URL"); databaseURL != "" {
		pgStore, err := postgres.New(ctx, databaseURL, repository)
		if err != nil {
			logger.Error("failed to initialize postgres adapter", "error", err)
			os.Exit(1)
		}
		defer pgStore.Close()
		repository = pgStore
	}

	var clusterInspector httpapi.ClusterInspector
	if os.Getenv("KUBEATHRIX_CLUSTER_INSPECTOR") != "false" {
		inspector, err := cluster.NewInspector()
		if err != nil {
			logger.Warn("cluster inspector disabled", "error", err)
		} else {
			clusterInspector = inspector
		}
	}

	var chaosRunner httpapi.ChaosRunner
	if os.Getenv("KUBEATHRIX_CHAOS_EXECUTION") == "true" {
		runner, err := cluster.NewChaosRunner()
		if err != nil {
			logger.Warn("chaos execution disabled", "error", err)
		} else {
			chaosRunner = runner
		}
	}

	server := httpapi.NewServer(repository, httpapi.Config{
		DevAuthEnabled:   os.Getenv("KUBEATHRIX_DEV_AUTH") != "false",
		OIDCIssuerURL:    os.Getenv("OIDC_ISSUER_URL"),
		OIDCClientID:     os.Getenv("OIDC_CLIENT_ID"),
		ClusterInspector: clusterInspector,
		ChaosRunner:      chaosRunner,
	})

	addr := ":8080"
	if fromEnv := os.Getenv("PORT"); fromEnv != "" {
		addr = ":" + fromEnv
	}

	logger.Info("starting kubeathrix api", "addr", addr)
	if err := http.ListenAndServe(addr, server.Routes()); err != nil {
		logger.Error("api server stopped", "error", err)
		os.Exit(1)
	}
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
