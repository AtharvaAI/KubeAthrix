package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/httpapi"
	"github.com/atharvaai/kubeathrix/services/api/internal/postgres"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var repository store.Repository = store.NewMemoryStore(store.WithDemoData())
	if databaseURL := os.Getenv("DATABASE_URL"); databaseURL != "" {
		pgStore, err := postgres.New(ctx, databaseURL, repository)
		if err != nil {
			logger.Error("failed to initialize postgres adapter", "error", err)
			os.Exit(1)
		}
		defer pgStore.Close()
		repository = pgStore
	}

	server := httpapi.NewServer(repository, httpapi.Config{
		DevAuthEnabled: os.Getenv("KUBEATHRIX_DEV_AUTH") != "false",
		OIDCIssuerURL:  os.Getenv("OIDC_ISSUER_URL"),
		OIDCClientID:   os.Getenv("OIDC_CLIENT_ID"),
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
