.PHONY: test build helm-lint api operator console

test:
	go test ./services/api/... ./operator/...
	pnpm -r test

build: api operator console

api:
	cd services/api && go build ./cmd/kubeathrix-api

operator:
	cd operator && go build ./cmd/manager

console:
	pnpm --filter @kubeathrix/console build

helm-lint:
	helm lint charts/kubeathrix
