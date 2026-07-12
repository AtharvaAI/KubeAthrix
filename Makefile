.PHONY: test verify format vet build helm-lint api operator console

test:
	go test ./services/api/... ./operator/... ./pkg/actioncatalog/...
	pnpm -r test

format:
	gofmt -w services/api operator pkg/actioncatalog

vet:
	go vet ./services/api/... ./operator/... ./pkg/actioncatalog/...

verify: vet test console helm-lint
	node scripts/check-versions.mjs
	npx --yes @redocly/cli@1.34.3 lint services/api/openapi.yaml
	node -e "require('node:fs').mkdirSync('tmp',{recursive:true})"
	helm template kubeathrix charts/kubeathrix -n kubeathrix --include-crds --set auth.insecureDevelopmentMode=true > tmp/kubeathrix-rendered.yaml

build: api operator console

api:
	cd services/api && go build ./cmd/kubeathrix-api

operator:
	cd operator && go build ./cmd/manager

console:
	pnpm --filter @kubeathrix/console build

helm-lint:
	helm lint charts/kubeathrix --set auth.insecureDevelopmentMode=true
