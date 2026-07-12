import { readFileSync } from "node:fs";

const rootPackage = JSON.parse(readFileSync("package.json", "utf8"));
const consolePackage = JSON.parse(readFileSync("apps/console/package.json", "utf8"));
const version = rootPackage.version;
const checks = [
  ["console package", consolePackage.version],
  ["Helm chart", match("charts/kubeathrix/Chart.yaml", /^version:\s*([^\s]+)$/m)],
  ["Helm appVersion", match("charts/kubeathrix/Chart.yaml", /^appVersion:\s*([^\s]+)$/m)],
  ["OpenAPI", match("services/api/openapi.yaml", /^\s{2}version:\s*([^\s]+)$/m)],
	["API metrics", match("services/api/internal/httpapi/metrics.go", /kubeathrix_api_build_info\{version="([^"]+)/)],
	["API telemetry", match("services/api/cmd/kubeathrix-api/main.go", /ServiceVersion:\s*"([^"]+)/)],
];

const failures = checks.filter(([, actual]) => actual !== version);
if (failures.length) {
  for (const [name, actual] of failures) console.error(`${name}: expected ${version}, got ${actual}`);
  process.exit(1);
}
console.log(`All release surfaces use ${version}`);

function match(path, expression) {
  return expression.exec(readFileSync(path, "utf8"))?.[1]?.replaceAll('"', "") ?? "missing";
}
