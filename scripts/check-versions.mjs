import { readFileSync } from "node:fs";

const rootPackage = JSON.parse(readFileSync("package.json", "utf8"));
const consolePackage = JSON.parse(readFileSync("apps/console/package.json", "utf8"));
const releaseManifest = JSON.parse(readFileSync(".release-please-manifest.json", "utf8"));
const version = rootPackage.version;
const checks = [
  ["console package", version, consolePackage.version],
  ["release manifest", version, releaseManifest["."]],
  ["Helm chart", version, match("charts/kubeathrix/Chart.yaml", /^version:\s*([^\s]+)$/m)],
  ["Helm appVersion", version, match("charts/kubeathrix/Chart.yaml", /^appVersion:\s*([^\s]+)$/m)],
  ["Helm API image tag", `api-${version}`, imageValue("api", "tag")],
  ["Helm API pull policy", "IfNotPresent", imageValue("api", "pullPolicy")],
  ["Helm console image tag", `console-${version}`, imageValue("console", "tag")],
  ["Helm console pull policy", "IfNotPresent", imageValue("console", "pullPolicy")],
  ["Helm operator image tag", `operator-${version}`, imageValue("operator", "tag")],
  ["Helm operator pull policy", "IfNotPresent", imageValue("operator", "pullPolicy")],
  ["OpenAPI", version, match("services/api/openapi.yaml", /^\s{2}version:\s*([^\s]+)$/m)],
	["API metrics", version, match("services/api/internal/httpapi/metrics.go", /kubeathrix_api_build_info\{version="([^"]+)/)],
	["API telemetry", version, match("services/api/cmd/kubeathrix-api/main.go", /ServiceVersion:\s*"([^"]+)/)],
];

const failures = checks.filter(([, expected, actual]) => actual !== expected);
if (failures.length) {
  for (const [name, expected, actual] of failures) console.error(`${name}: expected ${expected}, got ${actual}`);
  process.exit(1);
}
console.log(`All release surfaces use ${version}; Helm defaults use the matching release images`);

function match(path, expression) {
  return expression.exec(readFileSync(path, "utf8"))?.[1]?.replaceAll('"', "") ?? "missing";
}

function imageValue(component, key) {
  const values = readFileSync("charts/kubeathrix/values.yaml", "utf8");
  const block = new RegExp(`^  ${component}:\\r?\\n((?:    .*\\r?\\n)+)`, "m").exec(values)?.[1] ?? "";
  return new RegExp(`^    ${key}:\\s*["']?([^"'#\\s]+)`, "m").exec(block)?.[1] ?? "missing";
}
