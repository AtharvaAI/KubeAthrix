import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repository = resolve(here, "../../..");
for (let attempt = 0; attempt < 60; attempt++) {
  try {
    const response = await fetch("http://127.0.0.1:41740/health");
    if (response.ok) break;
  } catch {
    // The fixture and API web servers are started concurrently by Playwright.
  }
  await new Promise((resolveWait) => setTimeout(resolveWait, 250));
}

const child = spawn("go", ["run", "./services/api/cmd/kubeathrix-api"], {
  cwd: repository,
  env: {
    ...process.env,
    PORT: "41741",
    OIDC_ISSUER_URL: "http://127.0.0.1:41740",
    OIDC_CLIENT_ID: "kubeathrix",
    KUBEATHRIX_CLUSTER_ID: "e2e",
    KUBEATHRIX_CLUSTER_INSPECTOR: "false",
    KUBEATHRIX_ADAPTERS_ENABLED: "false",
    KUBEATHRIX_INSECURE_MEMORY_WORKFLOWS: "true",
    KUBEATHRIX_INSECURE_DEV_AUTH: "false"
  },
  stdio: "inherit",
  shell: false
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal));
}
child.on("exit", (code) => process.exit(code ?? 1));
