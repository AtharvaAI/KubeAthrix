import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  use: {
	baseURL: "http://127.0.0.1:41739",
    trace: "on-first-retry"
  },
  webServer: [
    {
      command: "node tests/oidc-fixture.mjs",
      url: "http://127.0.0.1:41740/health",
      reuseExistingServer: false,
      timeout: 60_000
    },
    {
      command: "node tests/start-api.mjs",
      url: "http://127.0.0.1:41741/health/ready",
      reuseExistingServer: false,
      timeout: 180_000
    },
    {
      command: "pnpm dev --port 41739",
      url: "http://127.0.0.1:41739",
      reuseExistingServer: false,
      timeout: 60_000,
      env: { KUBEATHRIX_API_PROXY: "http://127.0.0.1:41741" }
    }
  ],
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } }
  ]
});
