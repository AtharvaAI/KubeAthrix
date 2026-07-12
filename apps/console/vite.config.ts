import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.KUBEATHRIX_API_PROXY ?? "http://127.0.0.1:8080",
        changeOrigin: true
      },
      "/auth": {
        target: process.env.KUBEATHRIX_API_PROXY ?? "http://127.0.0.1:8080",
        changeOrigin: true
      }
    }
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    globals: true,
    exclude: ["tests/**", "node_modules/**", "dist/**"]
  }
});
