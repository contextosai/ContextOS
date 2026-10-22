/// <reference types="vitest/config" />
import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` serves the UI with hot reload and proxies the API to a local towerd
// (TOWER_URL, default http://127.0.0.1:8090), so the browser still talks to one origin.
// `npm run build` writes dist/ for towerd's `[tower] dir`.
export default defineConfig(({ mode }) => {
  const target = loadEnv(mode, ".", "").TOWER_URL || "http://127.0.0.1:8090";
  return {
  base: "/tower/",
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false, assetsInlineLimit: 0, chunkSizeWarningLimit: 900 },
  server: {
    proxy: {
      "/api": { target },
      "/healthz": { target },
    },
  },
  test: { environment: "node", include: ["src/**/*.test.ts"] },
  };
});
