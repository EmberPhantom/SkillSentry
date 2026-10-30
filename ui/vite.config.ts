import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard talks to the SkillSentry server on the same origin in production.
// In development, Vite forwards API paths to a running `skillsentry serve`.
const API = process.env.SKILLSENTRY_API ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      "/scans": API,
      "/scan": { target: API, ws: true },
      "/skills": API,
      "/cache": API,
      "/health": API,
      "/meta": API,
    },
  },
});
