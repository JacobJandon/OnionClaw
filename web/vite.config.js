import { resolve } from "node:path";
import { defineConfig } from "vite";

// The OnionClaw site (Peel) and the Peel × Planet hybrid, one build.
export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        peel: resolve(import.meta.dirname, "index.html"),
        hybrid: resolve(import.meta.dirname, "hybrid/index.html"),
      },
    },
  },
});
