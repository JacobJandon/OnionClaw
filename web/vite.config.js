import { defineConfig } from "vite";

// OnionClaw site (Peel). base "./" makes every asset path relative, so the built
// site works whether it is served from a domain root or a subdirectory.
export default defineConfig({
  base: "./",
  build: { target: "es2020", assetsInlineLimit: 2048 },
});
