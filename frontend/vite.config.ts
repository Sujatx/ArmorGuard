import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig({
  plugins: [tailwindcss(), react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
      "@workspace/api-client-react": path.resolve(
        __dirname,
        "lib/api-client-react/src/index.ts"
      ),
    },
  },
  server: {
    port: 3000,
    host: "0.0.0.0",
    // Host file edits don't emit inotify events through a Windows/Docker bind mount,
    // so Vite's watcher misses them and serves stale modules. Polling fixes HMR.
    watch: { usePolling: true, interval: 300 },
  },
});
