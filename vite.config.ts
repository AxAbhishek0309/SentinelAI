import { defineConfig } from "@lovable.dev/vite-tanstack-config";

export default defineConfig({
  tanstackStart: {
    server: { entry: "server" },
  },
  vite: {
    server: {
      proxy: {
        // Forward all /api calls to the FastAPI backend.
        // This means VITE_API_URL can stay as empty string and
        // EventSource("/api/scans/...") works without any CORS issues.
        "/api": {
          target: "http://localhost:8000",
          changeOrigin: true,
          // SSE needs these headers to stay streaming
          headers: {
            Connection: "keep-alive",
          },
        },
      },
    },
  },
});
