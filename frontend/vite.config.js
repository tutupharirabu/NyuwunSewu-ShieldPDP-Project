import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";
import { defineConfig, loadEnv } from "vite";
export default defineConfig(function (_a) {
  var mode = _a.mode;
  var env = loadEnv(mode, process.cwd(), "");
  var backend = env.VITE_PROXY_TARGET || "http://127.0.0.1:8000";
  return {
    plugins: [react()],
    resolve: {
      alias: {
        "@": fileURLToPath(new URL("./src", import.meta.url)),
      },
    },
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: backend,
          changeOrigin: true,
          rewrite: function (path) {
            return path.replace(/^\/api/, "");
          },
        },
      },
    },
    build: {
      rollupOptions: {
        output: {
          manualChunks: {
            react: ["react", "react-dom", "react-router-dom"],
            charts: ["recharts"],
            icons: ["lucide-react"],
          },
        },
      },
    },
  };
});
