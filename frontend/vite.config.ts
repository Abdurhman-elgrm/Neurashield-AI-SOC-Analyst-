import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    host: true,
    proxy: {
      // WS proxy must be listed before /api so it matches first
      "/api/v1/ws": {
        target: process.env.VITE_WS_URL || "ws://localhost:8000",
        ws: true,
        changeOrigin: true,
      },
      "/api": {
        target: process.env.VITE_API_URL || "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          if (id.includes("node_modules")) {
            if (
              id.includes("/react/") ||
              id.includes("/react-dom/") ||
              id.includes("/react-router-dom/") ||
              id.includes("/react-router/")
            ) return "vendor";
            if (id.includes("/@tanstack/react-query")) return "query";
            if (
              id.includes("/@tanstack/react-table") ||
              id.includes("/@tanstack/react-virtual")
            ) return "table";
            if (id.includes("/framer-motion/")) return "motion";
          }
        },
      },
    },
  },
});
