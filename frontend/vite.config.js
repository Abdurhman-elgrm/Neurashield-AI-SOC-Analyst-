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
            "/api": {
                target: process.env.VITE_API_URL || "http://localhost:8000",
                changeOrigin: true,
            },
            "/ws": {
                target: process.env.VITE_WS_URL || "ws://localhost:8000",
                ws: true,
                changeOrigin: true,
            },
        },
    },
    build: {
        sourcemap: true,
        rollupOptions: {
            output: {
                manualChunks: {
                    vendor: ["react", "react-dom", "react-router-dom"],
                    query: ["@tanstack/react-query"],
                    table: ["@tanstack/react-table", "@tanstack/react-virtual"],
                    motion: ["framer-motion"],
                },
            },
        },
    },
});
