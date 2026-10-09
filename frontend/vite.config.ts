import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // The API runs separately; proxying keeps the browser on one origin so no
    // CORS preflight is needed during development.
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true },
      "/health": { target: "http://127.0.0.1:8000", changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    rollupOptions: {
      output: {
        // MapLibre and Cytoscape are each large and only one view needs each,
        // so splitting them keeps the initial payload to the shell.
        manualChunks: {
          maplibre: ["maplibre-gl"],
          cytoscape: ["cytoscape", "cytoscape-cose-bilkent"],
          react: ["react", "react-dom"],
        },
      },
    },
  },
});
