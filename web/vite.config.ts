import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true, chunkSizeWarningLimit: 1800 },
  server: { proxy: { "/api": {target: "http://127.0.0.1:8080", headers:{host:"admin.localhost",origin:"http://admin.localhost"}} } },
});
