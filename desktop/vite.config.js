import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// base: "./" so the packaged build loads assets via relative paths from file://
export default defineConfig({
  plugins: [react()],
  base: "./",
  server: { port: 5173, strictPort: true },
  build: { outDir: "dist", emptyOutDir: true },
});
