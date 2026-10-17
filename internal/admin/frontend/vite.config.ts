import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/app-assets/",
  build: { outDir: "dist", emptyOutDir: false, sourcemap: false },
  test: { environment: "node", restoreMocks: true, clearMocks: true },
});
