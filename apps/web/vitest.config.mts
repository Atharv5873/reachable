import path from "node:path";

import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
      // `server-only` throws outside a React Server Component bundle; under
      // Vitest (plain Node) the server modules are imported directly.
      "server-only": path.resolve(__dirname, "tests/server-only-stub.ts"),
    },
  },
  test: { include: ["src/**/*.test.ts", "tests/unit/**/*.test.ts"], environment: "node" },
});
