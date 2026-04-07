import { defineConfig } from "vitest/config";

export default defineConfig({
  define: {
    __DEV__: true,
  },
  test: {
    globals: true,
    include: ["__tests__/**/*.test.ts"],
  },
  resolve: {
    alias: {
      "react-native-quick-crypto": "node:crypto",
    },
  },
});
