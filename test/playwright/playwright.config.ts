import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  retries: 0,
  use: {
    baseURL: process.env.CADDY_URL || "http://localhost:18080",
    // No JavaScript disabled — we need JS to solve the PoW.
    javaScriptEnabled: true,
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
    },
  ],
});
