import { defineConfig } from "@playwright/test";

export default defineConfig({
  testMatch: "journey.mjs",
  workers: 1,
  timeout: 60000,
  reporter: [
    ["list"],
    ["json", { outputFile: "../../build/browser-journey.json" }],
  ],
  outputDir: "../../build/browser-results",
});
