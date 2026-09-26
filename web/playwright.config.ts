import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "e2e",
  workers: 1,
  fullyParallel: false,
  timeout: 60000,
  retries: 0,
  use: {
    baseURL: "http://admin.localhost:18080",
    browserName: "chromium",
    viewport: { width: 1440, height: 1000 },
    trace: "retain-on-failure",
  },
  webServer: {
    command: "bash ../scripts/e2e-server.sh",
    url: "http://127.0.0.1:19090/livez",
    timeout: 60000,
    reuseExistingServer: false,
  },
  reporter: [["list"], ["html", { open: "never" }]],
});
