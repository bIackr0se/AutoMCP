const { defineConfig } = require("@playwright/test");
module.exports = defineConfig({
  testDir: "./tests/browser",
  fullyParallel: true,
  workers: 2,
  use: { baseURL: "http://127.0.0.1:8767", trace: "retain-on-failure" },
  projects: [
    { name: "desktop", use: { viewport: { width: 1440, height: 1000 } } },
    { name: "phone", use: { viewport: { width: 390, height: 844 } } },
    {
      name: "narrow",
      use: { viewport: { width: 320, height: 740 }, reducedMotion: "reduce" },
    },
  ],
  webServer: {
    command: "python3 -m workbench --port 8767",
    url: "http://127.0.0.1:8767",
    reuseExistingServer: false,
  },
});
