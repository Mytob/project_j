const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  testMatch: '*.spec.js',
  workers: 1,
  timeout: 30000,
  expect: { timeout: 5000 },
  projects: [
    { name: 'firefox-admin-smoke', testMatch: 'admin-smoke.spec.js', use: { browserName: 'firefox' } },
    { name: 'webkit-admin-smoke', testMatch: 'admin-smoke.spec.js', use: { browserName: 'webkit' } },
    { name: 'chromium', use: { browserName: 'chromium' } },
  ],
  use: { baseURL: process.env.BASE_URL || 'https://admin.domain.test', ignoreHTTPSErrors: true },
});
