const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  testMatch: 'totp-enrolment.spec.js',
  workers: 1,
  timeout: 30000,
  expect: { timeout: 5000 },
  use: {
    baseURL: process.env.BASE_URL || 'https://admin.domain.test',
    browserName: 'chromium',
    ignoreHTTPSErrors: true,
  },
});
