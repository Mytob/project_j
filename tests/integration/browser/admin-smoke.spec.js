const { test, expect } = require('@playwright/test');

const baseURL = process.env.BASE_URL || 'https://admin.domain.test';
const pages = [
  ['/dashboard', 'Overview'],
  ['/statistics', 'Statistics'],
  ['/health', 'Health'],
  ['/access-control', 'Access control'],
  ['/wireguard', 'WireGuard'],
  ['/security', 'Security'],
];

test('admin navigation and charts work in desktop and mobile-sized browser layouts', async ({ page, browser, browserName }, testInfo) => {
  test.setTimeout(90000);
  await page.goto('/');
  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);

  for (const width of [320, 390, 768, 1024, 1440, 1920, 2560]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth), `no horizontal page overflow at ${width}px`).toBeLessThanOrEqual(width);
  }

  await page.setViewportSize({ width: 1440, height: 900 });
  for (const [path, title] of pages) {
    await page.getByRole('link', { name: title, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`${path.replaceAll('/', '\\/')}$`));
    await expect(page.getByRole('heading', { name: title, exact: true })).toBeVisible();
  }

  await page.getByRole('link', { name: 'Statistics', exact: true }).click();
  const cpuChart = page.locator('.chart-panel').filter({ has: page.getByRole('heading', { name: 'CPU usage', exact: true }) });
  const slider = cpuChart.getByRole('slider', { name: 'CPU usage chart sample' });
  await expect.poll(async () => slider.count(), { timeout: 30000 }).toBe(1);
  await expect(slider).toBeVisible();
  await expect.poll(async () => Number(await slider.getAttribute('max')), { timeout: 30000 }).toBeGreaterThan(0);
  const plot = cpuChart.locator('svg.chart');
  await plot.click({ position: { x: 2, y: 20 } });
  expect(Number(await slider.inputValue())).toBe(0);
  await slider.focus();
  await slider.press('ArrowRight');
  expect(Number(await slider.inputValue())).toBe(1);
  await expect(cpuChart.locator('.chart-output')).toContainText('·');

  const mobileOptions = {
    baseURL,
    ignoreHTTPSErrors: true,
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 2,
    hasTouch: true,
    isMobile: browserName !== 'firefox',
  };
  const mobileContext = await browser.newContext(mobileOptions);
  const mobilePage = await mobileContext.newPage();
  await mobilePage.goto('/');
  await mobilePage.getByLabel('Password').fill('integration-test-admin-password');
  if (browserName === 'firefox') await mobilePage.getByRole('button', { name: 'Sign in' }).click();
  else await mobilePage.getByRole('button', { name: 'Sign in' }).tap();
  await expect(mobilePage).toHaveURL(/\/dashboard$/);

  for (const [path, title] of pages.slice(1)) {
    const menu = mobilePage.getByRole('button', { name: 'Toggle navigation' });
    if (browserName === 'firefox') await menu.click();
    else await menu.tap();
    const link = mobilePage.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: title, exact: true });
    await expect(link).toBeVisible();
    if (browserName === 'firefox') await link.click();
    else await link.tap();
    await expect(mobilePage).toHaveURL(new RegExp(`${path.replaceAll('/', '\\/')}$`));
    await expect(mobilePage.getByRole('heading', { name: title, exact: true })).toBeVisible();
    expect(await mobilePage.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  }
  await mobileContext.close();

  await page.setViewportSize({ width: 844, height: 390 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(844);
  await testInfo.attach('browser-engine', { body: browserName, contentType: 'text/plain' });
});
