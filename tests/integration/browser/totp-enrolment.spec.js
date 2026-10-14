const { test, expect } = require('@playwright/test');
const { createHmac } = require('node:crypto');

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function decodeBase32(value) {
  let bits = 0;
  let accumulator = 0;
  const bytes = [];
  for (const character of value.replace(/=+$/, '').toUpperCase()) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) throw new Error('Invalid Base32 setup secret');
    accumulator = (accumulator << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

function codeAt(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac('sha1', secret).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, '0');
}

function acceptedCodes(secret, step) {
  return new Set([step - 1, step, step + 1].filter((value) => value >= 0).map((value) => codeAt(secret, value)));
}

async function waitForStep(page, step) {
  while (Math.floor(Date.now() / 1000 / 30) < step) await page.waitForTimeout(100);
}

test('administrator can reauthenticate, cancel and complete rendered TOTP enrollment', async ({ page }) => {
  test.setTimeout(90000);
  const anonymousHistory = await page.request.get('/statistics/history?range=24h');
  expect(anonymousHistory.status()).toBe(401);
  const anonymousEvents = await page.request.get('/statistics/events');
  expect(anonymousEvents.status()).toBe(401);
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Jellyfin Proxy' })).toBeVisible();
  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole('heading', { name: 'Administrator authenticator' })).toBeVisible();
  const software = page.locator('section[aria-labelledby="software-heading"]');
  await expect(software.getByRole('heading', { name: 'Software' })).toBeVisible();
  await expect(software.getByText('Version: integration-test')).toBeVisible();
  await expect(software.getByText('Build number: browser-test')).toBeVisible();

  await page.getByLabel('Administrator password').fill('incorrect-password');
  const badPassword = page.waitForResponse((response) => response.url().endsWith('/totp/enroll/start') && response.status() === 401);
  await page.getByRole('button', { name: 'Set up authenticator' }).click();
  await badPassword;
  await expect(page.getByText('The password was not accepted.')).toBeVisible();

  await page.goto('/dashboard');
  await page.getByLabel('Administrator password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Set up authenticator' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  const qr = page.getByRole('img', { name: 'Authenticator setup QR code' });
  await expect(qr).toBeVisible();
  expect(await qr.evaluate((image) => image.complete && image.naturalWidth === 256)).toBeTruthy();

  const secretText = await page.locator('section[aria-labelledby="authenticator-heading"] code').textContent();
  const secret = decodeBase32(secretText.trim());
  const step = Math.floor(Date.now() / 1000 / 30);
  const accepted = acceptedCodes(secret, step);
  let incorrect = '000000';
  while (accepted.has(incorrect)) incorrect = String((Number(incorrect) + 1) % 1_000_000).padStart(6, '0');
  await page.getByLabel('Six-digit authenticator code').fill(incorrect);
  const rejected = page.waitForResponse((response) => response.url().endsWith('/totp/enroll/confirm') && response.status() === 400);
  await page.getByRole('button', { name: 'Verify and enable' }).click();
  await rejected;
  await expect(page.getByText('The authenticator code was not accepted.')).toBeVisible();

  await page.goto('/dashboard');
  await expect(page.getByRole('img', { name: 'Authenticator setup QR code' })).toBeVisible();
  await page.getByRole('button', { name: 'Cancel setup' }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByLabel('Password')).toBeVisible();

  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.getByLabel('Administrator password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Set up authenticator' }).click();
  await expect(page.getByRole('img', { name: 'Authenticator setup QR code' })).toBeVisible();
  const finalSecret = decodeBase32((await page.locator('section[aria-labelledby="authenticator-heading"] code').textContent()).trim());
  const currentStep = Math.floor(Date.now() / 1000 / 30);
  await page.getByLabel('Six-digit authenticator code').fill(codeAt(finalSecret, currentStep));
  await page.getByRole('button', { name: 'Verify and enable' }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByLabel('Password')).toBeVisible();
  await expect(page.getByLabel('Authenticator code')).toBeVisible();

  const loginStep = Math.floor(Date.now() / 1000 / 30);
  const acceptedLoginCodes = acceptedCodes(finalSecret, loginStep);
  let wrongLoginCode = '000000';
  while (acceptedLoginCodes.has(wrongLoginCode)) wrongLoginCode = String((Number(wrongLoginCode) + 1) % 1_000_000).padStart(6, '0');
  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByLabel('Authenticator code').fill(wrongLoginCode);
  const rejectedLogin = page.waitForResponse((response) => response.url().endsWith('/login') && response.status() === 401);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await rejectedLogin;
  await expect(page.getByRole('alert')).toContainText('password or authenticator code was not accepted');

  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByLabel('Authenticator code').fill(codeAt(finalSecret, loginStep + 1));
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByLabel('Authenticator code')).toBeVisible();
  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByLabel('Authenticator code').fill(codeAt(finalSecret, loginStep + 1));
  const rejectedReplay = page.waitForResponse((response) => response.url().endsWith('/login') && response.status() === 401);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await rejectedReplay;
  await expect(page.getByRole('alert')).toContainText('password or authenticator code was not accepted');

  await waitForStep(page, loginStep + 2);
  const disableLoginStep = Math.floor(Date.now() / 1000 / 30);
  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByLabel('Authenticator code').fill(codeAt(finalSecret, disableLoginStep));
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByText('Two-factor authentication is enabled for the administrator account.')).toBeVisible();
  await page.getByText('Disable two-factor authentication').click();
  await expect(page.getByLabel('Administrator password')).toBeVisible();
  await page.getByLabel('Administrator password').fill('integration-test-admin-password');
  const disableCodeStep = Math.max(Math.floor(Date.now() / 1000 / 30), disableLoginStep + 1);
  await page.getByLabel('Current six-digit authenticator code').fill(codeAt(finalSecret, disableCodeStep));
  await page.getByRole('button', { name: 'Disable authenticator' }).click();
  await expect(page).toHaveURL(/\?totp=disabled$/);
  await expect(page.getByText('Authenticator disabled. Sign in with your administrator password.')).toBeVisible();
  await expect(page.getByLabel('Authenticator code')).toHaveCount(0);

  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.getByRole('link', { name: 'Statistics' }).click();
  await expect(page).toHaveURL(/\/statistics$/);
  await expect(page.getByRole('heading', { name: 'VPS statistics' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Proxy statistics' })).toBeVisible();
  await expect(page.getByText('Blocked requests', { exact: true })).toBeVisible();
  await expect(page.getByText('HTTP allowlist denials')).toBeVisible();
  await expect(page.getByText('Active requests are not playback sessions.')).toBeVisible();
  await expect(page.locator('#host-memory')).not.toHaveText('—', { timeout: 15000 });
  await expect(page.locator('#proxy-active')).not.toHaveText('—', { timeout: 15000 });
  await expect(page.locator('#proxy-allowed')).not.toHaveText('0');
  await expect(page.locator('#proxy-blocked')).not.toHaveText('0');

  for (const range of ['24h', '7d', '30d', '90d']) {
    const response = await page.request.get(`/statistics/history?range=${range}`);
    expect(response.status()).toBe(200);
    expect(Array.isArray(await response.json())).toBeTruthy();
    await page.getByLabel('VPS statistics time range').selectOption(range);
    await page.getByLabel('Proxy statistics time range').selectOption(range);
  }
  await expect(page.locator('.history-chart').first()).toBeVisible();

  const accessOrigin = 'https://access.domain.test';
  const ranged = await page.request.get(`${accessOrigin}/__stream?bytes=128`, { headers: { Range: 'bytes=2-5' } });
  expect(ranged.status()).toBe(206);
  expect(ranged.headers()['content-range']).toBe('bytes 2-5/128');
  expect(Array.from(await ranged.body())).toEqual([2, 3, 4, 5]);

  const concurrent = [0, 1].map(() => page.request.get(`${accessOrigin}/__stream?bytes=1048576&slow=1`));
  await expect.poll(async () => Number((await page.locator('#proxy-active').textContent()).replaceAll(',', '')), { timeout: 10000 }).toBeGreaterThan(0);
  const streamed = await Promise.all(concurrent);
  for (const response of streamed) {
    expect(response.status()).toBe(200);
    expect((await response.body()).length).toBe(1048576);
  }
  await expect.poll(async () => Number((await page.locator('#proxy-active').textContent()).replaceAll(',', '')), { timeout: 10000 }).toBe(0);

  const websocketEcho = await page.evaluate((url) => new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    const timeout = setTimeout(() => { socket.close(); reject(new Error('WebSocket echo timed out')); }, 10000);
    socket.onopen = () => socket.send('streaming-proxy-check');
    socket.onmessage = (event) => { clearTimeout(timeout); socket.close(); resolve(event.data); };
    socket.onerror = () => { clearTimeout(timeout); reject(new Error('WebSocket proxy connection failed')); };
  }), 'wss://access.domain.test/__ws');
  expect(websocketEcho).toBe('streaming-proxy-check');

  await page.evaluate((url) => new Promise((resolve) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 300);
    fetch(url, { mode: 'no-cors', signal: controller.signal }).catch(() => {}).finally(() => { clearTimeout(timer); resolve(); });
  }), `${accessOrigin}/__stream?bytes=1048576&slow=1`);
  await expect.poll(async () => Number((await page.locator('#proxy-active').textContent()).replaceAll(',', '')), { timeout: 10000 }).toBe(0);

  let abortedConnections = 0;
  await page.route('**/statistics/events', (route) => {
    if (abortedConnections++ === 0) return route.abort();
    return route.continue();
  });
  await page.reload();
  await expect(page.locator('#connection-label')).toHaveText('Reconnecting');
  await expect(page.locator('#connection-label')).toHaveText('Live', { timeout: 15000 });
  await page.unroute('**/statistics/events');

  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();

  for (const width of [1440, 768, 390]) {
    await page.setViewportSize({ width, height: 900 });
    const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(pageWidth, `page must not overflow at ${width}px`).toBeLessThanOrEqual(width);
  }
});
