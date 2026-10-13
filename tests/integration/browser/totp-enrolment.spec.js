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

test('administrator can reauthenticate, cancel and complete rendered TOTP enrollment', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Jellyfin Proxy' })).toBeVisible();
  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole('heading', { name: 'Administrator authenticator' })).toBeVisible();

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
});
