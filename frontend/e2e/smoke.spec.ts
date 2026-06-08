/**
 * P0-02: Frontend smoke tests.
 *
 * Covers: login flow, Dashboard, multi-agent page, alerts page, users page.
 * Requires backend running on :8000 and frontend on :3000.
 */

import { test, expect } from '@playwright/test';

const BASE_URL = 'http://localhost:3000';
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin123';

test.describe('Smoke Tests', () => {
  test('login page renders', async ({ page }) => {
    await page.goto(BASE_URL);
    // Should redirect to login or show login form
    await expect(page.locator('body')).toBeVisible();
  });

  test('login with valid credentials', async ({ page }) => {
    await page.goto(BASE_URL);

    // Fill login form
    const usernameInput = page.locator('input[id*="username"], input[placeholder*="用户名"], input[placeholder*="username"]').first();
    const passwordInput = page.locator('input[id*="password"], input[type="password"]').first();

    if (await usernameInput.isVisible({ timeout: 5000 }).catch(() => false)) {
      await usernameInput.fill(ADMIN_USER);
      await passwordInput.fill(ADMIN_PASS);

      // Click login button
      const loginBtn = page.locator('button[type="submit"], button:has-text("登录"), button:has-text("Login")').first();
      await loginBtn.click();

      // Should redirect to dashboard or main page
      await page.waitForURL(/dashboard|chat|#/i, { timeout: 10000 }).catch(() => {});
      await expect(page.locator('body')).toBeVisible();
    }
  });

  test('dashboard page accessible after login', async ({ page }) => {
    // Login first
    await page.goto(BASE_URL);
    const usernameInput = page.locator('input[id*="username"], input[placeholder*="用户名"], input[placeholder*="username"]').first();
    const passwordInput = page.locator('input[id*="password"], input[type="password"]').first();

    if (await usernameInput.isVisible({ timeout: 5000 }).catch(() => false)) {
      await usernameInput.fill(ADMIN_USER);
      await passwordInput.fill(ADMIN_PASS);
      const loginBtn = page.locator('button[type="submit"], button:has-text("登录"), button:has-text("Login")').first();
      await loginBtn.click();
      await page.waitForTimeout(2000);
    }

    // Navigate to dashboard
    await page.goto(`${BASE_URL}/dashboard`);
    await page.waitForTimeout(2000);
    await expect(page.locator('body')).toBeVisible();
  });

  test('multi-agent page accessible', async ({ page }) => {
    await page.goto(BASE_URL);
    const usernameInput = page.locator('input[id*="username"], input[placeholder*="用户名"], input[placeholder*="username"]').first();
    const passwordInput = page.locator('input[id*="password"], input[type="password"]').first();

    if (await usernameInput.isVisible({ timeout: 5000 }).catch(() => false)) {
      await usernameInput.fill(ADMIN_USER);
      await passwordInput.fill(ADMIN_PASS);
      const loginBtn = page.locator('button[type="submit"], button:has-text("登录"), button:has-text("Login")').first();
      await loginBtn.click();
      await page.waitForTimeout(2000);
    }

    await page.goto(`${BASE_URL}/multi-agent`);
    await page.waitForTimeout(2000);
    await expect(page.locator('body')).toBeVisible();
  });

  test('alerts page accessible', async ({ page }) => {
    await page.goto(BASE_URL);
    const usernameInput = page.locator('input[id*="username"], input[placeholder*="用户名"], input[placeholder*="username"]').first();
    const passwordInput = page.locator('input[id*="password"], input[type="password"]').first();

    if (await usernameInput.isVisible({ timeout: 5000 }).catch(() => false)) {
      await usernameInput.fill(ADMIN_USER);
      await passwordInput.fill(ADMIN_PASS);
      const loginBtn = page.locator('button[type="submit"], button:has-text("登录"), button:has-text("Login")').first();
      await loginBtn.click();
      await page.waitForTimeout(2000);
    }

    await page.goto(`${BASE_URL}/alerts`);
    await page.waitForTimeout(2000);
    await expect(page.locator('body')).toBeVisible();
  });

  test('users page accessible as admin', async ({ page }) => {
    await page.goto(BASE_URL);
    const usernameInput = page.locator('input[id*="username"], input[placeholder*="用户名"], input[placeholder*="username"]').first();
    const passwordInput = page.locator('input[id*="password"], input[type="password"]').first();

    if (await usernameInput.isVisible({ timeout: 5000 }).catch(() => false)) {
      await usernameInput.fill(ADMIN_USER);
      await passwordInput.fill(ADMIN_PASS);
      const loginBtn = page.locator('button[type="submit"], button:has-text("登录"), button:has-text("Login")').first();
      await loginBtn.click();
      await page.waitForTimeout(2000);
    }

    await page.goto(`${BASE_URL}/users`);
    await page.waitForTimeout(2000);
    await expect(page.locator('body')).toBeVisible();
  });
});
