// Logs in to the Shopware administration and screenshots the Security alerts page.
// Usage: node screenshot.mjs <base-url> <user> <password> <out-dir>
import { chromium } from 'playwright';

const [base, user, password, out] = process.argv.slice(2);
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
page.on('pageerror', (e) => console.log('PAGE ERROR:', e.message));
page.on('console', (m) => ['error', 'warning'].includes(m.type()) && console.log('CONSOLE', m.type(), m.text().slice(0, 300)));
const go = async (hash) => { await page.evaluate((h) => { window.location.hash = h; }, hash); await page.waitForTimeout(2000); };

try {
    await page.goto(`${base}/admin`, { waitUntil: 'load' });
    await page.getByLabel('Username').fill(user);
    await page.locator('input[type="password"]').fill(password);
    await page.getByRole('button', { name: /log in/i }).click();
    await page.waitForURL(/#\/sw\/dashboard/, { timeout: 120000 });
    await page.locator('.sw-admin-menu').waitFor({ timeout: 120000 });
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(3000);

    await go('#/ruvelo/security/alerts/index');
    await page.getByText('Known vulnerabilities').first().waitFor({ timeout: 60000 });
    await page.getByText('not checked (not installed with Composer)').first().waitFor({ timeout: 30000 });
    await page.waitForTimeout(1500);
    await page.screenshot({ path: `${out}/admin-security-alerts.png` });

    // The settings entry that leads to it.
    await go('#/sw/settings/index/system');
    await page.getByText('Security alerts').first().waitFor({ timeout: 30000 });
    await page.waitForTimeout(1000);
    await page.screenshot({ path: `${out}/admin-settings-entry.png` });

    // Check now works from the page.
    await go('#/ruvelo/security/alerts/index');
    await page.getByRole('button', { name: 'Check now' }).click();
    await page.getByText('The check is done.').first().waitFor({ timeout: 120000 });
    console.log('Check now: done notification shown');
} catch (e) {
    console.log('FAILED:', e.message);
    console.log('URL', page.url(), 'BODY', (await page.locator('body').innerText()).slice(0, 1500));
    await page.screenshot({ path: `${out}/failure.png` });
    process.exitCode = 1;
} finally {
    await browser.close();
}
