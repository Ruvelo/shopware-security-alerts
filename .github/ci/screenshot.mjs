// Logs in to the Shopware administration and screenshots the Security alerts page.
// Usage: node screenshot.mjs <base-url> <user> <password> <out-dir>
import { chromium } from 'playwright';

const [base, user, password, out] = process.argv.slice(2);
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
page.on('pageerror', (e) => console.log('PAGE ERROR:', e.message));

try {
    await page.goto(`${base}/admin`, { waitUntil: 'load' });
    await page.getByLabel('Username').fill(user);
    await page.getByLabel('Password').fill(password);
    await page.getByRole('button', { name: /log in/i }).click();
    await page.waitForURL(/#\/sw\/dashboard/, { timeout: 120000 });

    await page.goto(`${base}/admin#/ruvelo/security/alerts/index`, { waitUntil: 'load' });
    await page.getByText('Known vulnerabilities').first().waitFor({ timeout: 60000 });
    await page.getByText('not checked (not installed with Composer)').first().waitFor({ timeout: 30000 });
    await page.waitForTimeout(1500);
    await page.screenshot({ path: `${out}/admin-security-alerts.png` });

    // The settings entry that leads to it.
    await page.goto(`${base}/admin#/sw/settings/index/system`, { waitUntil: 'load' });
    await page.getByText('Security alerts').first().waitFor({ timeout: 30000 });
    await page.waitForTimeout(1000);
    await page.screenshot({ path: `${out}/admin-settings-entry.png` });

    // Check now works from the page.
    await page.goto(`${base}/admin#/ruvelo/security/alerts/index`, { waitUntil: 'load' });
    await page.getByRole('button', { name: 'Check now' }).click();
    await page.getByText('The check is done.').first().waitFor({ timeout: 120000 });
    console.log('Check now: done notification shown');
} catch (e) {
    console.log('FAILED:', e.message);
    await page.screenshot({ path: `${out}/failure.png` });
    process.exitCode = 1;
} finally {
    await browser.close();
}
