const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

(async () => {
  const queuePath = 'queue.txt';
  if (!fs.existsSync(queuePath)) {
    console.log("No queue.txt file found.");
    return;
  }

  const urls = fs.readFileSync(queuePath, 'utf-8').split('\n').filter(Boolean);
  fs.writeFileSync(queuePath, ''); // Clear queue

  for (let url of urls) {
    console.log(`🕵️ Scanning: ${url}`);
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();
    let isMalicious = false;

    // Log any downloads or redirects
    page.on('response', async (res) => {
      const resUrl = res.url();
      if (resUrl.endsWith('.apk') || resUrl.endsWith('.exe') || resUrl.includes('download')) {
        console.log(`⚠️ MALICIOUS DOWNLOAD: ${resUrl}`);
        fs.appendFileSync('malware_logs.txt', `[MALICIOUS] ${url} → ${resUrl}\n`);
        isMalicious = true;
      }
    });

    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
      await page.screenshot({ path: `screenshots/${new URL(url).hostname}.png` });
    } catch (err) {
      console.log(`❌ Failed to open: ${url}`);
    }

    if (!isMalicious) {
      fs.appendFileSync('malware_logs.txt', `[CLEAN] ${url}\n`);
    }

    await browser.close();
  }

  console.log("✅ Scan complete.");
})();
