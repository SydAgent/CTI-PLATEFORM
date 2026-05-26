const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
  
  await page.goto('http://localhost:3000', { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(5000);
  
  // Screenshot 1: Open the chatbot/copilot and interact
  // Click the floating action button to open the copilot
  await page.click('#onyx-copilot-fab');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '../assistant_chatbot.png', fullPage: false });
  console.log('Saved assistant_chatbot.png');
  
  // Screenshot 2: Navigate to Reports page for export rules
  await page.click('#onyx-copilot-fab'); // close copilot first
  await page.waitForTimeout(500);
  await page.click('text=Rapports');
  await page.waitForTimeout(5000);
  await page.screenshot({ path: '../export_rules.png', fullPage: false });
  console.log('Saved export_rules.png');
  
  await browser.close();
  console.log('Done!');
})();
