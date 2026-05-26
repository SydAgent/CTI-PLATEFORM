const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
  
  await page.goto('http://localhost:3000', { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(5000);
  
  // Screenshot 1: Click "Vue Opérationnelle" to get the ThreatMap3D
  await page.click('text=Vue Opérationnelle');
  await page.waitForTimeout(8000);
  await page.screenshot({ path: '../map_geospatiale.png', fullPage: false });
  console.log('Saved map_geospatiale.png');
  
  // Screenshot 2: Click "Graphe de Menaces" to get the ThreatGraph
  await page.click('text=Graphe de Menaces');
  await page.waitForTimeout(8000);
  await page.screenshot({ path: '../graphe_3d_menace.png', fullPage: false });
  console.log('Saved graphe_3d_menace.png');
  
  await browser.close();
  console.log('Done!');
})();
