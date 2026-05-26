/**
 * ONYX CTI v3.0 GENESIS — VIDEO DEMO RECORDER
 * Records a full E2E navigation video using Playwright's built-in recordVideo.
 * Output: .webm video file at 1920x1080.
 */
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const ROOT = path.join(__dirname, '..');
const VIDEO_DIR = path.join(ROOT, '_demo_video');

async function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

(async () => {
  console.log('═══════════════════════════════════════════════════');
  console.log('  ONYX CTI v3.0 — VIDEO DEMO RECORDING');
  console.log('═══════════════════════════════════════════════════\n');

  // Ensure video output directory
  if (!fs.existsSync(VIDEO_DIR)) fs.mkdirSync(VIDEO_DIR, { recursive: true });

  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });

  // Create context WITH video recording
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 1,
    colorScheme: 'dark',
    recordVideo: {
      dir: VIDEO_DIR,
      size: { width: 1920, height: 1080 },
    },
  });

  const page = await context.newPage();

  // ═══════════════════════════════════════════════════════════════
  // ACTE 1 : Dashboard — First load & overview (15s)
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 1] Dashboard — Loading...');
  await page.goto('http://localhost:3000', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await delay(6000); // Let all WebSocket data, charts, and animations load

  // Slow mouse movement over the dashboard to show interactivity
  // Hover over the risk score
  await page.mouse.move(350, 155, { steps: 30 });
  await delay(1500);

  // Hover over IOCs count
  await page.mouse.move(590, 115, { steps: 25 });
  await delay(1000);

  // Hover over CVEs
  await page.mouse.move(800, 115, { steps: 25 });
  await delay(1000);

  // Hover over Botnets
  await page.mouse.move(1030, 115, { steps: 25 });
  await delay(1000);

  // Hover over the distribution chart
  await page.mouse.move(640, 350, { steps: 40 });
  await delay(1500);
  await page.mouse.move(500, 320, { steps: 30 });
  await delay(1000);
  await page.mouse.move(800, 380, { steps: 30 });
  await delay(1000);
  await page.mouse.move(950, 350, { steps: 30 });
  await delay(1500);

  // Hover over top actors
  await page.mouse.move(430, 565, { steps: 25 });
  await delay(800);
  await page.mouse.move(430, 615, { steps: 20 });
  await delay(800);
  await page.mouse.move(430, 665, { steps: 20 });
  await delay(800);

  // Hover over sector donut chart
  await page.mouse.move(750, 600, { steps: 25 });
  await delay(1500);

  // Hover over alert feed
  await page.mouse.move(1250, 330, { steps: 30 });
  await delay(1000);
  await page.mouse.move(1250, 400, { steps: 20 });
  await delay(1000);
  await page.mouse.move(1250, 480, { steps: 20 });
  await delay(1000);

  console.log('  ✅ ACTE 1 — Dashboard overview recorded');

  // ═══════════════════════════════════════════════════════════════
  // ACTE 2 : NLP Search (7s)
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 2] NLP Semantic Search...');
  // Click the search bar
  const searchInput = await page.$('input[type="text"], input[placeholder*="Rechercher"]');
  if (searchInput) {
    await searchInput.click();
    await delay(500);
    // Type slowly for video effect
    const query = 'Ransomware ciblant infrastructures critiques';
    for (const char of query) {
      await page.keyboard.type(char, { delay: 60 });
    }
    await delay(2000);
    await page.keyboard.press('Escape');
    await delay(500);
  }
  console.log('  ✅ ACTE 2 — NLP search recorded');

  // ═══════════════════════════════════════════════════════════════
  // ACTE 3 : Navigate to Vue Opérationnelle (7s)
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 3] Vue Opérationnelle...');
  const vueOp = await page.$('text=Vue Opérationnelle');
  if (vueOp) {
    await vueOp.click();
    await delay(5000);
    await page.mouse.move(960, 400, { steps: 30 });
    await delay(2000);
  } else {
    // Try the second sidebar item
    const sidebarItems = await page.$$('nav li, aside li, [class*="sidebar"] > div > div');
    if (sidebarItems.length > 1) {
      await sidebarItems[1].click();
      await delay(5000);
    }
  }
  console.log('  ✅ ACTE 3 — Vue Opérationnelle recorded');

  // ═══════════════════════════════════════════════════════════════
  // ACTE 4 : Laboratoire IA (7s)
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 4] Laboratoire IA...');
  const labIA = await page.$('text=Laboratoire IA');
  if (labIA) {
    await labIA.click();
    await delay(5000);
    await page.mouse.move(960, 500, { steps: 25 });
    await delay(2000);
  }
  console.log('  ✅ ACTE 4 — Laboratoire IA recorded');

  // ═══════════════════════════════════════════════════════════════
  // ACTE 5 : Explorateur IOC (7s)
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 5] Explorateur IOC...');
  const exploIOC = await page.$('text=Explorateur IOC');
  if (exploIOC) {
    await exploIOC.click();
    await delay(5000);
    // Scroll down slowly to show the table
    await page.mouse.move(960, 500);
    await page.mouse.wheel(0, 300);
    await delay(2000);
  }
  console.log('  ✅ ACTE 5 — Explorateur IOC recorded');

  // ═══════════════════════════════════════════════════════════════
  // ACTE 6 : Acteurs de la Menace (7s)
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 6] Acteurs de la Menace...');
  const acteurs = await page.$('text=Acteurs de la Menace');
  if (acteurs) {
    await acteurs.click();
    await delay(5000);
    await page.mouse.move(600, 400, { steps: 25 });
    await delay(2000);
  }
  console.log('  ✅ ACTE 6 — Acteurs recorded');

  // ═══════════════════════════════════════════════════════════════
  // ACTE 7 : Graphe de Menaces 3D (10s)
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 7] Graphe de Menaces 3D...');
  const graphe = await page.$('text=Graphe de Menaces');
  if (graphe) {
    await graphe.click();
    await delay(6000); // Let 3D scene render

    // Rotate the 3D graph by dragging
    await page.mouse.move(960, 500);
    await page.mouse.down();
    for (let i = 0; i < 60; i++) {
      await page.mouse.move(960 + i * 3, 500 + Math.sin(i * 0.1) * 20, { steps: 1 });
      await delay(30);
    }
    await page.mouse.up();
    await delay(2000);

    // Drag in another direction
    await page.mouse.move(1100, 500);
    await page.mouse.down();
    for (let i = 0; i < 40; i++) {
      await page.mouse.move(1100 - i * 3, 500 - i * 2, { steps: 1 });
      await delay(30);
    }
    await page.mouse.up();
    await delay(2000);
  }
  console.log('  ✅ ACTE 7 — 3D Threat Graph recorded');

  // ═══════════════════════════════════════════════════════════════
  // ACTE 8 : Crawlers / OSINT (5s)
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 8] Crawlers...');
  const crawlers = await page.$('text=Crawlers');
  if (crawlers) {
    await crawlers.click();
    await delay(4000);
    await page.mouse.move(960, 400, { steps: 25 });
    await delay(1500);
  }
  console.log('  ✅ ACTE 8 — Crawlers recorded');

  // ═══════════════════════════════════════════════════════════════
  // ACTE 9 : Rapports (5s)
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 9] Rapports...');
  const rapports = await page.$('text=Rapports');
  if (rapports) {
    await rapports.click();
    await delay(4000);
    await page.mouse.move(960, 400, { steps: 25 });
    await delay(1500);
  }
  console.log('  ✅ ACTE 9 — Rapports recorded');

  // ═══════════════════════════════════════════════════════════════
  // ACTE 10 : Matrice ATT&CK (7s)
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 10] Matrice ATT&CK...');
  const matrice = await page.$('text=Matrice ATT&CK');
  if (matrice) {
    await matrice.click();
    await delay(5000);
    // Scroll horizontally to show the full matrix
    await page.mouse.move(960, 500);
    await page.mouse.wheel(300, 0);
    await delay(2000);
  }
  console.log('  ✅ ACTE 10 — Matrice ATT&CK recorded');

  // ═══════════════════════════════════════════════════════════════
  // ACTE 11 : ONYX Copilot GenAI (15s)
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 11] ONYX Copilot — GenAI...');
  // Go back to dashboard first
  const dashboard = await page.$('text=Tableau de Bord');
  if (dashboard) {
    await dashboard.click();
    await delay(3000);
  }

  // Click the Copilot FAB (bottom-right floating button)
  const allButtons = await page.$$('button');
  let fabClicked = false;
  for (const btn of allButtons.reverse()) {
    const box = await btn.boundingBox();
    if (box && box.x > 1350 && box.y > 700) {
      await btn.click();
      fabClicked = true;
      await delay(2000);
      break;
    }
  }

  if (fabClicked) {
    // Find chat input and type
    const chatInput = await page.$('input[placeholder*="Enter"], input[placeholder*="command"], input[placeholder*="search"], textarea');
    if (chatInput) {
      await chatInput.click();
      await delay(500);
      const prompt = "Synthèse tactique de APT28 et ses IOCs actifs";
      for (const char of prompt) {
        await page.keyboard.type(char, { delay: 50 });
      }
      await delay(1000);
      await page.keyboard.press('Enter');
      await delay(8000); // Wait for AI response streaming
    }
  }
  console.log('  ✅ ACTE 11 — ONYX Copilot recorded');

  // Final pause on the result
  await delay(3000);

  // ═══════════════════════════════════════════════════════════════
  // Close and save video
  // ═══════════════════════════════════════════════════════════════
  console.log('\n[SAVING] Closing context to finalize video...');
  await page.close();
  await context.close();
  await browser.close();

  // Find the video file
  const videos = fs.readdirSync(VIDEO_DIR).filter(f => f.endsWith('.webm'));
  if (videos.length > 0) {
    const videoFile = path.join(VIDEO_DIR, videos[videos.length - 1]);
    const finalPath = path.join(ROOT, 'ONYX_Demo_Complete.webm');
    fs.copyFileSync(videoFile, finalPath);
    const sizeMB = (fs.statSync(finalPath).size / (1024 * 1024)).toFixed(1);
    console.log(`\n═══════════════════════════════════════════════════`);
    console.log(`  ✅ VIDEO SAVED: ONYX_Demo_Complete.webm (${sizeMB} MB)`);
    console.log(`  Path: ${finalPath}`);
    console.log(`═══════════════════════════════════════════════════`);
  } else {
    console.log('  ❌ No video file found in output directory');
  }
})();
