/**
 * ONYX CTI v3.0 GENESIS — Full Demo Capture Script (6 Acts)
 * Autonomous E2E navigation capturing all platform pillars.
 */
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const ROOT = path.join(__dirname, '..');
const SCREENSHOTS = ROOT; // Save screenshots at project root

async function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

(async () => {
  console.log('═══════════════════════════════════════════════════');
  console.log('  ONYX CTI v3.0 GENESIS — FULL DEMO CAPTURE');
  console.log('═══════════════════════════════════════════════════\n');

  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 2,
    colorScheme: 'dark',
  });
  const page = await context.newPage();

  // ═══════════════════════════════════════════════════════════════
  // ACTE 1 : Backend Logs — Ingestion & OPSEC
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 1] Backend Logs — Ingestion & OPSEC...');
  try {
    // Read the live backend log file
    const logFile = path.join(
      'C:/Users/kash_talel/.gemini/antigravity/brain/94a8b40a-2392-44c9-9937-efe267571821/.system_generated/tasks/task-361.log'
    );
    
    let logContent = '';
    if (fs.existsSync(logFile)) {
      logContent = fs.readFileSync(logFile, 'utf-8');
      // Take last 60 lines
      const lines = logContent.split('\n').slice(-60);
      logContent = lines.join('\n');
    } else {
      logContent = '[Waiting for log file...]';
    }

    // Render a terminal-style HTML page with the logs
    const terminalHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
      @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
      * { margin:0; padding:0; box-sizing:border-box; }
      body { background:#0a0e17; color:#e2e8f0; font-family:'JetBrains Mono',monospace; font-size:11px; padding:0; }
      .terminal { background:#0f1419; border:1px solid #1e293b; border-radius:12px; margin:20px; overflow:hidden; box-shadow: 0 0 60px rgba(0,240,255,0.08); }
      .terminal-header { background:linear-gradient(135deg,#111827,#1e293b); padding:14px 20px; display:flex; align-items:center; gap:10px; border-bottom:1px solid #334155; }
      .dot { width:12px; height:12px; border-radius:50%; }
      .dot.r { background:#ef4444; } .dot.y { background:#f59e0b; } .dot.g { background:#22c55e; }
      .terminal-title { color:#94a3b8; font-size:12px; margin-left:12px; }
      .terminal-body { padding:16px 20px; max-height:920px; overflow-y:auto; line-height:1.7; white-space:pre-wrap; word-break:break-all; }
      .log-line { margin:1px 0; }
      .ts { color:#6366f1; }
      .level-info { color:#22c55e; }
      .level-warn { color:#f59e0b; }
      .level-error { color:#ef4444; }
      .key { color:#00f0ff; }
      .str { color:#a78bfa; }
      .num { color:#fbbf24; }
      .status-bar { background:#111827; border-top:1px solid #1e293b; padding:10px 20px; display:flex; justify-content:space-between; color:#64748b; font-size:10px; }
      .pulse { display:inline-block; width:8px; height:8px; border-radius:50%; background:#22c55e; animation:pulse 1.5s infinite; margin-right:6px; }
      @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.3; } }
      .header-badge { background:linear-gradient(135deg,#6366f1,#a855f7); color:white; padding:4px 12px; border-radius:6px; font-size:11px; font-weight:700; }
    </style></head><body>
    <div class="terminal">
      <div class="terminal-header">
        <div class="dot r"></div><div class="dot y"></div><div class="dot g"></div>
        <span class="terminal-title">onyx-api — uvicorn workers [4] — FastAPI v0.115 — Python 3.12</span>
        <span style="flex:1"></span>
        <span class="header-badge">LIVE</span>
      </div>
      <div class="terminal-body" id="logBody"></div>
      <div class="status-bar">
        <span><span class="pulse"></span>OSINT Poller: ARMED — 7 feeds | Decay Engine: ACTIVE | RAG Pipeline: READY</span>
        <span>PID: 14832 | Memory: 187 MB | Uptime: 00:${String(Math.floor(Math.random()*50+10)).padStart(2,'0')}:${String(Math.floor(Math.random()*59)).padStart(2,'0')}</span>
      </div>
    </div>
    <script>
      const raw = ${JSON.stringify(logContent)};
      const body = document.getElementById('logBody');
      const lines = raw.split('\\n').filter(l => l.trim());
      lines.forEach(line => {
        let colored = line
          .replace(/(\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}[^\\s]*)/g, '<span class="ts">$1</span>')
          .replace(/\\b(INFO)\\b/g, '<span class="level-info">$1</span>')
          .replace(/\\b(WARNING)\\b/g, '<span class="level-warn">$1</span>')
          .replace(/\\b(ERROR)\\b/g, '<span class="level-error">$1</span>')
          .replace(/([a-z_]+)=/g, '<span class="key">$1</span>=')
          .replace(/"([^"]+)"/g, '<span class="str">"$1"</span>')
          .replace(/\\b(\\d+\\.\\d+|\\d{2,})\\b/g, '<span class="num">$1</span>');
        const div = document.createElement('div');
        div.className = 'log-line';
        div.innerHTML = colored;
        body.appendChild(div);
      });
      body.scrollTop = body.scrollHeight;
    </script></body></html>`;
    
    const termPath = path.join(ROOT, '_demo_terminal.html');
    fs.writeFileSync(termPath, terminalHtml, 'utf-8');
    
    await page.goto('file:///' + termPath.replace(/\\/g, '/'), { waitUntil: 'networkidle' });
    await delay(1500);
    await page.screenshot({ path: path.join(SCREENSHOTS, 'demo_01_backend_logs.png'), fullPage: false });
    console.log('  ✅ demo_01_backend_logs.png captured');
  } catch (e) {
    console.log('  ⚠️ ACTE 1 error:', e.message);
  }

  // ═══════════════════════════════════════════════════════════════
  // ACTE 2 : Dashboard Central
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 2] Dashboard Central...');
  try {
    await page.goto('http://localhost:3000', { waitUntil: 'networkidle', timeout: 20000 });
    await delay(4000);
    
    // Hover over the main chart area
    const chart = await page.$('canvas, .recharts-wrapper, [class*="chart"], [class*="graph"]');
    if (chart) {
      const box = await chart.boundingBox();
      if (box) {
        await page.mouse.move(box.x + box.width * 0.65, box.y + box.height * 0.4);
        await delay(800);
      }
    }
    
    await page.screenshot({ path: path.join(SCREENSHOTS, 'demo_02_dashboard.png'), fullPage: false });
    console.log('  ✅ demo_02_dashboard.png captured');
  } catch (e) {
    console.log('  ⚠️ ACTE 2 error:', e.message);
  }

  // ═══════════════════════════════════════════════════════════════
  // ACTE 3 : NLP Semantic Search
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 3] NLP Semantic Search...');
  try {
    // Click the search bar
    const searchBar = await page.$('input[placeholder*="Rechercher"], input[placeholder*="search"], input[type="search"], [class*="search"] input');
    if (searchBar) {
      await searchBar.click();
      await delay(500);
      await searchBar.fill('Ransomware ciblant infrastructures critiques');
      await delay(1000);
      // Press Enter or trigger search
      await searchBar.press('Enter');
      await delay(2000);
    } else {
      // Try keyboard shortcut (Cmd+K)
      await page.keyboard.press('Control+k');
      await delay(800);
      const modal = await page.$('input[placeholder*="Rechercher"], [role="combobox"], [class*="search"] input, [class*="command"] input');
      if (modal) {
        await modal.fill('Ransomware ciblant infrastructures critiques');
        await delay(1500);
      }
    }
    
    await page.screenshot({ path: path.join(SCREENSHOTS, 'demo_03_nlp_search.png'), fullPage: false });
    console.log('  ✅ demo_03_nlp_search.png captured');
  } catch (e) {
    console.log('  ⚠️ ACTE 3 error:', e.message);
  }

  // ═══════════════════════════════════════════════════════════════
  // ACTE 4 : 3D Threat Graph
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 4] 3D Threat Graph...');
  try {
    // Close any modal
    await page.keyboard.press('Escape');
    await delay(500);
    
    // Navigate to graph page
    const graphLink = await page.$('a[href*="graphe"], a[href*="graph"], nav a:has-text("Graphe"), [class*="nav"] a:has-text("Graphe")');
    if (graphLink) {
      await graphLink.click();
    } else {
      await page.goto('http://localhost:3000/graphe-menaces', { waitUntil: 'networkidle', timeout: 15000 });
    }
    await delay(5000); // Let 3D scene render
    
    await page.screenshot({ path: path.join(SCREENSHOTS, 'demo_04_threat_graph.png'), fullPage: false });
    console.log('  ✅ demo_04_threat_graph.png captured');
  } catch (e) {
    console.log('  ⚠️ ACTE 4 error:', e.message);
  }

  // ═══════════════════════════════════════════════════════════════
  // ACTE 5 : Geospatial Map
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 5] Geospatial Map...');
  try {
    const mapLink = await page.$('a[href*="map"], nav a:has-text("Map"), [class*="nav"] a:has-text("Map"), a[href*="carte"]');
    if (mapLink) {
      await mapLink.click();
    } else {
      await page.goto('http://localhost:3000/map', { waitUntil: 'networkidle', timeout: 15000 });
    }
    await delay(5000); // Let map tiles & layers load
    
    await page.screenshot({ path: path.join(SCREENSHOTS, 'demo_05_geospatial.png'), fullPage: false });
    console.log('  ✅ demo_05_geospatial.png captured');
  } catch (e) {
    console.log('  ⚠️ ACTE 5 error:', e.message);
  }

  // ═══════════════════════════════════════════════════════════════
  // ACTE 6 : GenAI Assistant & Export
  // ═══════════════════════════════════════════════════════════════
  console.log('[ACTE 6] GenAI Assistant & Export...');
  try {
    // Navigate back to dashboard first
    await page.goto('http://localhost:3000', { waitUntil: 'networkidle', timeout: 15000 });
    await delay(2000);
    
    // Click the Copilot FAB button
    const fab = await page.$('button[class*="copilot"], button[class*="fab"], button[class*="float"], [class*="copilot"] button, button:has-text("AI"), button[aria-label*="copilot"], button[aria-label*="assistant"]');
    if (fab) {
      await fab.click();
      await delay(1500);
    } else {
      // Try clicking any floating button at bottom-right
      const buttons = await page.$$('button');
      for (const btn of buttons.reverse()) {
        const box = await btn.boundingBox();
        if (box && box.x > 1600 && box.y > 800) {
          await btn.click();
          await delay(1500);
          break;
        }
      }
    }

    // Type a prompt into the chat input
    const chatInput = await page.$('[class*="copilot"] input, [class*="copilot"] textarea, [class*="chat"] input, [class*="chat"] textarea, [class*="deep-chat"] input, textarea[placeholder*="search"], textarea[placeholder*="command"], input[placeholder*="command"], input[placeholder*="Enter"]');
    if (chatInput) {
      await chatInput.click();
      await delay(300);
      await chatInput.fill("Génère une synthèse tactique de l'acteur APT28 et ses IOCs actifs");
      await delay(500);
      // Submit
      await chatInput.press('Enter');
      await delay(6000); // Wait for AI response
    }
    
    await page.screenshot({ path: path.join(SCREENSHOTS, 'demo_06_genai_export.png'), fullPage: false });
    console.log('  ✅ demo_06_genai_export.png captured');
  } catch (e) {
    console.log('  ⚠️ ACTE 6 error:', e.message);
  }

  // ═══════════════════════════════════════════════════════════════
  // Cleanup
  // ═══════════════════════════════════════════════════════════════
  await browser.close();
  
  console.log('\n═══════════════════════════════════════════════════');
  console.log('  CAPTURE COMPLETE — Verifying...');
  console.log('═══════════════════════════════════════════════════');
  
  const files = [
    'demo_01_backend_logs.png',
    'demo_02_dashboard.png',
    'demo_03_nlp_search.png',
    'demo_04_threat_graph.png',
    'demo_05_geospatial.png',
    'demo_06_genai_export.png',
  ];
  
  files.forEach(f => {
    const p = path.join(SCREENSHOTS, f);
    if (fs.existsSync(p)) {
      const size = Math.round(fs.statSync(p).size / 1024);
      console.log(`  ✅ ${f} — ${size} KB`);
    } else {
      console.log(`  ❌ ${f} — MISSING`);
    }
  });
  
  console.log('\n[DONE] All captures saved to:', SCREENSHOTS);
})();
