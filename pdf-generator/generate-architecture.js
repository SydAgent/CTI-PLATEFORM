'use strict';
const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

async function generatePDF() {
  const html = fs.readFileSync(path.join(__dirname, 'architecture-template.html'), 'utf8');
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: 'networkidle0' });
  await page.emulateMediaType('print');

  const outputPath = path.join(__dirname, 'ONYX-CTI-Architecture-v4.2.pdf');
  await page.pdf({
    path: outputPath,
    format: 'A4',
    margin: { top: '2cm', right: '2cm', bottom: '2.5cm', left: '2cm' },
    printBackground: true,
    displayHeaderFooter: true,
    headerTemplate: `
      <div style="width:100%;font-family:Helvetica,Arial,sans-serif;font-size:8pt;
                  color:#4A5568;border-bottom:1px solid #E2E8F0;padding:4px 20px;
                  display:flex;justify-content:space-between;align-items:center;box-sizing:border-box;">
        <span style="font-weight:700;color:#0891B2;">ONYX CTI</span>
        <span class="title" style="color:#2D3748;"></span>
        <span style="color:#0891B2;font-weight:600;">v4.2 Sovereign</span>
      </div>`,
    footerTemplate: `
      <div style="width:100%;font-family:Helvetica,Arial,sans-serif;font-size:7.5pt;
                  color:#718096;border-top:1px solid #E2E8F0;padding:4px 20px;
                  display:flex;justify-content:space-between;align-items:center;box-sizing:border-box;">
        <span style="color:#C53030;font-weight:600;">CONFIDENTIEL — ONYX CTI v4.2</span>
        <span>Page <span class="pageNumber"></span> sur <span class="totalPages"></span></span>
        <span>Généré le 24/04/2026</span>
      </div>`
  });

  await browser.close();
  console.log('PDF généré :', outputPath);
}

generatePDF().catch(err => { console.error(err); process.exit(1); });
