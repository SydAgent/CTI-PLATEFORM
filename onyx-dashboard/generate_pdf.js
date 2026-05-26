/**
 * ONYX Chapter 4 — LaTeX-to-PDF via Playwright
 * Reads the merged .tex, converts to styled HTML, renders to PDF.
 */
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

// ── Read and parse LaTeX ────────────────────────────────────────────────────
const ROOT = path.join(__dirname, '..');
const tex = fs.readFileSync(path.join(ROOT, 'chapitre4_complet.tex'), 'utf-8');

function texToHtml(raw) {
  let s = raw;

  // Remove pure LaTeX comments (lines starting with %%)
  s = s.replace(/^%%.*$/gm, '');

  // ── Listings (code blocks) ──
  s = s.replace(/\\begin\{lstlisting\}\[([^\]]*)\]([\s\S]*?)\\end\{lstlisting\}/g, (_, opts, code) => {
    const capMatch = opts.match(/caption=\{([^}]*)\}/);
    const labMatch = opts.match(/label=\{([^}]*)\}/);
    const caption = capMatch ? capMatch[1] : '';
    const label = labMatch ? labMatch[1] : '';
    const clean = code.replace(/</g, '&lt;').replace(/>/g, '&gt;').trim();
    return `<figure class="listing" ${label ? `id="${label}"` : ''}>
      <pre><code>${clean}</code></pre>
      ${caption ? `<figcaption>${caption}</figcaption>` : ''}
    </figure>`;
  });

  // ── Tables ──
  s = s.replace(/\\begin\{table\}\[H\]([\s\S]*?)\\end\{table\}/g, (_, inner) => {
    const capMatch = inner.match(/\\caption\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/);
    const labMatch = inner.match(/\\label\{([^}]*)\}/);
    const caption = capMatch ? capMatch[1] : '';
    const label = labMatch ? labMatch[1] : '';

    // Parse tabular
    const tabMatch = inner.match(/\\begin\{tabular\}\{[^}]*\}([\s\S]*?)\\end\{tabular\}/);
    if (!tabMatch) return inner;

    let tabContent = tabMatch[1];
    // Remove \hline
    tabContent = tabContent.replace(/\\hline/g, '');
    // Split rows
    const rows = tabContent.split('\\\\').map(r => r.trim()).filter(r => r.length > 0);

    let tableHtml = `<table ${label ? `id="${label}"` : ''}>`;
    if (caption) tableHtml += `<caption>${texInline(caption)}</caption>`;

    rows.forEach((row, idx) => {
      const cells = row.split('&').map(c => c.trim());
      const tag = idx === 0 ? 'th' : 'td';
      const trClass = idx === 0 ? 'header-row' : (idx % 2 === 0 ? 'even' : 'odd');
      tableHtml += `<tr class="${trClass}">`;
      cells.forEach(cell => {
        tableHtml += `<${tag}>${texInline(cell)}</${tag}>`;
      });
      tableHtml += `</tr>`;
    });
    tableHtml += `</table>`;
    return tableHtml;
  });

  // ── Figures ──
  s = s.replace(/\\begin\{figure\}\[H\]([\s\S]*?)\\end\{figure\}/g, (_, inner) => {
    const imgMatch = inner.match(/\\includegraphics\[([^\]]*)\]\{([^}]*)\}/);
    const capMatch = inner.match(/\\caption\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/);
    const labMatch = inner.match(/\\label\{([^}]*)\}/);
    const imgFile = imgMatch ? imgMatch[2] : '';
    const caption = capMatch ? capMatch[1] : '';
    const label = labMatch ? labMatch[1] : '';

    // Convert to base64 for embedding
    const imgPath = path.join(ROOT, imgFile);
    let imgTag = '';
    if (fs.existsSync(imgPath)) {
      const b64 = fs.readFileSync(imgPath).toString('base64');
      imgTag = `<img src="data:image/png;base64,${b64}" alt="${caption}" />`;
    } else {
      imgTag = `<div class="img-placeholder">[Image: ${imgFile}]</div>`;
    }

    return `<figure ${label ? `id="${label}"` : ''}>
      ${imgTag}
      ${caption ? `<figcaption>${texInline(caption)}</figcaption>` : ''}
    </figure>`;
  });

  // ── Enumerate ──
  s = s.replace(/\\begin\{enumerate\}([\s\S]*?)\\end\{enumerate\}/g, (_, inner) => {
    const items = inner.split('\\item').filter(i => i.trim().length > 0);
    return '<ol>' + items.map(i => `<li>${texInline(i.trim())}</li>`).join('\n') + '</ol>';
  });

  // ── Structure ──
  s = s.replace(/\\chapter\*\{([^}]*)\}/g, '<h1 class="chapter">$1</h1>');
  s = s.replace(/\\addcontentsline\{[^}]*\}\{[^}]*\}\{[^}]*\}/g, '');
  s = s.replace(/\\section\*\{([^}]*)\}/g, '<h2 class="section-unnumbered">$1</h2>');
  s = s.replace(/\\section\{([^}]*)\}/g, '<h2 class="section">$1</h2>');
  s = s.replace(/\\subsection\{([^}]*)\}/g, '<h3 class="subsection">$1</h3>');
  s = s.replace(/\\subsubsection\{([^}]*)\}/g, '<h4 class="subsubsection">$1</h4>');

  // Apply inline formatting
  s = texInline(s);

  // ── Paragraphs ──
  s = s.replace(/\n{2,}/g, '</p><p>');
  s = '<p>' + s + '</p>';
  s = s.replace(/<p>\s*<(h[1-4]|figure|table|ol|pre)/g, '<$1');
  s = s.replace(/<\/(h[1-4]|figure|table|ol|pre)>\s*<\/p>/g, '</$1>');
  s = s.replace(/<p>\s*<\/p>/g, '');

  return s;
}

function texInline(s) {
  // Order matters
  s = s.replace(/\\textbf\{([^}]*)\}/g, '<strong>$1</strong>');
  s = s.replace(/\\textit\{([^}]*)\}/g, '<em>$1</em>');
  s = s.replace(/\\texttt\{([^}]*)\}/g, '<code>$1</code>');
  s = s.replace(/\\emph\{([^}]*)\}/g, '<em>$1</em>');
  s = s.replace(/\\og\s*/g, '«\u00a0');
  s = s.replace(/\\fg\{\}/g, '\u00a0»');
  s = s.replace(/\\ref\{([^}]*)\}/g, '<a href="#$1">[ref]</a>');
  s = s.replace(/~~/g, '\u00a0');
  s = s.replace(/~/g, '\u00a0');
  s = s.replace(/---/g, '—');
  s = s.replace(/--/g, '–');
  s = s.replace(/\\&/g, '&amp;');
  s = s.replace(/\\\\/g, '');
  s = s.replace(/\\_/g, '_');
  s = s.replace(/\\,/g, '\u2009');
  s = s.replace(/\\%/g, '%');
  s = s.replace(/\\\$/g, '$');
  // Math mode (simple inline)
  s = s.replace(/\$([^$]+)\$/g, '<span class="math">$1</span>');
  s = s.replace(/\\\\geq/g, '≥');
  s = s.replace(/\\geq/g, '≥');
  s = s.replace(/\\alpha/g, 'α');
  s = s.replace(/\\times/g, '×');
  s = s.replace(/\\left\(/g, '(');
  s = s.replace(/\\right\)/g, ')');
  s = s.replace(/\\(  )/g, ' ');
  return s;
}

const bodyHtml = texToHtml(tex);

// ── Full HTML document ──────────────────────────────────────────────────────
const html = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Chapitre 4 — Validation Fonctionnelle, Restitution et Évaluation</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=EB+Garamond:ital,wght@0,400;0,600;0,700;1,400&family=JetBrains+Mono:wght@400;600&display=swap');

  :root {
    --bg: #0c1019;
    --card: #111827;
    --border: #1e293b;
    --text: #e2e8f0;
    --text-dim: #94a3b8;
    --accent: #00f0ff;
    --accent2: #a855f7;
    --red: #ef4444;
    --amber: #f59e0b;
    --green: #22c55e;
  }

  @page {
    size: A4;
    margin: 25mm 20mm 30mm 25mm;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'EB Garamond', 'Times New Roman', serif;
    font-size: 12pt;
    line-height: 1.75;
    color: #1a1a2e;
    background: #fff;
    max-width: 100%;
    padding: 0;
  }

  /* ── Headings ────────────────────────────────────────── */
  h1.chapter {
    font-size: 26pt;
    font-weight: 700;
    color: #0f172a;
    text-align: center;
    margin: 40pt 0 12pt;
    padding-bottom: 10pt;
    border-bottom: 3px solid #0f172a;
    page-break-before: always;
  }

  h2.section, h2.section-unnumbered {
    font-size: 18pt;
    font-weight: 700;
    color: #0f172a;
    margin: 30pt 0 10pt;
    padding-bottom: 6pt;
    border-bottom: 1.5px solid #334155;
    counter-increment: section;
    page-break-after: avoid;
  }

  h2.section::before {
    content: "4." counter(section) "  ";
    color: #6366f1;
  }

  h3.subsection {
    font-size: 14pt;
    font-weight: 600;
    color: #1e293b;
    margin: 22pt 0 8pt;
    counter-increment: subsection;
    page-break-after: avoid;
  }

  h3.subsection::before {
    content: "4." counter(section) "." counter(subsection) "  ";
    color: #6366f1;
  }

  h4.subsubsection {
    font-size: 12pt;
    font-weight: 600;
    color: #334155;
    margin: 16pt 0 6pt;
    font-style: italic;
  }

  /* Reset counters */
  body { counter-reset: section; }
  h2.section { counter-reset: subsection; }

  /* ── Paragraphs ─────────────────────────────────────── */
  p {
    text-align: justify;
    margin: 8pt 0;
    text-indent: 20pt;
    orphans: 3;
    widows: 3;
  }

  p:first-of-type, h2 + p, h3 + p, h4 + p, figure + p, table + p, ol + p {
    text-indent: 0;
  }

  /* ── Inline ─────────────────────────────────────────── */
  strong { font-weight: 700; }
  em { font-style: italic; }
  code {
    font-family: 'JetBrains Mono', monospace;
    font-size: 9.5pt;
    background: #f1f5f9;
    padding: 1pt 4pt;
    border-radius: 3pt;
    color: #7c3aed;
  }
  .math {
    font-style: italic;
    font-family: 'EB Garamond', serif;
  }

  /* ── Code Listings ──────────────────────────────────── */
  figure.listing {
    margin: 16pt 0;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 6pt;
    overflow: hidden;
    page-break-inside: avoid;
  }
  figure.listing pre {
    padding: 14pt 18pt;
    margin: 0;
    overflow-x: auto;
  }
  figure.listing code {
    font-family: 'JetBrains Mono', monospace;
    font-size: 8.5pt;
    line-height: 1.6;
    color: #e2e8f0;
    background: transparent;
    padding: 0;
    white-space: pre;
    display: block;
  }
  figure.listing figcaption {
    padding: 8pt 18pt;
    font-size: 9pt;
    color: #64748b;
    background: #1e293b;
    border-top: 1px solid #334155;
    font-style: italic;
  }

  /* ── Tables ─────────────────────────────────────────── */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 16pt 0;
    font-size: 10pt;
    page-break-inside: avoid;
  }
  caption {
    font-size: 10pt;
    font-style: italic;
    color: #475569;
    text-align: left;
    margin-bottom: 6pt;
    caption-side: top;
  }
  th, td {
    border: 1px solid #cbd5e1;
    padding: 6pt 10pt;
    text-align: left;
    vertical-align: top;
  }
  tr.header-row {
    background: #0f172a;
    color: #fff;
  }
  tr.header-row th {
    border-color: #334155;
    font-weight: 700;
    font-size: 9.5pt;
    text-transform: uppercase;
    letter-spacing: 0.5pt;
  }
  tr.even { background: #f8fafc; }
  tr.odd { background: #fff; }

  /* ── Figures ────────────────────────────────────────── */
  figure {
    margin: 20pt 0;
    text-align: center;
    page-break-inside: avoid;
  }
  figure img {
    max-width: 100%;
    border: 1px solid #e2e8f0;
    border-radius: 6pt;
    box-shadow: 0 4px 16px rgba(0,0,0,0.08);
  }
  figure figcaption {
    font-size: 10pt;
    font-style: italic;
    color: #475569;
    margin-top: 8pt;
    text-align: center;
    line-height: 1.5;
  }

  /* ── Lists ──────────────────────────────────────────── */
  ol {
    margin: 10pt 0 10pt 30pt;
    font-size: 11.5pt;
  }
  ol li {
    margin: 6pt 0;
    text-align: justify;
  }

  /* ── Title Page ─────────────────────────────────────── */
  .title-page {
    text-align: center;
    padding: 80pt 20pt 60pt;
    page-break-after: always;
  }
  .title-page h1 {
    font-size: 15pt;
    color: #64748b;
    font-weight: 400;
    text-transform: uppercase;
    letter-spacing: 4pt;
    margin-bottom: 30pt;
    border: none;
  }
  .title-page .chapter-num {
    font-size: 72pt;
    font-weight: 700;
    color: #6366f1;
    line-height: 1;
  }
  .title-page .chapter-title {
    font-size: 24pt;
    font-weight: 700;
    color: #0f172a;
    margin: 16pt 0 30pt;
  }
  .title-page .subtitle {
    font-size: 13pt;
    color: #64748b;
    font-style: italic;
    max-width: 400pt;
    margin: 0 auto;
    line-height: 1.6;
  }
  .title-page .separator {
    width: 80pt;
    height: 3pt;
    background: #6366f1;
    margin: 30pt auto;
    border-radius: 2pt;
  }
  .title-page .meta {
    font-size: 10pt;
    color: #94a3b8;
    margin-top: 40pt;
  }

  .img-placeholder {
    padding: 40pt;
    background: #f1f5f9;
    color: #94a3b8;
    border: 2px dashed #cbd5e1;
    border-radius: 6pt;
    font-style: italic;
  }
</style>
</head>
<body>

<!-- ── Title Page ────────────────────────────────────────── -->
<div class="title-page">
  <h1 style="border:none; page-break-before: avoid;">ONYX CTI Platform — Mémoire PFE</h1>
  <div class="separator"></div>
  <div class="chapter-num">4</div>
  <div class="chapter-title">Validation Fonctionnelle, Restitution et Évaluation</div>
  <div class="separator"></div>
  <div class="subtitle">
    Démonstration opérationnelle de la plateforme souveraine de renseignement
    sur les cybermenaces : interfaces, performances et interopérabilité.
  </div>
  <div class="meta">
    Généré automatiquement par ONYX Build System — ${new Date().toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' })}
  </div>
</div>

<!-- ── Content ───────────────────────────────────────────── -->
${bodyHtml}

</body>
</html>`;

// ── Write HTML and render PDF ───────────────────────────────────────────────
const htmlPath = path.join(ROOT, 'chapitre4_complet.html');
fs.writeFileSync(htmlPath, html, 'utf-8');
console.log('HTML written:', htmlPath);

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  // Load from file URL to preserve UTF-8 encoding
  const fileUrl = 'file:///' + htmlPath.replace(/\\/g, '/');
  await page.goto(fileUrl, { waitUntil: 'networkidle' });
  await page.waitForTimeout(3000);

  const pdfPath = path.join(ROOT, 'Chapitre4_Validation_Fonctionnelle.pdf');
  await page.pdf({
    path: pdfPath,
    format: 'A4',
    margin: { top: '25mm', bottom: '30mm', left: '25mm', right: '20mm' },
    printBackground: true,
    displayHeaderFooter: true,
    headerTemplate: '<div style="font-size:8px; color:#94a3b8; width:100%; text-align:center; font-family:sans-serif; padding:5px 0;">ONYX CTI Platform — Chapitre 4 : Validation Fonctionnelle</div>',
    footerTemplate: '<div style="font-size:8px; color:#94a3b8; width:100%; text-align:center; font-family:sans-serif; padding:5px 0;">Page <span class="pageNumber"></span> / <span class="totalPages"></span></div>',
  });

  console.log('PDF generated:', pdfPath);
  await browser.close();
})();

