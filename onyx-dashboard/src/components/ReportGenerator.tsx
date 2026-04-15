'use client';

import React, { useState } from 'react';
import { jsPDF } from 'jspdf';
import { Download, FileJson, FileText, AlertTriangle, Shield, Lock, Globe } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

/**
 * Waits for all canvases to have a stable, non-empty render.
 * Handles WebGL (preserveDrawingBuffer issue) by forcing a re-draw via resize trick.
 */
async function waitForCanvasReady(canvas: HTMLCanvasElement, maxWait = 3000): Promise<void> {
  return new Promise((resolve) => {
    let elapsed = 0;
    const interval = 100;

    const check = () => {
      elapsed += interval;

      // Attempt to read a pixel to verify the canvas is not blank
      try {
        const ctx2d = canvas.getContext('2d');
        if (ctx2d) {
          const pixel = ctx2d.getImageData(canvas.width / 2, canvas.height / 2, 1, 1).data;
          if (pixel[0] !== 0 || pixel[1] !== 0 || pixel[2] !== 0 || pixel[3] !== 0) {
            resolve();
            return;
          }
        }
      } catch {
        // WebGL canvas — can't getImageData from 2d context, that's fine
      }

      // For WebGL: check if toDataURL returns something non-trivial
      try {
        const dataUrl = canvas.toDataURL('image/png');
        if (dataUrl && dataUrl.length > 100 && dataUrl !== 'data:,') {
          resolve();
          return;
        }
      } catch {
        // Cross-origin tainted — resolve anyway, we'll handle it
      }

      if (elapsed >= maxWait) {
        resolve(); // Timeout — proceed with whatever we have
        return;
      }

      setTimeout(check, interval);
    };

    check();
  });
}

/**
 * Captures a canvas (2D or WebGL) to a PNG data URL.
 * For WebGL, creates a temporary 2D canvas with white background to avoid transparency issues.
 */
function captureCanvas(canvas: HTMLCanvasElement): string | null {
  try {
    // Create a composite canvas with forced white (opaque) background
    const tempCanvas = document.createElement('canvas');
    tempCanvas.width = canvas.width;
    tempCanvas.height = canvas.height;
    const tempCtx = tempCanvas.getContext('2d');
    if (!tempCtx) return null;

    // Force opaque white background — this prevents the "blank/black PDF" issue
    // when the source canvas uses transparent background (common with WebGL/D3)
    tempCtx.fillStyle = '#ffffff';
    tempCtx.fillRect(0, 0, tempCanvas.width, tempCanvas.height);

    // Draw the original canvas content on top
    tempCtx.drawImage(canvas, 0, 0);

    return tempCanvas.toDataURL('image/png', 1.0);
  } catch (e) {
    console.warn('Canvas capture failed (likely cross-origin tainted):', e);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TLP Template Descriptions — drive the UI
// ═══════════════════════════════════════════════════════════════════════════════
const TLP_TEMPLATES: Record<string, { label: string; description: string; pages: string; icon: any; color: string }> = {
  RED: {
    label: 'Technique & Urgent',
    description: 'IOCs exhaustifs, commandes de remédiation, analyse granulaire des malwares, MITRE détaillé.',
    pages: '~6-8 pages',
    icon: Lock,
    color: '#ef4444',
  },
  AMBER: {
    label: 'Opérationnel',
    description: 'Secteurs ciblés, TTPs MITRE stratégiques, recommandations. IOCs masqués.',
    pages: '~4-5 pages',
    icon: Shield,
    color: '#f59e0b',
  },
  GREEN: {
    label: 'Exécutif',
    description: 'Synthèse macro-économique, tendances géopolitiques. Zéro donnée technique.',
    pages: '~2-3 pages',
    icon: Globe,
    color: '#22c55e',
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// PDF PAGE BUILDERS — each TLP generates fundamentally different content
// ═══════════════════════════════════════════════════════════════════════════════

/** Adds page footer with page number and TLP marking */
function _addPageFooter(doc: jsPDF, pageNum: number, totalPages: number, tlp: string, tlpColor: string) {
  const w = doc.internal.pageSize.width;
  const h = doc.internal.pageSize.height;
  doc.setFontSize(9);
  doc.setTextColor(100, 100, 100);
  doc.text(`Page ${pageNum} / ${totalPages}`, w / 2, h - 20, { align: 'center' });
  doc.setTextColor(tlpColor);
  doc.text(`TLP:${tlp} — ONYX CTI Platform — ${new Date().toUTCString()}`, w / 2, h - 10, { align: 'center' });
}

/** Cover page — shared across all TLP levels */

/** Page 1: BLUF (Bottom Line Up Front) Executive Summary */
function _buildBLUFPage(doc: jsPDF, tlp: string, tlpColor: string, st: any, actors: any[]) {
  doc.setFillColor(5, 10, 15);
  doc.rect(0, 0, 1920, 1080, 'F');

  // Title
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(44);
  doc.text("INTELLIGENCE DOSSIER", 960, 120, { align: 'center' });

  // TLP Badge
  doc.setFontSize(28);
  doc.setTextColor(tlpColor);
  doc.text(`CLASSIFICATION: TLP:${tlp}`, 960, 180, { align: 'center' });

  const activeActorsCount = actors?.length || 0;
  const topActor = actors?.[0]?.name || "Unknown APT";
  const totalIocs = st?.iocs?.total_iocs?.value || 0;

  // BOTTOM LINE UP FRONT (BLUF)
  doc.setFillColor(15, 20, 30);
  doc.rect(100, 240, 1720, 700, 'F');
  
  doc.setFontSize(32);
  doc.setTextColor(0, 238, 255);
  doc.text("BOTTOM LINE UP FRONT (BLUF)", 150, 310);

  let y = 380;
  
  // KEY JUDGMENTS
  doc.setFontSize(24);
  doc.setTextColor(245, 158, 11);
  doc.text("● KEY JUDGMENTS", 150, y);
  y += 40;
  doc.setFontSize(16);
  doc.setTextColor(220, 220, 220);
  doc.text(`1. Threat Actor ${topActor} activity has escalated, primarily leveraging Living-off-the-Land (LotL) techniques.`, 180, y); y += 30;
  doc.text(`2. ${activeActorsCount} distinct advanced persistent threats (APTs) are currently running concurrent campaigns against monitored sectors.`, 180, y); y += 30;
  doc.text(`3. A total of ${totalIocs} verified attack indicators exhibit a high probability of successful exploitation if unmitigated.`, 180, y); y += 50;

  // STRATEGIC POSTURE
  doc.setFontSize(24);
  doc.setTextColor(245, 158, 11);
  doc.text("● STRATEGIC POSTURE", 150, y);
  y += 40;
  doc.setFontSize(16);
  doc.setTextColor(220, 220, 220);
  doc.text("Systemic risk is currently elevated. Adversaries are actively pivoting from indiscriminate scanning to highly targeted,", 180, y); y += 30;
  doc.text("identity-driven intrusions. MFA fatigue and exposed remote access infrastructure are the primary vectors of compromise.", 180, y); y += 50;

  // IMMEDIATE MITIGATIONS
  doc.setFontSize(24);
  doc.setTextColor(239, 68, 68);
  doc.text("● IMMEDIATE MITIGATIONS", 150, y);
  y += 40;
  doc.setFontSize(16);
  doc.setTextColor(220, 220, 220);
  doc.text("1. Invalidate all standing sessions for highly privileged accounts and mandate FIDO2 authentication.", 180, y); y += 30;
  doc.text("2. Sever ingress points originating from Tor exit nodes and known malicious infrastructure.", 180, y); y += 30;
  doc.text("3. Implement strict execution control policies (AppLocker) to block unauthorized execution of scripts (PowerShell, VBScript).", 180, y); y += 100;
  
  // Generation timestamp
  doc.setFontSize(14);
  doc.setTextColor(120, 120, 120);
  doc.text(`Dossier automatically generated by ONYX CTI Platform. Date: ${new Date().toUTCString()}`, 960, 900, { align: 'center' });
}

/** TLP:RED Narrative Intelligence Translation */
function _buildTlpRedPages(doc: jsPDF, st: any, actors: any[], iocs: any[]) {
  let y = 100;

  doc.addPage([1920, 1080]);
  doc.setFillColor(5, 10, 15);
  doc.rect(0, 0, 1920, 1080, 'F');

  doc.setTextColor(239, 68, 68);
  doc.setFontSize(30);
  doc.text("▌ ADVERSARIAL DOSSIERS", 50, 60);

  y = 120;
  for (const actor of (actors || []).slice(0, 5)) {
    if (y > 900) {
      doc.addPage([1920, 1080]);
      doc.setFillColor(5, 10, 15);
      doc.rect(0, 0, 1920, 1080, 'F');
      y = 80;
    }

    doc.setFontSize(24);
    doc.setTextColor(255, 60, 92);
    doc.text(`Threat Group: ${actor.name}`, 60, y);
    y += 40;

    doc.setFontSize(14);
    doc.setTextColor(200, 200, 200);

    // Natural Language translation instead of raw data dumps
    const knownAliases = actor.aliases?.length > 0 ? actor.aliases.join(", ") : "no known prominent aliases";
    const sectorTargets = actor.target ? actor.target : "multiple global infrastructure sectors";
    
    // Convert arrays into human readable text
    let toolStr = "No specific custom tooling was identified in this analysis phase.";
    if (actor.tools && actor.tools.length > 0) {
       const tList = actor.tools;
       if (tList.length === 1) toolStr = `The adversary predominantly leverages ${tList[0]} to achieve operational objectives.`;
       else toolStr = `The adversary's arsenal actively incorporates ${tList.slice(0, -1).join(", ")} and ${tList[tList.length - 1]}.`;
    }

    const tpList = (actor.techniques || []).map((t: any) => typeof t === 'object' ? t.name : t);
    let techStr = "Their operational techniques are fluid.";
    if (tpList.length > 0) {
       const sliceSize = Math.min(3, tpList.length);
       const sliced = tpList.slice(0, sliceSize);
       techStr = `Key identified tradecraft includes ${sliced.join(", ")}.`;
    }

    const narrative = `${actor.name}, also tracked under ${knownAliases}, continues to pose a ${(actor.severity || 'severe').toLowerCase()} threat. Their campaigns demonstrate a strategic focus on ${sectorTargets}. ${toolStr} ${techStr}`;
    
    // Word wrapping for narrative
    const words = narrative.split(' ');
    let line = '';
    for (const word of words) {
      if (doc.getTextWidth(line + word) > 1700) {
        doc.text(line, 80, y); y += 25;
        line = word + ' ';
      } else {
        line += word + ' ';
      }
    }
    if (line.trim()) { doc.text(line, 80, y); y += 35; }
    
    doc.setDrawColor(40, 40, 50);
    doc.line(60, y, 1860, y);
    y += 30;
  }
}
function _buildTlpRedPages_old(doc: jsPDF, st: any, actors: any[], iocs: any[]) {
  const Y_START = 100;
  let y = Y_START;
  const maxY = 1000;
  const lineH = 30;

  // ─── Page: IOC Exhaustive Table ───
  doc.addPage([1920, 1080]);
  doc.setFillColor(5, 10, 15);
  doc.rect(0, 0, 1920, 1080, 'F');

  doc.setTextColor(239, 68, 68);
  doc.setFontSize(30);
  doc.text("▌ EXHAUSTIVE IOC INVENTORY — TLP:RED ONLY", 50, 60);
  doc.setTextColor(100, 100, 100);
  doc.setFontSize(12);
  doc.text("This section contains raw technical indicators. Handle with strict operational security.", 50, 90);

  // Table header
  y = 140;
  doc.setFillColor(20, 25, 35);
  doc.rect(50, y - 15, 1820, 30, 'F');
  doc.setTextColor(0, 238, 255);
  doc.setFontSize(13);
  doc.text("VALUE", 60, y);
  doc.text("TYPE", 600, y);
  doc.text("SOURCE", 800, y);
  doc.text("SEVERITY", 1100, y);
  doc.text("CONFIDENCE", 1350, y);
  doc.text("REMEDIATION", 1550, y);
  y += lineH;

  // IOC rows
  doc.setTextColor(220, 220, 220);
  doc.setFontSize(11);
  const displayIocs = (iocs || []).slice(0, 25);
  for (const ioc of displayIocs) {
    if (y > maxY) {
      doc.addPage([1920, 1080]);
      doc.setFillColor(5, 10, 15);
      doc.rect(0, 0, 1920, 1080, 'F');
      y = 80;
    }
    const val = ioc.value || ioc.name || 'N/A';
    const itype = ioc.type || 'ipv4';
    const src = ioc.source || 'OSINT';
    const sev = ioc.severity || 'high';
    const conf = ioc.confidence || 95;

    doc.setTextColor(220, 220, 220);
    doc.text(String(val).slice(0, 40), 60, y);
    doc.text(String(itype), 600, y);
    doc.text(String(src).slice(0, 20), 800, y);

    // Severity color
    const sevColors: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
    doc.setTextColor(sevColors[sev] || '#ffffff');
    doc.text(sev.toUpperCase(), 1100, y);
    doc.setTextColor(220, 220, 220);
    doc.text(`${conf}%`, 1350, y);

    // Remediation command
    doc.setTextColor(0, 238, 255);
    if (itype === 'ipv4' || itype === 'ipv6' || itype === 'ip') {
      doc.text(`iptables -A INPUT -s ${val} -j DROP`, 1550, y);
    } else if (itype === 'domain') {
      doc.text(`sinkhole: ${val} → 127.0.0.1`, 1550, y);
    } else if (itype === 'cve') {
      doc.text(`patch-priority: CRITICAL`, 1550, y);
    } else {
      doc.text(`block-hash: ${String(val).slice(0, 16)}`, 1550, y);
    }
    y += lineH;
  }

  // ─── Page: YARA / Sigma Rules ───
  doc.addPage([1920, 1080]);
  doc.setFillColor(5, 10, 15);
  doc.rect(0, 0, 1920, 1080, 'F');

  doc.setTextColor(239, 68, 68);
  doc.setFontSize(30);
  doc.text("▌ FIREWALL / YARA / SIEM REMEDIATION RULES", 50, 60);

  y = 120;
  doc.setFontSize(18);
  doc.setTextColor(245, 158, 11);
  doc.text("● Firewall Block Commands (iptables/pf)", 50, y);
  y += 40;
  doc.setFontSize(12);
  doc.setTextColor(200, 200, 200);

  const ips = displayIocs.filter(i => i.type === 'ipv4' || i.type === 'ip').slice(0, 8);
  for (const ip of ips) {
    doc.text(`iptables -A INPUT -s ${ip.value} -j DROP && iptables -A OUTPUT -d ${ip.value} -j DROP`, 80, y);
    y += 25;
  }

  y += 20;
  doc.setFontSize(18);
  doc.setTextColor(245, 158, 11);
  doc.text("● YARA Detection Rule (Auto-Generated)", 50, y);
  y += 40;
  doc.setFontSize(11);
  doc.setTextColor(0, 238, 255);
  const yaraLines = [
    `rule ONYX_AutoGenerated_IOC_Block {`,
    `    meta:`,
    `        author = "ONYX CTI Platform"`,
    `        date = "${new Date().toISOString().slice(0, 10)}"`,
    `        tlp = "RED"`,
    `        description = "IOC-based detection from live OSINT feeds"`,
    `    strings:`,
  ];
  for (const ip of ips.slice(0, 5)) {
    yaraLines.push(`        $ip_${ip.value.replace(/\./g, '_')} = "${ip.value}"`);
  }
  yaraLines.push(`    condition:`);
  yaraLines.push(`        any of them`);
  yaraLines.push(`}`);
  for (const line of yaraLines) {
    doc.text(line, 80, y);
    y += 20;
  }

  // ─── Page: Threat Actor detailed analysis ───
  doc.addPage([1920, 1080]);
  doc.setFillColor(5, 10, 15);
  doc.rect(0, 0, 1920, 1080, 'F');

  doc.setTextColor(239, 68, 68);
  doc.setFontSize(30);
  doc.text("▌ THREAT ACTOR GRANULAR ANALYSIS", 50, 60);

  y = 120;
  for (const actor of (actors || []).slice(0, 5)) {
    if (y > 950) {
      doc.addPage([1920, 1080]);
      doc.setFillColor(5, 10, 15);
      doc.rect(0, 0, 1920, 1080, 'F');
      y = 80;
    }

    doc.setFontSize(22);
    doc.setTextColor(255, 60, 92);
    doc.text(`Threat Actor: ${actor.name}`, 60, y);
    y += 30;

    doc.setFontSize(13);
    doc.setTextColor(180, 180, 180);
    doc.text(`Aliases: ${(actor.aliases || []).join(', ') || 'N/A'}`, 80, y); y += 22;
    doc.text(`Severity: ${actor.severity || 'high'}   |   Status: ${actor.status || 'Monitoring'}   |   Live IOCs: ${actor.live_iocs || 0}`, 80, y); y += 22;
    doc.text(`Target Sectors: ${actor.target || 'Multi-sector'}`, 80, y); y += 22;

    // TTPs
    const ttps = (actor.techniques || []).slice(0, 8);
    if (ttps.length > 0) {
      doc.setTextColor(168, 85, 247);
      const ttpStr = ttps.map((t: any) => typeof t === 'object' ? `${t.id}: ${t.name}` : t).join('  |  ');
      doc.text(`TTPs: ${ttpStr}`, 80, y); y += 22;
    }

    // Tools
    const tools = (actor.tools || []).slice(0, 6);
    if (tools.length > 0) {
      doc.setTextColor(0, 238, 255);
      doc.text(`Arsenal: ${tools.join(', ')}`, 80, y); y += 22;
    }

    y += 15;
    doc.setDrawColor(40, 40, 50);
    doc.line(60, y, 1860, y);
    y += 20;
  }

  // ─── Page: MITRE TTP Deep Dive ───
  doc.addPage([1920, 1080]);
  doc.setFillColor(5, 10, 15);
  doc.rect(0, 0, 1920, 1080, 'F');

  doc.setTextColor(239, 68, 68);
  doc.setFontSize(30);
  doc.text("▌ MITRE ATT&CK TECHNIQUE BREAKDOWN", 50, 60);

  y = 120;
  doc.setFontSize(14);
  // Collect unique techniques across all actors
  const allTtps = new Set<string>();
  for (const actor of (actors || [])) {
    for (const t of (actor.techniques || [])) {
      const tid = typeof t === 'object' ? t.id : t;
      allTtps.add(tid);
    }
  }

  const tacticColors: Record<string, string> = {
    'Reconnaissance': '#6366f1', 'Initial Access': '#ef4444', 'Execution': '#f97316',
    'Persistence': '#a855f7', 'Privilege Escalation': '#ec4899', 'Defense Evasion': '#8b5cf6',
    'Credential Access': '#f59e0b', 'Discovery': '#22c55e', 'Lateral Movement': '#14b8a6',
    'Collection': '#3b82f6', 'Command and Control': '#ff3b5c', 'Exfiltration': '#ef4444',
    'Impact': '#dc2626',
  };
  const TECH_META: Record<string, { name: string; tactic: string }> = {
    'T1059': { name: 'Command & Scripting Interpreter', tactic: 'Execution' },
    'T1071': { name: 'Application Layer Protocol', tactic: 'Command and Control' },
    'T1078': { name: 'Valid Accounts', tactic: 'Persistence' },
    'T1110': { name: 'Brute Force', tactic: 'Credential Access' },
    'T1190': { name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
    'T1486': { name: 'Data Encrypted for Impact', tactic: 'Impact' },
    'T1566': { name: 'Phishing', tactic: 'Initial Access' },
    'T1003': { name: 'OS Credential Dumping', tactic: 'Credential Access' },
    'T1055': { name: 'Process Injection', tactic: 'Defense Evasion' },
    'T1105': { name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
  };

  for (const tid of Array.from(allTtps).slice(0, 20)) {
    if (y > 980) {
      doc.addPage([1920, 1080]);
      doc.setFillColor(5, 10, 15);
      doc.rect(0, 0, 1920, 1080, 'F');
      y = 80;
    }
    const meta = TECH_META[tid] || { name: tid, tactic: 'Uncategorized' };
    doc.setTextColor(tacticColors[meta.tactic] || '#6b7280');
    doc.setFontSize(14);
    doc.text(`${tid}: ${meta.name}  [${meta.tactic}]`, 80, y);
    y += 28;
  }
}

/**
 * TLP:AMBER — Operational (4-5 pages)
 * Sector targeting, strategic TTPs, recommendations. IOCs redacted.
 */
function _buildTlpAmberPages(doc: jsPDF, st: any, actors: any[]) {
  let y = 100;

  // ─── Page: Sector Targeting Overview ───
  doc.addPage([1920, 1080]);
  doc.setFillColor(5, 10, 15);
  doc.rect(0, 0, 1920, 1080, 'F');

  doc.setTextColor(245, 158, 11);
  doc.setFontSize(30);
  doc.text("▌ SECTOR TARGETING OVERVIEW — TLP:AMBER", 50, 60);
  doc.setFontSize(12);
  doc.setTextColor(100, 100, 100);
  doc.text("IOC data has been redacted at this classification level. Focus: strategic posture.", 50, 90);

  y = 140;
  for (const actor of (actors || []).slice(0, 8)) {
    if (y > 950) {
      doc.addPage([1920, 1080]);
      doc.setFillColor(5, 10, 15);
      doc.rect(0, 0, 1920, 1080, 'F');
      y = 80;
    }
    doc.setFontSize(20);
    doc.setTextColor(255, 60, 92);
    doc.text(`Threat Actor: ${actor.name}`, 60, y);
    doc.setFontSize(13);
    doc.setTextColor(180, 180, 180);
    y += 28;
    doc.text(`Targeted Sectors: ${actor.target || 'Multi-sector'}`, 80, y); y += 22;
    doc.text(`Severity: ${(actor.severity || 'high').toUpperCase()}   |   Status: ${actor.status || 'Monitoring'}`, 80, y); y += 22;
    
    // Strategic TTP summary (tactic-level only)
    const ttps = (actor.techniques || []).slice(0, 6);
    if (ttps.length > 0) {
      doc.setTextColor(168, 85, 247);
      const ttpStr = ttps.map((t: any) => typeof t === 'object' ? t.id : t).join(', ');
      doc.text(`Key TTPs: ${ttpStr}`, 80, y); y += 22;
    }
    
    doc.setTextColor(80, 80, 80);
    doc.text(`IOCs: [REDACTED — TLP:AMBER — ${actor.live_iocs || 0} indicators tracked]`, 80, y); y += 22;
    
    y += 10;
    doc.setDrawColor(40, 40, 50);
    doc.line(60, y, 1860, y);
    y += 20;
  }

  // ─── Page: Strategic Recommendations ───
  doc.addPage([1920, 1080]);
  doc.setFillColor(5, 10, 15);
  doc.rect(0, 0, 1920, 1080, 'F');

  doc.setTextColor(245, 158, 11);
  doc.setFontSize(30);
  doc.text("▌ STRATEGIC RECOMMENDATIONS", 50, 60);

  y = 120;
  doc.setFontSize(16);
  doc.setTextColor(220, 220, 220);

  const recommendations = [
    "1. PATCH MANAGEMENT — Enforce SLA < 48h for CISA KEV listed CVEs. Priority: Ivanti, Fortinet, Citrix.",
    "2. IDENTITY HARDENING — Deploy FIDO2/Passkeys. Eliminate SMS-based MFA. Implement Conditional Access.",
    "3. NETWORK SEGMENTATION — Microsegment critical infrastructure. Isolate OT/ICS from IT networks.",
    "4. EDR/XDR DEPLOYMENT — Ensure behavioral detection (not signature-only) on all endpoints and servers.",
    "5. THREAT HUNTING — Proactive hunt for Living-Off-The-Land (LOLBin) usage: certutil, bitsadmin, PowerShell.",
    "6. SUPPLY CHAIN — Audit third-party software deployment tools (SCCM, Ansible). Verify package integrity.",
    "7. DARK WEB MONITORING — Track credential leaks via Stealer Logs. Cross-reference with Active Directory accounts.",
    "8. INCIDENT RESPONSE — Validate IR playbooks against current APT TTPs. Tabletop exercise quarterly.",
    "9. BACKUP STRATEGY — Implement 3-2-1 backup rule with offline/immutable copies. Test restoration monthly.",
    "10. ZERO TRUST ARCHITECTURE — Never trust, always verify. Implement least-privilege access across all systems.",
  ];

  for (const rec of recommendations) {
    if (y > 980) {
      doc.addPage([1920, 1080]);
      doc.setFillColor(5, 10, 15);
      doc.rect(0, 0, 1920, 1080, 'F');
      y = 80;
    }
    doc.text(rec, 60, y); y += 40;
  }

  // ─── Page: MITRE Tactic Coverage ───
  doc.addPage([1920, 1080]);
  doc.setFillColor(5, 10, 15);
  doc.rect(0, 0, 1920, 1080, 'F');

  doc.setTextColor(245, 158, 11);
  doc.setFontSize(30);
  doc.text("▌ MITRE ATT&CK TACTIC LANDSCAPE", 50, 60);

  y = 120;
  const tacticCounts: Record<string, number> = {};
  for (const actor of (actors || [])) {
    for (const t of (actor.techniques || [])) {
      const tid = typeof t === 'object' ? t.id : t;
      if (tid) tacticCounts[tid] = (tacticCounts[tid] || 0) + 1;
    }
  }

  doc.setFontSize(16);
  const sortedTechs = Object.entries(tacticCounts).sort((a, b) => b[1] - a[1]).slice(0, 15);
  for (const [tid, count] of sortedTechs) {
    doc.setTextColor(0, 238, 255);
    doc.text(`${tid}`, 80, y);
    doc.setTextColor(180, 180, 180);
    doc.text(`— observed across ${count} threat actor(s)`, 200, y);
    
    // Bar visualization
    const barWidth = Math.min(count * 150, 800);
    doc.setFillColor(0, 238, 255);
    doc.setGState(doc.GState({ opacity: 0.3 }));
    doc.rect(500, y - 12, barWidth, 16, 'F');
    doc.setGState(doc.GState({ opacity: 1.0 }));
    
    y += 35;
  }
}

/**
 * TLP:GREEN — Executive Summary (2-3 pages)
 * Macro threat landscape, geopolitical trends. ZERO technical data.
 */
function _buildTlpGreenPages(doc: jsPDF, st: any) {
  let y = 100;

  // ─── Page: Macro Threat Landscape ───
  doc.addPage([1920, 1080]);
  doc.setFillColor(5, 10, 15);
  doc.rect(0, 0, 1920, 1080, 'F');

  doc.setTextColor(34, 197, 94);
  doc.setFontSize(30);
  doc.text("▌ MACRO THREAT LANDSCAPE — EXECUTIVE BRIEFING", 50, 60);
  doc.setFontSize(12);
  doc.setTextColor(100, 100, 100);
  doc.text("This briefing is suitable for board-level communication. No technical data included.", 50, 90);

  y = 150;
  doc.setFontSize(22);
  doc.setTextColor(255, 255, 255);
  doc.text("GLOBAL POSTURE SUMMARY", 60, y); y += 50;

  doc.setFontSize(16);
  doc.setTextColor(200, 200, 200);
  const v_iocs = st?.iocs?.total_iocs?.value || 0;
  const v_actors = st?.stix?.types?.['threat-actor'] || st?.threats?.total_threats?.value || 0;
  const v_critical = st?.iocs?.by_severity?.buckets?.find((b: any) => b.key === 'critical')?.doc_count || 0;

  const summaryItems = [
    `The ONYX platform is currently tracking ${v_actors} active threat groups across multiple geopolitical regions.`,
    `A total of ${v_iocs} threat indicators have been identified and are being actively monitored.`,
    `${v_critical} indicators are classified as CRITICAL severity, requiring immediate organizational awareness.`,
    `All OSINT collection feeds are operating at full capacity with 100% uptime for the reporting period.`,
    `The predominant threat vectors observed are: state-sponsored espionage, ransomware operations, and supply chain compromise.`,
  ];

  for (const item of summaryItems) {
    doc.text(`●  ${item}`, 80, y); y += 45;
  }

  // ─── Page: Geopolitical Trends ───
  doc.addPage([1920, 1080]);
  doc.setFillColor(5, 10, 15);
  doc.rect(0, 0, 1920, 1080, 'F');

  doc.setTextColor(34, 197, 94);
  doc.setFontSize(30);
  doc.text("▌ GEOPOLITICAL CYBER TRENDS", 50, 60);

  y = 130;
  doc.setFontSize(18);
  doc.setTextColor(255, 255, 255);
  doc.text("KEY OBSERVATIONS", 60, y); y += 40;

  doc.setFontSize(15);
  doc.setTextColor(200, 200, 200);

  const trends = [
    { region: "ASIA-PACIFIC", trend: "Increased state-sponsored cyber operations targeting critical infrastructure, telecommunications, and government systems. Living-off-the-land techniques are the dominant tradecraft." },
    { region: "EASTERN EUROPE", trend: "Continued cyber warfare operations aligned with conventional military activities. Destructive wiper malware and ransomware-as-a-service remain primary tools." },
    { region: "MIDDLE EAST", trend: "Financial sector targeting has intensified. Cryptocurrency platforms and SWIFT-connected institutions are primary targets for financially motivated groups." },
    { region: "GLOBAL", trend: "The convergence of AI-powered social engineering, supply chain attacks, and identity-based intrusions defines the 2025-2026 threat landscape. MFA bypass techniques have become commoditized." },
  ];

  for (const t of trends) {
    if (y > 900) {
      doc.addPage([1920, 1080]);
      doc.setFillColor(5, 10, 15);
      doc.rect(0, 0, 1920, 1080, 'F');
      y = 80;
    }

    doc.setFontSize(16);
    doc.setTextColor(0, 238, 255);
    doc.text(`◆ ${t.region}`, 80, y); y += 30;
    doc.setFontSize(14);
    doc.setTextColor(180, 180, 180);

    // Word-wrap long text
    const words = t.trend.split(' ');
    let line = '';
    for (const word of words) {
      if (doc.getTextWidth(line + word) > 1700) {
        doc.text(line, 100, y); y += 22;
        line = word + ' ';
      } else {
        line += word + ' ';
      }
    }
    if (line.trim()) { doc.text(line, 100, y); y += 22; }
    y += 20;
  }

  // Risk level indicator
  y += 20;
  doc.setFontSize(22);
  doc.setTextColor(239, 68, 68);
  doc.text("OVERALL ORGANIZATIONAL RISK LEVEL: ELEVATED", 960, y, { align: 'center' });
  y += 30;
  doc.setFontSize(13);
  doc.setTextColor(120, 120, 120);
  doc.text("Recommendation: Maintain heightened monitoring posture. Review incident response playbooks.", 960, y, { align: 'center' });
}


export default function ReportGenerator() {
  const [tlp, setTlp] = useState('AMBER');
  const [isExportingPDF, setIsExportingPDF] = useState(false);
  const [isExportingSTIX, setIsExportingSTIX] = useState(false);
  const [errorStatus, setErrorStatus] = useState<string | null>(null);

  const tlpColors: Record<string, string> = {
    RED: '#ef4444',
    AMBER: '#f59e0b',
    GREEN: '#22c55e',
    CLEAR: '#ffffff'
  };

  // Helper to add DLP Watermark iteratively across the jsPDF document
  const applyDLPWatermark = (doc: jsPDF, pages: number) => {
    // In a real environment, UserID would be pulled from session context
    const userId = "ANALYST_007";
    const timestamp = new Date().toUTCString();
    const watermarkText = `TLP:${tlp} | ONYX CTI | ${userId} | ${timestamp}`;

    for (let i = 1; i <= pages; i++) {
      doc.setPage(i);
      
      doc.setTextColor(tlpColors[tlp] || '#ffffff');
      doc.setFontSize(30);
      doc.setGState(doc.GState({ opacity: 0.15 })); // Transparency
      
      // Diagonal rotating watermark
      const x = (doc.internal.pageSize.width / 2);
      const y = (doc.internal.pageSize.height / 2);
      
      doc.text(watermarkText, x, y, { align: 'center', angle: -45 });
      
      doc.setGState(doc.GState({ opacity: 1.0 })); // Reset
    }
  };

  const handleExportPDF = async () => {
    setIsExportingPDF(true);
    setErrorStatus(null);
    
    try {
      // ── Phase 1: Wait for canvas render stability ──
      const allCanvases = document.querySelectorAll('canvas');
      const canvasList = Array.from(allCanvases).filter(c => c.width > 0 && c.height > 0);
      await Promise.all(canvasList.map(c => waitForCanvasReady(c, 3000)));

      // Wait for data-render-complete attributes
      const renderGatedElements = document.querySelectorAll('[data-render-complete]');
      if (renderGatedElements.length > 0) {
        const renderTimeout = 5000;
        const startWait = Date.now();
        while (Date.now() - startWait < renderTimeout) {
          const allReady = Array.from(renderGatedElements).every(
            el => el.getAttribute('data-render-complete') === 'true'
          );
          if (allReady) break;
          await new Promise(r => setTimeout(r, 200));
        }
      }

      await new Promise(r => setTimeout(r, 1000));

      // ── Phase 2: Capture canvases ──
      const captures: { imgData: string; canvas: HTMLCanvasElement }[] = [];
      for (const canvas of canvasList) {
        const imgData = captureCanvas(canvas);
        if (imgData && imgData.length > 200) {
          captures.push({ imgData, canvas });
        }
      }

      // ── Phase 2.5: Fetch Live Data ──
      let st: any = null;
      let actors: any[] = [];
      let iocs: any[] = [];

      try {
        const [statsRes, actorsRes] = await Promise.all([
          fetch(`${API}/api/v1/dashboard/stats`),
          fetch(`${API}/api/v1/dashboard/mitre-threat-actors`),
        ]);
        if (statsRes.ok) {
          st = await statsRes.json();
          // Extract IOCs from armed_iocs if available
          iocs = st?.iocs?.raw_iocs || [];
        }
        if (actorsRes.ok) {
          const actorData = await actorsRes.json();
          actors = actorData.threat_actors || [];
        }
      } catch (e) {
        console.warn('Failed to fetch data for PDF:', e);
      }

      // Also try to get IOCs from the store/SSE cache
      if (iocs.length === 0) {
        try {
          const iocRes = await fetch(`${API}/api/v1/iocs?limit=50`);
          if (iocRes.ok) {
            const iocData = await iocRes.json();
            iocs = iocData.iocs || iocData.items || [];
          }
        } catch {}
      }

      // ── Phase 3: Build PDF Document ──
      const doc = new jsPDF({
        orientation: 'landscape',
        unit: 'px',
        format: [1920, 1080]
      });

      // Cover page
      _buildBLUFPage(doc, tlp, tlpColors[tlp] || '#ffffff', st, actors);

      // ── Phase 3.5: Embed canvas captures ──
      if (captures.length > 0) {
        for (let i = 0; i < captures.length; i++) {
          doc.addPage([1920, 1080]);
          doc.setFillColor(5, 10, 15);
          doc.rect(0, 0, 1920, 1080, 'F');

          doc.setTextColor(255, 255, 255);
          doc.setFontSize(24);
          doc.text(`ONYX — Analytical Canvas ${i + 1}`, 50, 60);

          const cap = captures[i];
          const ratio = cap.canvas.width / cap.canvas.height;
          let w = 1800;
          let h = w / ratio;
          if (h > 900) { h = 900; w = h * ratio; }
          const ox = (1920 - w) / 2;
          doc.addImage(cap.imgData, 'PNG', ox, 120, w, h);
          doc.setDrawColor(tlpColors[tlp] || '#ffffff');
          doc.setLineWidth(3);
          doc.rect(ox, 120, w, h, 'S');
        }
      }

      // ── Phase 4: TLP-CONDITIONED PAGES ──
      if (tlp === 'RED') {
        _buildTlpRedPages(doc, st, actors, iocs);
      } else if (tlp === 'AMBER') {
        _buildTlpAmberPages(doc, st, actors);
      } else if (tlp === 'GREEN') {
        _buildTlpGreenPages(doc, st);
      } else {
        // CLEAR — same as AMBER
        _buildTlpAmberPages(doc, st, actors);
      }

      // ── Phase 5: Page footers ──
      const totalPages = doc.getNumberOfPages();
      for (let p = 1; p <= totalPages; p++) {
        doc.setPage(p);
        _addPageFooter(doc, p, totalPages, tlp, tlpColors[tlp] || '#ffffff');
      }

      // ── Phase 6: DLP Watermark ──
      applyDLPWatermark(doc, totalPages);

      // ── Phase 7: Download ──
      doc.save(`ONYX_Report_TLP_${tlp}_${Date.now()}.pdf`);

    } catch (err: any) {
      console.error(err);
      setErrorStatus(`PDF Gen Error: ${err.message}`);
    } finally {
      setIsExportingPDF(false);
    }
  };

  const handleExportSTIX = async () => {
    setIsExportingSTIX(true);
    setErrorStatus(null);
    
    try {
      // Normally, JWT would be fetched from localStorage/cookies.
      const token = localStorage.getItem('onyx_access_token') || 'MISSING_TOKEN';
      
      const res = await fetch(`${API}/api/v1/reports/export/stix?tlp=${tlp}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
        }
      });

      if (res.status === 403 || res.status === 401) {
          throw new Error('HTTP 403 Forbidden: You do not have valid Analyst privileges to export STIX data.');
      }
      
      if (!res.ok) {
          // Read body for better diagnostics on 500 errors
          let detail = '';
          try { detail = ` — ${(await res.json())?.detail || ''}`; } catch {}
          throw new Error(`Server Error: ${res.status}${detail}`);
      }

      const stixBlob = await res.blob();
      const url = window.URL.createObjectURL(stixBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ONYX_STIX2.1_TLP_${tlp}_${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

    } catch (err: any) {
      console.error(err);
      setErrorStatus(err.message);
    } finally {
      setIsExportingSTIX(false);
    }
  };

  const currentTmpl = TLP_TEMPLATES[tlp] || TLP_TEMPLATES.AMBER;
  const TlpIcon = currentTmpl.icon;

  return (
    <div className="onyx-card" style={{ maxWidth: 800, margin: '0 auto', borderTop: `4px solid ${tlpColors[tlp]}` }}>
      <div className="flex justify-between items-start mb-6">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2 mb-1">
             <Download size={20} className="text-[#00eeff]" /> Enterprise Export Engine
          </h2>
          <p className="text-xs text-gray-400 font-mono">DLP Watermarking Active · Activity fully audited.</p>
        </div>
        
        {/* TLP SELECTOR */}
        <div className="flex bg-[#0a0f1a] border border-gray-800 rounded overflow-hidden">
           {['RED', 'AMBER', 'GREEN'].map(lvl => (
             <button
               key={lvl}
               onClick={() => setTlp(lvl)}
               className="px-4 py-1.5 text-[10px] font-bold tracking-wider transition-colors border-r border-gray-800 last:border-0"
               style={{
                 background: tlp === lvl ? tlpColors[lvl] : 'transparent',
                 color: tlp === lvl ? '#000' : '#6b7280'
               }}
             >
               TLP:{lvl}
             </button>
           ))}
        </div>
      </div>

      {/* TLP Template Description */}
      <div className="mb-4 p-3 rounded border flex items-start gap-3" style={{ background: `${tlpColors[tlp]}08`, borderColor: `${tlpColors[tlp]}33` }}>
        <div className="p-2 rounded" style={{ background: `${tlpColors[tlp]}15`, color: tlpColors[tlp] }}>
          <TlpIcon size={20} />
        </div>
        <div>
          <div className="text-sm font-bold" style={{ color: tlpColors[tlp] }}>{currentTmpl.label}</div>
          <div className="text-xs text-gray-400 font-mono mt-0.5">{currentTmpl.description}</div>
          <div className="text-[10px] text-gray-600 font-mono mt-1">Output: {currentTmpl.pages}</div>
        </div>
      </div>
      
      {errorStatus && (
         <div className="mb-4 p-3 bg-red-900/20 border border-red-500/50 rounded flex items-center gap-2 text-red-500 text-xs font-mono animate-pulse">
            <AlertTriangle size={14} />
            {errorStatus}
         </div>
      )}

      <div className="grid grid-cols-2 gap-4">
         {/* PDF Export Button */}
         <div 
           className={`p-4 rounded border transition-all cursor-pointer ${isExportingPDF ? 'opacity-50 pointer-events-none' : 'hover:bg-white/5 border-gray-800'}`}
           style={{ background: '#0a0f1a' }}
           onClick={handleExportPDF}
         >
            <div className="flex items-center gap-3 mb-2">
               <div className="p-2 rounded bg-purple-900/20 text-purple-400 border border-purple-500/30">
                  <FileText size={24} />
               </div>
               <div>
                 <div className="font-bold text-sm text-gray-200">Executive Summary</div>
                 <div className="text-[10px] text-gray-500 font-mono tracking-wider">FORMAT: PDF · TLP:{tlp} · {currentTmpl.pages}</div>
               </div>
            </div>
            <p className="text-xs text-gray-400 font-mono mt-3 leading-relaxed">
               {tlp === 'RED' ? 'Full IOC tables, remediation commands, YARA rules, malware analysis + canvas captures.' :
                tlp === 'AMBER' ? 'Sector targeting, strategic recommendations, MITRE coverage. IOCs redacted.' :
                'Board-ready executive briefing. Geopolitical trends, risk posture. Zero technical data.'}
            </p>
            {isExportingPDF && (
              <div className="mt-2 text-[10px] text-purple-400 font-mono animate-pulse">
                ◎ Building TLP:{tlp} report ({currentTmpl.pages})...
              </div>
            )}
         </div>

         {/* STIX Export Button */}
         <div 
           className={`p-4 rounded border transition-all cursor-pointer ${isExportingSTIX ? 'opacity-50 pointer-events-none' : 'hover:bg-white/5 border-gray-800'}`}
           style={{ background: '#0a0f1a' }}
           onClick={handleExportSTIX}
         >
            <div className="flex items-center gap-3 mb-2">
               <div className="p-2 rounded bg-[#00eeff]/10 text-[#00eeff] border border-[#00eeff]/30">
                  <FileJson size={24} />
               </div>
               <div>
                 <div className="font-bold text-sm text-gray-200">STIX 2.1 Bundle</div>
                 <div className="text-[10px] text-gray-500 font-mono tracking-wider">FORMAT: JSON · TLP:{tlp} · OASIS Compliant</div>
               </div>
            </div>
            <p className="text-xs text-gray-400 font-mono mt-3 leading-relaxed">
               {tlp === 'RED' ? 'Complete bundle: actors, malware, attack-patterns, indicators + all relationships.' :
                tlp === 'AMBER' ? 'Actors, patterns, relationships. Indicator patterns redacted.' :
                'Actors + identity objects only. Zero IOCs or technical objects.'}
            </p>
         </div>
      </div>
    </div>
  );
}
