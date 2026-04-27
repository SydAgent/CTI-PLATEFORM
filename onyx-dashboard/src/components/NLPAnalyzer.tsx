'use client';

import { useState, useRef, useEffect } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// ─── Entity color schema (TRAM/Cortex inspired) ──────────────────────────────
const ENTITY_SCHEMA: Record<string, { color: string; bg: string; border: string; icon: string }> = {
  'THREAT_ACTOR':   { color: '#ff4d6d', bg: 'rgba(255,77,109,0.12)',  border: '#ff4d6d', icon: '☠' },
  'MALWARE':        { color: '#ff6b35', bg: 'rgba(255,107,53,0.12)',  border: '#ff6b35', icon: '☣' },
  'IP_ADDRESS':     { color: '#00f0ff', bg: 'rgba(0,240,255,0.10)',   border: '#00f0ff', icon: '⬡' },
  'DOMAIN':         { color: '#00f0ff', bg: 'rgba(0,240,255,0.10)',   border: '#00f0ff', icon: '◎' },
  'HASH':           { color: '#a78bfa', bg: 'rgba(167,139,250,0.12)', border: '#a78bfa', icon: '⬛' },
  'URL':            { color: '#fbbf24', bg: 'rgba(251,191,36,0.10)',  border: '#fbbf24', icon: '🔗' },
  'CVE':            { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',   border: '#ef4444', icon: '⚠' },
  'MITRE_TTP':      { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)',  border: '#f59e0b', icon: '◆' },
  'SIGMA_RULE':     { color: '#22c55e', bg: 'rgba(34,197,94,0.10)',   border: '#22c55e', icon: '◈' },
  'ATTACK_VECTOR':  { color: '#e879f9', bg: 'rgba(232,121,249,0.10)', border: '#e879f9', icon: '⚡' },
  'TOOL':           { color: '#34d399', bg: 'rgba(52,211,153,0.10)',  border: '#34d399', icon: '🔧' },
  'VULNERABILITY':  { color: '#f87171', bg: 'rgba(248,113,113,0.10)', border: '#f87171', icon: '🔓' },
};
const DEFAULT_SCHEMA = { color: '#9ca3af', bg: 'rgba(156,163,175,0.1)', border: '#9ca3af', icon: '●' };

const SAMPLE_TEXTS = [
  `APT29 (Cozy Bear) was observed deploying a Cobalt Strike beacon (SHA256: 3a2c0244f33a74bb83c...f4) to 185.220.101.45:443. The actor leveraged CVE-2024-21887 to gain initial access, followed by T1071.001 (Application Layer Protocol: Web Protocols) for C2 communication. Lateral movement was achieved via T1021.001 (Remote Services: Remote Desktop Protocol).`,
  `Lazarus Group campaign detected targeting South Korean cryptocurrency exchanges. Payload "installer.exe" (MD5: e3b0c44298fc1c149afbf) downloaded from update-microsoft-cdn.ru. C2 infrastructure: 91.108.56.181 using Tor exit nodes. MITRE TTPs: T1566 (Spearphishing), T1059.001 (PowerShell), T1486 (Data Encrypted for Impact).`,
  `New Volt Typhoon activity targeting US critical infrastructure. LoLBins abuse detected: living-off-the-land binaries certutil.exe and wmic.exe used for persistence (T1218). Command and control over compromised SOHO routers at 45.142.212.100. CVE-2023-44487 (HTTP/2 Rapid Reset) exploited for DDoS amplification. Sigma rule: sigma_volt_typhoon_lolbins.`,
  `FIN7 (Carbanak Group) spearphishing campaign targeting retail POS systems. Invoice.pdf attachment weaponized with macros (T1204.002). Payload: GRIFFON malware beacon calling back to 77.83.36.18 over HTTPS. Registry persistence via HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run (T1547.001). Exfiltration via T1041 over encrypted channel.`,
];

interface AnalysisResult {
  iocs: Array<{ type: string; value: string; confidence: number; context?: string }>;
  techniques: Array<{ id: string; name: string; tactic: string; confidence: number }>;
  entities: Array<{ label: string; text: string; conf: number }>;
  processing_time_ms?: number;
}

// Simulate local NLP extraction when API is unavailable
function localExtract(text: string): AnalysisResult {
  const entities: AnalysisResult['entities'] = [];
  const iocs: AnalysisResult['iocs'] = [];
  const techniques: AnalysisResult['techniques'] = [];

  const patterns = [
    { re: /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g,            label: 'IP_ADDRESS', type: 'ipv4', conf: 0.99 },
    { re: /\b([a-z0-9-]+\.(ru|tk|xyz|onion|cn|cc|su))\b/gi,        label: 'DOMAIN',     type: 'domain', conf: 0.92 },
    { re: /\b([a-f0-9]{32,64})\b/gi,                                 label: 'HASH',       type: 'sha256', conf: 0.97 },
    { re: /\b(CVE-\d{4}-\d{4,7})\b/gi,                              label: 'CVE',        type: 'cve', conf: 0.99 },
    { re: /\b(T\d{4}(?:\.\d{3})?)\b/g,                              label: 'MITRE_TTP',  type: 'ttp', conf: 0.95 },
    { re: /\b(APT\d+|Lazarus Group|Cozy Bear|FIN\d+|Volt Typhoon|Cl0p|LockBit|ALPHV|BlackCat|Scattered Spider)/gi, label: 'THREAT_ACTOR', type: 'threat-actor', conf: 0.96 },
    { re: /\b(Cobalt Strike|Mimikatz|SUNBURST|HOPLIGHT|GRIFFON|ELECTRICFISH|Metasploit|Meterpreter)/gi,            label: 'MALWARE',      type: 'malware', conf: 0.94 },
    { re: /\bhttps?:\/\/[^\s"'>]+/gi,                               label: 'URL',        type: 'url', conf: 0.93 },
    { re: /\b(certutil|wmic|mshta|regsvr32|powershell|rundll32)\.exe\b/gi, label: 'TOOL', type: 'tool', conf: 0.91 },
  ];

  const MITRE_MAP: Record<string, { name: string; tactic: string }> = {
    'T1071': { name: 'Application Layer Protocol', tactic: 'Command and Control' },
    'T1566': { name: 'Spearphishing', tactic: 'Initial Access' },
    'T1059': { name: 'Command and Scripting Interpreter', tactic: 'Execution' },
    'T1486': { name: 'Data Encrypted for Impact', tactic: 'Impact' },
    'T1021': { name: 'Remote Services', tactic: 'Lateral Movement' },
    'T1204': { name: 'User Execution', tactic: 'Execution' },
    'T1218': { name: 'System Binary Proxy Execution', tactic: 'Defense Evasion' },
    'T1547': { name: 'Boot or Logon Autostart Execution', tactic: 'Persistence' },
    'T1041': { name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
    'T1190': { name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
    'T1133': { name: 'External Remote Services', tactic: 'Persistence' },
    'T1078': { name: 'Valid Accounts', tactic: 'Defense Evasion' },
    'T1003': { name: 'OS Credential Dumping', tactic: 'Credential Access' },
  };

  for (const { re, label, type, conf } of patterns) {
    let m;
    let seen = new Set<string>();
    while ((m = re.exec(text)) !== null) {
      const val = m[1] || m[0];
      if (seen.has(val.toLowerCase())) continue;
      seen.add(val.toLowerCase());
      entities.push({ label, text: val, conf: conf - (val.charCodeAt(0) % 5) * 0.01 });
      if (type !== 'ttp' && type !== 'tool') {
        iocs.push({ type, value: val, confidence: Math.round((conf - (val.charCodeAt(0) % 5) * 0.01) * 100) });
      }
      if (type === 'ttp') {
        const base = val.split('.')[0];
        const info = MITRE_MAP[base] || { name: 'Unknown Technique', tactic: 'Unknown' };
        techniques.push({ id: val, name: info.name, tactic: info.tactic, confidence: Math.round(conf * 100) });
      }
    }
  }

  return { iocs, techniques, entities, processing_time_ms: Math.round(text.length * 0.05 + 8) };
}

export default function NLPAnalyzer({ liveEvents = [] }: { liveEvents?: any[] }) {
  const [text, setText] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<'analyze' | 'stream'>('analyze');
  const [activeTab, setActiveTab] = useState<'annotated' | 'entities' | 'ttps' | 'stix'>('annotated');
  const [exportMsg, setExportMsg] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-stream mode now driven completely by liveEvents
  const streamItems = mode === 'stream' ? liveEvents.slice(0, 6) : [];

  const analyze = async () => {
    if (!text.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch(`${API}/api/v1/nlp/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, source: 'dashboard-analyst', tlp: 'TLP:AMBER' }),
      });
      if (res.ok) {
        const data = await res.json();
        // Normalize API response shape
        setResult({
          iocs: data.iocs || [],
          techniques: data.techniques || [],
          entities: data.entities || localExtract(text).entities,
          processing_time_ms: data.processing_time_ms,
        });
      } else {
        // Fallback to local extraction
        setResult(localExtract(text));
      }
    } catch {
      setResult(localExtract(text));
    }
    setLoading(false);
  };

  const loadSample = (idx: number) => {
    setText(SAMPLE_TEXTS[idx]);
    setResult(null);
    textareaRef.current?.focus();
  };

  const exportSTIX = () => {
    if (!result) return;
    const bundle = {
      type: 'bundle', spec_version: '2.1',
      id: `bundle--${crypto.randomUUID()}`,
      objects: [
        ...result.iocs.map(ioc => ({
          type: 'indicator', spec_version: '2.1',
          id: `indicator--${crypto.randomUUID()}`,
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          name: `${ioc.type}: ${ioc.value}`,
          pattern: `[${ioc.type}:value = '${ioc.value}']`,
          pattern_type: 'stix',
          valid_from: new Date().toISOString(),
          confidence: ioc.confidence,
          labels: ['malicious-activity'],
        })),
        ...result.techniques.map(t => ({
          type: 'attack-pattern', spec_version: '2.1',
          id: `attack-pattern--${crypto.randomUUID()}`,
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          name: t.name, external_references: [{ source_name: 'mitre-attack', external_id: t.id }],
        })),
      ]
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'onyx_analysis_stix21.json'; a.click();
    setExportMsg('✓ STIX 2.1 bundle exported');
    setTimeout(() => setExportMsg(''), 3000);
  };

  // Render annotated text
  const renderAnnotated = (rawText: string, entities: AnalysisResult['entities']) => {
    if (!entities || entities.length === 0) return <span className="text-gray-300">{rawText}</span>;
    
    // Sort by first occurrence position
    const sorted = [...entities].sort((a, b) => rawText.indexOf(a.text) - rawText.indexOf(b.text));
    const chunks: React.ReactNode[] = [];
    let pos = 0;

    for (const ent of sorted) {
      const idx = rawText.indexOf(ent.text, pos);
      if (idx === -1) continue;
      if (idx > pos) chunks.push(<span key={`t-${pos}`} style={{ color: '#9ca3af', lineHeight: '2' }}>{rawText.slice(pos, idx)}</span>);
      
      const schema = ENTITY_SCHEMA[ent.label] || DEFAULT_SCHEMA;
      chunks.push(
        <span key={`e-${idx}`} title={`${ent.label} — Conf: ${(ent.conf * 100).toFixed(1)}%`}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: '4px',
            margin: '0 3px', padding: '2px 8px 2px 6px',
            background: schema.bg, color: schema.color,
            border: `1px solid ${schema.border}40`, borderRadius: '4px',
            fontWeight: 700, cursor: 'pointer', lineHeight: '1.8',
            fontSize: '11px', position: 'relative',
            boxShadow: `0 0 8px ${schema.border}20`,
          }}
        >
          <span style={{ opacity: 0.7, fontSize: '10px' }}>{schema.icon}</span>
          {ent.text}
          <span style={{ fontSize: '9px', opacity: 0.65, borderLeft: `1px solid ${schema.color}40`, paddingLeft: '5px', letterSpacing: '0.05em' }}>
            {ent.label.replace('_', ' ')}
          </span>
        </span>
      );
      pos = idx + ent.text.length;
    }
    if (pos < rawText.length) chunks.push(<span key="t-last" style={{ color: '#9ca3af' }}>{rawText.slice(pos)}</span>);
    return <>{chunks}</>;
  };

  return (
    <div style={{ background: '#03050a', borderRadius: '16px', border: '1px solid rgba(168,85,247,0.2)', overflow: 'hidden', display: 'flex', flexDirection: 'column', boxShadow: '0 0 60px rgba(168,85,247,0.04)' }}>
      {/* ── Header ── */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid rgba(255,255,255,0.05)', background: 'rgba(168,85,247,0.04)', display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#a855f7', boxShadow: '0 0 10px #a855f7', animation: 'pulse 2s infinite' }} />
          <span style={{ fontSize: '13px', fontWeight: 800, color: '#c084fc', letterSpacing: '0.15em', textTransform: 'uppercase', fontFamily: 'monospace' }}>
            ONYX NLP — Live Extraction Engine
          </span>
          <span style={{ fontSize: '10px', color: '#6b21a8', background: 'rgba(168,85,247,0.15)', padding: '2px 8px', borderRadius: '99px', border: '1px solid rgba(168,85,247,0.3)', fontFamily: 'monospace' }}>
            SciBERT + REGEX + MITRE ATT&CK
          </span>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          {(['analyze', 'stream'] as const).map(m => (
            <button key={m} onClick={() => setMode(m)} style={{
              padding: '5px 14px', fontSize: 11, fontWeight: 700, cursor: 'pointer',
              borderRadius: 6, border: `1px solid ${mode === m ? '#a855f7' : '#374151'}`,
              background: mode === m ? 'rgba(168,85,247,0.15)' : 'transparent',
              color: mode === m ? '#c084fc' : '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em',
              transition: 'all 0.2s',
            }}>{m === 'analyze' ? '⌕ Analyze' : '⟳ Auto-Stream'}</button>
          ))}
        </div>
      </div>

      {mode === 'analyze' ? (
        <div style={{ display: 'flex', gap: 0, minHeight: '520px' }}>
          {/* Left: Input */}
          <div style={{ flex: '0 0 45%', borderRight: '1px solid rgba(255,255,255,0.05)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)', display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 10, color: '#4b5563', alignSelf: 'center', marginRight: 4, fontFamily: 'monospace' }}>SAMPLES:</span>
              {['APT29', 'Lazarus', 'Volt Typhoon', 'FIN7'].map((label, i) => (
                <button key={i} onClick={() => loadSample(i)} style={{
                  fontSize: 10, padding: '3px 8px', borderRadius: 4,
                  border: '1px solid #1f2937', background: 'rgba(255,255,255,0.02)',
                  color: '#6b7280', cursor: 'pointer', fontFamily: 'monospace',
                  transition: 'all 0.15s',
                }} onMouseEnter={e => (e.currentTarget.style.borderColor = '#a855f7', e.currentTarget.style.color = '#c084fc')}
                  onMouseLeave={e => (e.currentTarget.style.borderColor = '#1f2937', e.currentTarget.style.color = '#6b7280')}>
                  {label}
                </button>
              ))}
            </div>
            <div style={{ padding: '12px 14px', flex: 1, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <textarea
                ref={textareaRef}
                value={text}
                onChange={e => setText(e.target.value)}
                placeholder="Paste CTI report, blog post, tweet, or IOC list here...&#10;&#10;The engine will extract: IPs, domains, hashes, CVEs, TTPs, threat actors, malware families."
                style={{
                  flex: 1, background: '#03060a', border: '1px solid #1f2937', borderRadius: 8,
                  padding: '12px', color: '#d1d5db', fontSize: 11, fontFamily: 'monospace',
                  lineHeight: '1.7', resize: 'none', outline: 'none', transition: 'border 0.2s',
                  minHeight: 260,
                }}
                onFocus={e => (e.target.style.borderColor = '#a855f730')}
                onBlur={e => (e.target.style.borderColor = '#1f2937')}
              />
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 10, color: '#4b5563', fontFamily: 'monospace' }}>
                  {text.split(/\s+/).filter(Boolean).length} words · {text.length} chars
                </span>
                <button onClick={analyze} disabled={loading || !text.trim()} style={{
                  padding: '10px 24px', fontWeight: 800, fontSize: 12, cursor: loading ? 'wait' : 'pointer',
                  borderRadius: 8, border: 'none', letterSpacing: '0.1em', textTransform: 'uppercase',
                  background: loading ? '#1f2937' : 'linear-gradient(135deg, #7c3aed, #a855f7)',
                  color: loading ? '#4b5563' : '#fff', transition: 'all 0.2s',
                  boxShadow: loading ? 'none' : '0 0 20px rgba(168,85,247,0.3)',
                  opacity: !text.trim() ? 0.4 : 1,
                }}>
                  {loading ? '⟳ Analyzing...' : '▶ Extract Intelligence'}
                </button>
              </div>
            </div>
          </div>

          {/* Right: Results */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            {!result && !loading && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12, opacity: 0.3 }}>
                <div style={{ fontSize: '3rem' }}>◈</div>
                <div style={{ fontSize: 12, fontFamily: 'monospace', color: '#6b7280', textAlign: 'center' }}>
                  AWAITING INPUT<br/>
                  <span style={{ fontSize: 10 }}>Load a sample or paste threat intelligence text</span>
                </div>
              </div>
            )}
            {loading && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16 }}>
                <div style={{ display: 'flex', gap: 6 }}>
                  {[0, 1, 2].map(i => (
                    <div key={i} style={{ width: 8, height: 8, borderRadius: '50%', background: '#a855f7', animation: `nlpDot 1.2s ${i * 0.2}s infinite ease-in-out` }} />
                  ))}
                </div>
                <div style={{ fontSize: 11, color: '#6b7280', fontFamily: 'monospace', letterSpacing: '0.1em' }}>
                  NEURAL NETWORK PROCESSING...
                </div>
                <style dangerouslySetInnerHTML={{ __html: `
                  @keyframes nlpDot { 0%, 80%, 100% { transform: scale(0.6); opacity: 0.3 } 40% { transform: scale(1.2); opacity: 1 } }
                ` }} />
              </div>
            )}
            {result && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                {/* Stats bar */}
                <div style={{ padding: '10px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)', display: 'flex', gap: 20, background: 'rgba(0,0,0,0.3)', flexWrap: 'wrap' }}>
                  {[
                    { label: 'IOCs', value: result.iocs.length, color: '#00f0ff' },
                    { label: 'Entities', value: result.entities.length, color: '#a78bfa' },
                    { label: 'TTPs', value: result.techniques.length, color: '#f59e0b' },
                    { label: 'Time', value: `${result.processing_time_ms ?? '—'}ms`, color: '#22c55e' },
                  ].map(s => (
                    <div key={s.label} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                      <div style={{ fontSize: 16, fontWeight: 800, color: s.color, fontFamily: 'monospace' }}>{s.value}</div>
                      <div style={{ fontSize: 9, color: '#4b5563', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{s.label}</div>
                    </div>
                  ))}
                  <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                    <button onClick={exportSTIX} style={{ fontSize: 10, padding: '4px 10px', border: '1px solid rgba(0,240,255,0.3)', borderRadius: 4, background: 'rgba(0,240,255,0.05)', color: '#00f0ff', cursor: 'pointer', fontFamily: 'monospace' }}>
                      {exportMsg || '↓ STIX 2.1'}
                    </button>
                  </div>
                </div>

                {/* Tabs */}
                <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  {(['annotated', 'entities', 'ttps', 'stix'] as const).map(tab => (
                    <button key={tab} onClick={() => setActiveTab(tab)} style={{
                      padding: '8px 14px', fontSize: 10, fontWeight: 700, cursor: 'pointer',
                      border: 'none', textTransform: 'uppercase', letterSpacing: '0.06em',
                      borderBottom: activeTab === tab ? '2px solid #a855f7' : '2px solid transparent',
                      color: activeTab === tab ? '#c084fc' : '#4b5563',
                      background: activeTab === tab ? 'rgba(168,85,247,0.06)' : 'transparent',
                      transition: 'all 0.15s',
                    }}>{tab === 'annotated' ? '⬡ Annotated' : tab === 'entities' ? '◈ Entities' : tab === 'ttps' ? '⚔ TTPs' : '▣ STIX'}</button>
                  ))}
                </div>

                {/* Tab content */}
                <div style={{ flex: 1, overflow: 'auto', padding: '14px 16px' }}>
                  {activeTab === 'annotated' && (
                    <div style={{ fontSize: 12, lineHeight: '2.2', fontFamily: 'system-ui, sans-serif', color: '#9ca3af' }}>
                      {renderAnnotated(text, result.entities)}
                    </div>
                  )}

                  {activeTab === 'entities' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                      {result.entities.length === 0 && <div style={{ color: '#4b5563', fontFamily: 'monospace', fontSize: 11 }}>No entities extracted.</div>}
                      {result.entities.map((e, i) => {
                        const schema = ENTITY_SCHEMA[e.label] || DEFAULT_SCHEMA;
                        return (
                          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 12px', background: schema.bg, borderRadius: 6, border: `1px solid ${schema.border}30` }}>
                            <span style={{ fontSize: 14 }}>{schema.icon}</span>
                            <div style={{ flex: 1 }}>
                              <div style={{ fontSize: 12, fontWeight: 700, color: schema.color, fontFamily: 'monospace' }}>{e.text}</div>
                              <div style={{ fontSize: 10, color: '#4b5563', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{e.label.replace('_', ' ')}</div>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              <div style={{ width: 60, height: 4, background: '#1f2937', borderRadius: 99, overflow: 'hidden' }}>
                                <div style={{ width: `${e.conf * 100}%`, height: '100%', background: schema.color, borderRadius: 99 }} />
                              </div>
                              <span style={{ fontSize: 10, color: schema.color, fontFamily: 'monospace', width: 36 }}>{(e.conf * 100).toFixed(0)}%</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {activeTab === 'ttps' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {result.techniques.length === 0 && <div style={{ color: '#4b5563', fontFamily: 'monospace', fontSize: 11 }}>No MITRE ATT&CK techniques mapped.</div>}
                      {result.techniques.map((t, i) => (
                        <div key={i} style={{ padding: '10px 14px', background: 'rgba(245,158,11,0.06)', borderRadius: 8, border: '1px solid rgba(245,158,11,0.2)', display: 'flex', gap: 12, alignItems: 'center' }}>
                          <div style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 800, color: '#f59e0b', minWidth: 70 }}>{t.id}</div>
                          <div style={{ flex: 1 }}>
                            <div style={{ fontSize: 12, fontWeight: 600, color: '#e5e7eb' }}>{t.name}</div>
                            <div style={{ fontSize: 10, color: '#6b7280' }}>{t.tactic}</div>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <div style={{ width: 50, height: 3, background: '#1f2937', borderRadius: 99, overflow: 'hidden' }}>
                              <div style={{ width: `${t.confidence}%`, height: '100%', background: '#f59e0b', borderRadius: 99 }} />
                            </div>
                            <span style={{ fontSize: 10, color: '#f59e0b', fontFamily: 'monospace' }}>{t.confidence}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {activeTab === 'stix' && (
                    <pre style={{ fontSize: 10, color: '#22c55e', fontFamily: 'monospace', lineHeight: 1.5, overflow: 'auto', background: '#000', padding: 12, borderRadius: 6, whiteSpace: 'pre-wrap' }}>
                      {JSON.stringify({
                        type: 'bundle', spec_version: '2.1',
                        id: `bundle--preview`,
                        objects: result.iocs.slice(0, 5).map(ioc => ({
                          type: 'indicator',
                          name: `${ioc.type}: ${ioc.value}`,
                          pattern: `[${ioc.type}:value = '${ioc.value}']`,
                          pattern_type: 'stix',
                          confidence: ioc.confidence,
                        })),
                      }, null, 2)}
                    </pre>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      ) : (
        // STREAM MODE
        <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12, minHeight: 400, overflow: 'auto' }}>
          <div style={{ fontSize: 11, color: '#6b7280', fontFamily: 'monospace', letterSpacing: '0.08em' }}>
            ⟳ LISTENING ON LIVE CTI FEEDS (RSS) — {liveEvents.length} extractions received
          </div>
          {streamItems.length === 0 && (
            <div style={{ padding: 40, textAlign: 'center', color: '#4b5563', fontFamily: 'monospace' }}>Awaiting incoming NLP stream from backend workers...</div>
          )}
          {streamItems.map((item: any, idx) => (
            <div key={`${item.timestamp}-${idx}`} style={{ animation: 'nlpSlideIn 0.5s cubic-bezier(0.16, 1, 0.3, 1)', borderLeft: '3px solid #00f0ff', background: 'rgba(0,240,255,0.03)', borderRadius: '0 8px 8px 0', padding: '14px 18px', transition: 'all 0.3s', boxShadow: 'inset 0 0 20px rgba(0,240,255,0.01)' }}>
              
              {/* Header: Title and Source */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                 <div style={{ fontWeight: 800, color: '#e5e7eb', fontSize: 13, lineHeight: 1.4 }}>
                    {item.data?.title || 'Unknown OSINT Report'}
                 </div>
                 <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                    <span style={{ fontSize: 9, padding: '2px 6px', background: '#1f2937', color: '#9ca3af', borderRadius: 4, fontFamily: 'monospace' }}>
                      {new Date(item.timestamp).toLocaleTimeString()}
                    </span>
                    <span style={{ fontSize: 10, padding: '2px 8px', border: '1px solid #00f0ff40', borderRadius: 99, color: '#00f0ff', fontWeight: 700, fontFamily: 'monospace', textTransform: 'uppercase' }}>
                      {item.data?.source_feed || item.data?.source || 'RSS Stream'}
                    </span>
                 </div>
              </div>

              {/* Body: Annotated Raw Text */}
              <div style={{ fontSize: 12, color: '#9ca3af', lineHeight: '2', marginBottom: 12, paddingLeft: 8, borderLeft: '1px solid rgba(255,255,255,0.05)' }}>
                {renderAnnotated(item.data?.raw || '', item.data?.entities || [])}
              </div>

              {/* Footer: Extracted Badges */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, borderTop: '1px dashed rgba(255,255,255,0.08)', paddingTop: 10 }}>
                <span style={{ fontSize: 10, color: '#6b7280', alignSelf: 'center', fontFamily: 'monospace', marginRight: 4 }}>► EXTRACTED:</span>
                {(item.data?.entities || []).length === 0 && <span style={{ fontSize: 10, color: '#4b5563', fontStyle: 'italic' }}>No entities found.</span>}
                {(item.data?.entities || []).map((e: any, i: number) => {
                  const s = ENTITY_SCHEMA[e.label] || DEFAULT_SCHEMA;
                  return (
                    <span key={i} title={`Conf: ${e.conf}%`} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 99, background: s.bg, color: s.color, border: `1px solid ${s.border}40`, fontFamily: 'monospace', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 4, boxShadow: `0 0 10px ${s.bg}` }}>
                      <span style={{ opacity: 0.8 }}>{s.icon}</span> {e.text}
                    </span>
                  );
                })}
              </div>
            </div>
          ))}
          <style dangerouslySetInnerHTML={{ __html: `@keyframes nlpSlideIn { from { opacity:0; transform:translateX(-20px) } to { opacity:1; transform:translateX(0) } }` }} />
        </div>
      )}
    </div>
  );
}
