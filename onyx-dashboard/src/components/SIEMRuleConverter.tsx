"use client";

import { useState, useEffect, useId, useMemo, useRef } from 'react';
import { useOnyxStore } from '@/lib/store';
import { Maximize2, X, Pause, Play } from 'lucide-react';

export default function SIEMRuleConverter({ activeIoc }: { activeIoc?: string }) {
  const [engine, setEngine] = useState<'SIGMA' | 'YARA' | 'SNORT'>('SIGMA');
  const [copied, setCopied] = useState(false);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  const [ruleId, setRuleId] = useState('');
  const [ruleDate, setRuleDate] = useState('');
  const [rotatingIdx, setRotatingIdx] = useState(0);
  const [autoScroll, setAutoScroll] = useState(true);
  const [readMode, setReadMode] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  
  const armedIocs = useOnyxStore(s => s.armedIocs) || [];

  // Extract live IOC values for rotation
  const liveIocValues = useMemo(() => {
    const vals = armedIocs
      .filter((ioc: any) => ioc.type === 'ipv4' && ioc.confidence >= 90)
      .slice(0, 20)
      .map((ioc: any) => ioc.value);
    return vals.length > 0 ? vals : ['0.0.0.0'];
  }, [armedIocs]);

  const rotatingIoc = activeIoc || liveIocValues[rotatingIdx % liveIocValues.length];
  const uid = useId();

  // Generate all volatile values client-side only
  useEffect(() => {
    setRuleId(crypto.randomUUID());
    setRuleDate(new Date().toISOString().split('T')[0]);
    if (!autoScroll) return; // Pause rotation if hover
    const interval = setInterval(() => {
      setRotatingIdx(prev => prev + 1);
      setRuleId(crypto.randomUUID());
    }, 5000);
    return () => clearInterval(interval);
  }, [autoScroll]);

  useEffect(() => {
     if (autoScroll && scrollRef.current) {
        scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
     }
  }, [rotatingIdx, engine, autoScroll]);

  const target = activeIoc || rotatingIoc;

  const rules = {
    SIGMA: `title: Malicious C2 Communication — MISP Feed
id: ${ruleId || '...generating...'}
status: production
description: Auto-generated from ONYX MISP ingestion. Detects outbound C2 to ${target}.
author: ONYX CTI Platform v3.0
date: ${ruleDate || '...'}
logsource:
    category: network_connection
    product: zeek
detection:
    selection:
        TargetIp|contains:
            - '${target}'
    filter_internal:
        SourceIp|startswith:
            - '10.'
            - '192.168.'
    condition: selection and not filter_internal
falsepositives:
    - Legitimate CDN infrastructure (verify manually)
level: critical
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1095`,
    YARA: `rule ONYX_AutoGen_C2_${target.replace(/\./g, '_')} {
    meta:
        description   = "MISP auto-ingested payload — C2 endpoint ${target}"
        author        = "ONYX CTI Platform"
        date          = "${ruleDate || '...'}"
        confidence    = "98"
        source        = "MISP Widespread Bad IPs"
        mitre_attack  = "T1041, T1095"
    strings:
        $ip_ascii    = "${target}" ascii wide nocase
        $ip_hex      = { ${target.split('.').map((o: string) => parseInt(o).toString(16).padStart(2,'0')).join(' ')} }
        $ua_bot      = "python-requests" ascii nocase
        $beacon_call = { 48 8B ?? E8 ?? ?? ?? ?? 48 85 C0 }
    condition:
        (1 of ($ip_*)) or ($beacon_call and $ua_bot)
}`,
    SNORT: `# ONYX Auto-Generated Snort Rule (${ruleDate || '...'})
# Source: MISP Widespread Bad IPs | IOC: ${target}
alert tcp $HOME_NET any -> ${target} any (
    msg:"ONYX CTI - Outbound C2 to MISP Flagged Host ${target}";
    flow:established,to_server;
    classtype:trojan-activity;
    sid:${Array.from(target as string).reduce((h: number, c: any) => ((h << 5) - h + String(c).charCodeAt(0)) | 0, 0x100000) >>> 0};
    rev:1;
    metadata:affected_product Any, attack_target Client_Endpoint,
              deployment Perimeter, signature_severity Critical,
              tag C2, created_at ${ruleDate || '...'};
)`
  };

  const tabConfig = {
    SIGMA: { color: '#f59e0b', bg: 'rgba(245,158,11,0.1)', border: '#f59e0b', desc: 'Signatures SIEM génériques — détection agnostique vendeur (Splunk, QRadar, Elastic)' },
    YARA:  { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',   border: '#ef4444', desc: 'Correspondance de patterns fichiers & mémoire — chasse aux malwares' },
    SNORT: { color: '#a855f7', bg: 'rgba(168,85,247,0.1)',  border: '#a855f7', desc: 'Détection d\'intrusion réseau — signatures au niveau paquet (IDS/IPS)' },
  };

  const codeArea = (
    <div 
       ref={scrollRef}
       onMouseEnter={() => setAutoScroll(false)} 
       onMouseLeave={() => setAutoScroll(true)}
       style={{ flex: 1, padding: 16, overflowY: 'auto', background: readMode ? '#0f172a' : '#000', fontFamily: 'monospace', fontSize: 12, transition: 'background 0.2s', position: 'relative' }}
       className="scrollbar-thin scrollbar-thumb-gray-800 hover:scrollbar-thumb-gray-600"
    >
       {!autoScroll && !readMode && (
         <div className="absolute top-2 right-4 text-amber-500 flex items-center gap-1 text-[10px] bg-amber-500/10 px-2 py-0.5 rounded-full border border-amber-500/20">
           <Pause size={10} /> DÉFILEMENT PAUSÉ
         </div>
       )}
       <pre style={{ color: tabConfig[engine].color, opacity: 0.9, lineHeight: 1.6, margin: 0, whiteSpace: 'pre-wrap' }}>
         {rules[engine].split('\n').map((line, i) => (
           <div key={i} style={{ display: 'flex' }}>
             <span style={{ color: '#334155', width: 28, textAlign: 'right', marginRight: 12, userSelect: 'none', flexShrink: 0 }}>{i + 1}</span>
             <span>{line}</span>
           </div>
         ))}
       </pre>
    </div>
  );

  return (
    <>
    <div style={{ background: 'var(--onyx-bg-secondary)', borderRadius: 12, border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', height: '100%', minHeight: 400, overflow: 'hidden' }}>
      <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border-subtle)', background: 'var(--onyx-bg-primary)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
           <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>⚙ Ingénierie de Détection</div>
           <div style={{ fontSize: 10, color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>Règles de détection auto-compilées depuis les flux OSINT en direct</div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button
            onClick={() => handleCopy(rules[engine])}
            style={{ padding: '4px 10px', fontSize: 10, fontWeight: 700, borderRadius: 6, background: copied ? 'rgba(34,197,94,0.15)' : 'rgba(0,240,255,0.08)', color: copied ? '#22c55e' : '#00f0ff', border: `1px solid ${copied ? 'rgba(34,197,94,0.4)' : 'rgba(0,240,255,0.3)'}`, cursor: 'pointer', fontFamily: 'monospace', transition: 'all 0.2s' }}
          >
            {copied ? '✓ Copié' : '⎘ Copier'}
          </button>
          <button onClick={() => setReadMode(true)} className="p-1.5 hover:bg-white/10 rounded border border-transparent hover:border-white/20 transition-all text-gray-400 hover:text-white" title="Mode Lecture (Plein écran)">
             <Maximize2 size={14} />
          </button>
        </div>
      </div>
      
      <div style={{ display: 'flex', borderBottom: '1px solid #1f2937', background: '#0a0a0a' }}>
        {(['SIGMA', 'YARA', 'SNORT'] as const).map(tab => (
          <button
            key={tab}
            id={`${uid}-tab-${tab}`}
            onClick={() => setEngine(tab)}
            style={{
              flex: 1, padding: '10px 8px', fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', cursor: 'pointer', border: 'none',
              borderBottom: engine === tab ? `2px solid ${tabConfig[tab].border}` : '2px solid transparent', color: engine === tab ? tabConfig[tab].color : '#4b5563',
              background: engine === tab ? tabConfig[tab].bg : 'rgba(0,0,0,0.5)', transition: 'all 0.2s',
            }}
          >
            {tab}
          </button>
        ))}
      </div>

      <div style={{ padding: '6px 14px', background: 'var(--onyx-bg-primary)', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--text-tertiary)' }}>CIBLE AUTO-COMPILÉE</span>
        <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--onyx-cyan)', background: 'rgba(0,238,255,0.05)', padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(0,238,255,0.2)' }}>
          {target}
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'monospace', fontSize: 10, color: '#22c55e' }}>
           <span className="pulse-live" style={{ background: '#22c55e' }}/> OSINT EN DIRECT
        </span>
      </div>

      <div style={{ padding: '6px 14px', background: 'var(--onyx-bg-primary)', borderBottom: '1px solid var(--border-subtle)' }}>
        <p style={{ fontSize: 10, color: 'var(--text-tertiary)', fontFamily: 'monospace', margin: 0 }}>{tabConfig[engine].desc}</p>
      </div>

      {codeArea}
    </div>

    {/* OVERLAY MODAL FOR READ MODE */}
    {readMode && (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-8 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
         <div className="w-full max-w-5xl h-[85vh] bg-[#0a0a0a] border border-gray-700/50 rounded-xl overflow-hidden flex flex-col shadow-2xl">
            <div className="flex justify-between items-center p-4 border-b border-gray-800 bg-[#050505]">
               <div className="flex items-center gap-3">
                  <span className="font-bold text-white tracking-widest">RÈGLE {engine}</span>
                  <span className="text-gray-500 font-mono text-xs">{target}</span>
               </div>
               <div style={{ display: 'flex', gap: 8 }}>
                 <button onClick={() => handleCopy(rules[engine])} style={{ padding: '6px 14px', fontSize: 11, fontWeight: 700, borderRadius: 6, background: copied ? 'rgba(34,197,94,0.15)' : 'rgba(0,240,255,0.08)', color: copied ? '#22c55e' : '#00f0ff', border: `1px solid ${copied ? 'rgba(34,197,94,0.4)' : 'rgba(0,240,255,0.3)'}`, cursor: 'pointer', fontFamily: 'monospace' }}>{copied ? '✓ Copié' : '⎘ Copier la règle'}</button>
                 <button onClick={() => setReadMode(false)} className="p-2 hover:bg-red-500/20 text-gray-400 hover:text-red-500 rounded-lg transition-colors">
                   <X size={20} />
                 </button>
               </div>
            </div>
            {codeArea}
         </div>
      </div>
    )}
    </>
  );
}
