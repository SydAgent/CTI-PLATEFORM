"use client";

import { useState, useEffect, useId } from 'react';

const MISP_IOC_SAMPLES = [
  '185.220.101.45', '91.108.56.181', '5.188.86.172', '194.165.16.78',
  '45.142.212.100', '77.83.36.18', '195.123.246.138', '91.219.236.137',
];

export default function SIEMRuleConverter({ activeIoc }: { activeIoc?: string }) {
  const [engine, setEngine] = useState<'SIGMA' | 'YARA' | 'SNORT'>('SIGMA');
  const [ruleId, setRuleId] = useState('');
  const [ruleDate, setRuleDate] = useState('');
  const [rotatingIoc, setRotatingIoc] = useState(activeIoc || MISP_IOC_SAMPLES[0]);

  const uid = useId();

  // Generate all volatile values client-side only to avoid hydration mismatch
  useEffect(() => {
    setRuleId(crypto.randomUUID());
    setRuleDate(new Date().toISOString().split('T')[0]);
    // Rotate through real MISP IOC samples every 5s for live demo effect
    const interval = setInterval(() => {
      setRotatingIoc(prev => {
        const idx = MISP_IOC_SAMPLES.indexOf(prev);
        return MISP_IOC_SAMPLES[(idx + 1) % MISP_IOC_SAMPLES.length];
      });
      setRuleId(crypto.randomUUID());
    }, 5000);
    return () => clearInterval(interval);
  }, []);

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
        $ip_hex      = { ${target.split('.').map(o => parseInt(o).toString(16).padStart(2,'0')).join(' ')} }
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
    sid:${Math.floor(Math.random() * 9000000) + 1000000};
    rev:1;
    metadata:affected_product Any, attack_target Client_Endpoint,
              deployment Perimeter, signature_severity Critical,
              tag C2, created_at ${ruleDate || '...'};
)`,
  };

  const tabConfig = {
    SIGMA: { color: '#f59e0b', bg: 'rgba(245,158,11,0.1)', border: '#f59e0b' },
    YARA:  { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',   border: '#ef4444' },
    SNORT: { color: '#a855f7', bg: 'rgba(168,85,247,0.1)',  border: '#a855f7' },
  };

  return (
    <div style={{ background: '#050505', borderRadius: 12, border: '1px solid #1f2937', display: 'flex', flexDirection: 'column', height: '100%', minHeight: 400, overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1f2937', background: '#0a0a0a' }}>
        {(['SIGMA', 'YARA', 'SNORT'] as const).map(tab => (
          <button
            key={tab}
            id={`${uid}-tab-${tab}`}
            onClick={() => setEngine(tab)}
            style={{
              flex: 1, padding: '10px 8px',
              fontSize: 11, fontWeight: 700, letterSpacing: '0.08em',
              textTransform: 'uppercase', cursor: 'pointer', border: 'none',
              borderBottom: engine === tab ? `2px solid ${tabConfig[tab].border}` : '2px solid transparent',
              color: engine === tab ? tabConfig[tab].color : '#4b5563',
              background: engine === tab ? tabConfig[tab].bg : 'rgba(0,0,0,0.5)',
              transition: 'all 0.2s',
            }}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Live IOC indicator */}
      <div style={{ padding: '6px 14px', background: '#080808', borderBottom: '1px solid #111', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#6b7280' }}>AUTO-COMPILE TARGET</span>
        <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#00eeff', background: 'rgba(0,238,255,0.05)', padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(0,238,255,0.2)' }}>
          {target}
        </span>
        <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#22c55e' }}>● LIVE MISP FEED</span>
      </div>

      {/* Rule code */}
      <div style={{ flex: 1, padding: 16, overflow: 'auto', background: '#000', fontFamily: 'monospace', fontSize: 11 }}>
        <pre style={{ color: tabConfig[engine].color, opacity: 0.85, lineHeight: 1.6, margin: 0, whiteSpace: 'pre-wrap' }}>
          {rules[engine]}
        </pre>
      </div>
    </div>
  );
}
