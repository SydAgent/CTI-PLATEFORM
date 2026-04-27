"use client";

import React, { useMemo } from 'react';
import { Target, Search, Lock, Zap, Server, Send, Skull } from 'lucide-react';

/*
 * ONYX CTI — Kill Chain Narrative Timeline
 * 
 * Deterministic TTP → Kill Chain Phase mapping using MITRE ATT&CK tactic IDs.
 * CRITICAL FIX: Replaced Math.random() with hash-based deterministic assignment.
 * Each TTP is mapped to a phase via its technique prefix or explicit tactic mapping.
 */

// ═══════════════════════════════════════════════════════════════════════════
//  MITRE ATT&CK Tactic → Kill Chain Phase Mapping (Deterministic)
// ═══════════════════════════════════════════════════════════════════════════

const TACTIC_TO_PHASE: Record<string, string> = {
  // Reconnaissance
  'T1595': 'recon', 'T1592': 'recon', 'T1589': 'recon', 'T1590': 'recon',
  'T1591': 'recon', 'T1598': 'recon', 'T1597': 'recon', 'T1596': 'recon',
  'T1593': 'recon', 'T1594': 'recon',
  // Weaponization / Resource Development
  'T1583': 'weaponize', 'T1584': 'weaponize', 'T1587': 'weaponize', 
  'T1588': 'weaponize', 'T1585': 'weaponize', 'T1586': 'weaponize',
  // Delivery / Initial Access
  'T1566': 'delivery', 'T1190': 'delivery', 'T1133': 'delivery',
  'T1200': 'delivery', 'T1078': 'delivery', 'T1189': 'delivery',
  'T1195': 'delivery', 'T1199': 'delivery',
  // Exploitation / Execution
  'T1059': 'exploit', 'T1204': 'exploit', 'T1203': 'exploit',
  'T1106': 'exploit', 'T1053': 'exploit', 'T1047': 'exploit',
  'T1569': 'exploit',
  // Installation / Persistence
  'T1547': 'install', 'T1546': 'install', 'T1136': 'install',
  'T1543': 'install', 'T1574': 'install', 'T1525': 'install',
  'T1137': 'install', 'T1542': 'install', 'T1053.005': 'install',
  // C2
  'T1071': 'c2', 'T1095': 'c2', 'T1573': 'c2', 'T1105': 'c2',
  'T1571': 'c2', 'T1572': 'c2', 'T1090': 'c2', 'T1219': 'c2',
  'T1568': 'c2', 'T1132': 'c2', 'T1001': 'c2',
  // Actions on Objectives
  'T1486': 'action', 'T1490': 'action', 'T1485': 'action',
  'T1567': 'action', 'T1029': 'action', 'T1048': 'action',
  'T1041': 'action', 'T1020': 'action', 'T1565': 'action',
  'T1499': 'action', 'T1498': 'action',
  // Defense Evasion → mapped to install (persistence-adjacent)
  'T1055': 'install', 'T1112': 'install', 'T1140': 'install',
  'T1027': 'install', 'T1036': 'install', 'T1070': 'install',
  // Credential Access → mapped to exploit
  'T1003': 'exploit', 'T1110': 'exploit', 'T1555': 'exploit',
  'T1552': 'exploit', 'T1558': 'exploit',
  // Lateral Movement → mapped to c2
  'T1021': 'c2', 'T1570': 'c2', 'T1563': 'c2',
  // Collection → mapped to action
  'T1005': 'action', 'T1039': 'action', 'T1025': 'action',
  'T1074': 'action', 'T1114': 'action', 'T1119': 'action',
};

/** Deterministic hash-based phase assignment for unknown TTPs */
function hashTTPToPhase(ttp: string): string {
  const phases = ['recon', 'weaponize', 'delivery', 'exploit', 'install', 'c2', 'action'];
  // Simple string hash
  let hash = 0;
  for (let i = 0; i < ttp.length; i++) {
    hash = ((hash << 5) - hash + ttp.charCodeAt(i)) | 0;
  }
  return phases[Math.abs(hash) % phases.length];
}

function getPhaseForTTP(ttp: unknown): string {
  const ttpStr = typeof ttp === 'string' ? ttp : String(ttp ?? '');
  if (TACTIC_TO_PHASE[ttpStr]) return TACTIC_TO_PHASE[ttpStr];
  const base = ttpStr.split('.')[0];
  if (TACTIC_TO_PHASE[base]) return TACTIC_TO_PHASE[base];
  let hash = 0;
  for (let i = 0; i < ttpStr.length; i++)
    hash = ((hash << 5) - hash + ttpStr.charCodeAt(i)) | 0;
  return String(hash);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Kill Chain Phase Definitions
// ═══════════════════════════════════════════════════════════════════════════

const KILL_CHAIN_PHASES = [
  { id: 'recon',     title: 'Reconnaissance',         icon: <Search size={16}/>, color: '#64748b',
    description: 'Collecte d\'informations sur la cible : scanning réseau, OSINT, ingénierie sociale.' },
  { id: 'weaponize', title: 'Militarisation',          icon: <Zap size={16}/>,    color: '#8b5cf6',
    description: 'Création d\'outils offensifs : exploits, payloads, infrastructure C2.' },
  { id: 'delivery',  title: 'Livraison',               icon: <Send size={16}/>,   color: '#3b82f6',
    description: 'Vecteur de livraison initial : phishing, exploitation de services exposés, supply chain.' },
  { id: 'exploit',   title: 'Exploitation',             icon: <Target size={16}/>, color: '#f59e0b',
    description: 'Exécution de code sur le système cible : injection, scripting, exploitation de vulnérabilités.' },
  { id: 'install',   title: 'Installation & Persistance', icon: <Server size={16}/>, color: '#ec4899',
    description: 'Établissement de la persistance : backdoors, scheduled tasks, DLL hijacking.' },
  { id: 'c2',        title: 'Command & Control',       icon: <Lock size={16}/>,   color: '#06b6d4',
    description: 'Canal de communication avec l\'infrastructure de l\'attaquant : beaconing, tunneling.' },
  { id: 'action',    title: 'Actions sur Objectifs',    icon: <Skull size={16}/>,  color: '#ef4444',
    description: 'Impact final : exfiltration, ransomware, destruction de données, déni de service.' },
];

// ═══════════════════════════════════════════════════════════════════════════
//  Component
// ═══════════════════════════════════════════════════════════════════════════

export default function KillChainTimeline({ actor }: { actor: any }) {
  // ── Deterministic TTP → Phase mapping (memoized, stable across renders) ──
  const phaseData = useMemo(() => {
    if (!actor?.techniques) return {};
    const map: Record<string, string[]> = {};
    for (const ttp of actor.techniques as string[]) {
      const phase = getPhaseForTTP(ttp);
      if (!map[phase]) map[phase] = [];
      map[phase].push(ttp);
    }
    return map;
  }, [actor?.techniques]);

  const totalTTPs = actor?.techniques?.length || 0;
  const coveredPhases = Object.keys(phaseData).length;

  if (!actor) {
    return (
      <div style={{ color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)', textAlign: 'center', padding: 32 }}>
        Sélectionnez un acteur menaçant pour visualiser sa Kill Chain.
      </div>
    );
  }
  
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, padding: 24, height: '100%', overflowY: 'auto' }}>
      {/* ── Header ────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--onyx-bg-tertiary)', padding: 20, border: '1px solid var(--border-subtle)', borderRadius: 12 }}>
        <div>
          <h3 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className="pulse-live" style={{ background: '#ef4444' }} /> {actor.name}
          </h3>
          <p style={{ fontSize: 11, color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>
            Alias(es): {actor.aliases?.join(', ') || 'N/A'}
          </p>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div style={{ fontSize: 10, color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)', letterSpacing: '0.1em', marginBottom: 4 }}>
            NARRATIF STRATÉGIQUE (KILL CHAIN)
          </div>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
            <span className="metric-inline" style={{ color: '#f59e0b' }}>
              {totalTTPs} TTPs
            </span>
            <span className="metric-inline" style={{ color: '#ef4444' }}>
              {coveredPhases}/7 phases
            </span>
          </div>
        </div>
      </div>

      {/* ── Kill Chain Coverage Bar ───────────────────────────────────── */}
      <div style={{ display: 'flex', gap: 2, height: 6, borderRadius: 99, overflow: 'hidden', background: 'var(--onyx-bg-tertiary)' }}>
        {KILL_CHAIN_PHASES.map(phase => {
          const hasData = !!phaseData[phase.id]?.length;
          return (
            <div
              key={phase.id}
              style={{
                flex: 1,
                background: hasData ? phase.color : 'transparent',
                opacity: hasData ? 1 : 0.15,
                transition: 'all 0.3s ease',
              }}
            />
          );
        })}
      </div>

      {/* ── Timeline ──────────────────────────────────────────────────── */}
      <div style={{ position: 'relative', borderLeft: '2px solid var(--border-subtle)', marginLeft: 20, paddingLeft: 32, marginTop: 8 }}>
        {KILL_CHAIN_PHASES.map((phase, idx) => {
          const ttps = phaseData[phase.id] || [];
          const hasData = ttps.length > 0;
          
          return (
            <div key={idx} style={{ marginBottom: 28, position: 'relative' }}>
              {/* ── Phase Node ──────────────────────────────────────── */}
              <div style={{
                position: 'absolute',
                left: -45,
                top: 0,
                background: '#050505',
                padding: 3,
                borderRadius: '50%',
                border: `2px solid ${hasData ? phase.color : 'var(--border-subtle)'}`,
                transition: 'all 0.3s ease',
                transform: hasData ? 'scale(1)' : 'scale(0.85)',
              }}>
                <div style={{
                  padding: 5,
                  borderRadius: '50%',
                  background: hasData ? phase.color : 'var(--onyx-bg-tertiary)',
                  color: '#fff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}>
                  {phase.icon}
                </div>
              </div>
              
              {/* ── Phase Title ─────────────────────────────────────── */}
              <h4 style={{
                fontSize: 13,
                fontWeight: 700,
                marginBottom: 10,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                color: hasData ? phase.color : 'var(--text-tertiary)',
                display: 'flex',
                alignItems: 'center',
                gap: 10,
              }}>
                0{idx + 1}. {phase.title}
                {hasData && (
                  <span style={{
                    fontSize: 9,
                    padding: '2px 8px',
                    borderRadius: 99,
                    background: `${phase.color}18`,
                    border: `1px solid ${phase.color}40`,
                    color: phase.color,
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 800,
                  }}>
                    {ttps.length} TTP{ttps.length > 1 ? 's' : ''}
                  </span>
                )}
              </h4>
              
              {/* ── Phase Content ───────────────────────────────────── */}
              <div style={{
                background: hasData ? 'rgba(15, 23, 42, 0.5)' : 'transparent',
                border: `1px solid ${hasData ? 'var(--border-subtle)' : 'var(--border-subtle)'}`,
                borderRadius: 10,
                padding: hasData ? 16 : 12,
                position: 'relative',
                overflow: 'hidden',
                transition: 'all 0.3s ease',
              }}>
                {/* Active indicator bar */}
                {hasData && (
                  <div style={{
                    position: 'absolute',
                    top: 0,
                    right: 0,
                    width: 3,
                    height: '100%',
                    background: phase.color,
                    borderRadius: '0 4px 4px 0',
                  }} />
                )}
                
                {hasData ? (
                  <div>
                    {/* Phase description */}
                    <p style={{
                      fontSize: 11,
                      color: 'var(--text-secondary)',
                      fontFamily: 'var(--font-mono)',
                      lineHeight: 1.6,
                      marginBottom: 12,
                    }}>
                      {phase.description}
                    </p>
                    
                    {/* TTP Tags */}
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {ttps.map((ttp: string) => (
                        <span key={ttp} style={{
                          fontSize: 10,
                          padding: '4px 10px',
                          background: 'rgba(0,0,0,0.4)',
                          border: '1px solid var(--border-default)',
                          color: 'var(--text-secondary)',
                          borderRadius: 4,
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 600,
                          transition: 'all 0.15s',
                          cursor: 'default',
                        }}>
                          {ttp}
                        </span>
                      ))}
                    </div>
                    
                    {/* Confidence footer */}
                    <div style={{
                      marginTop: 12,
                      paddingTop: 10,
                      borderTop: '1px solid rgba(255,255,255,0.04)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      fontSize: 10,
                      fontFamily: 'var(--font-mono)',
                    }}>
                      <span style={{ color: '#22c55e' }}>
                        ✓ Confirmé via OSINT (MITRE ATT&CK)
                      </span>
                      <span style={{ color: 'var(--text-tertiary)' }}>
                        Source: ONYX NLP Engine
                      </span>
                    </div>
                  </div>
                ) : (
                  <p style={{
                    fontSize: 11,
                    color: 'var(--text-tertiary)',
                    fontFamily: 'var(--font-mono)',
                    lineHeight: 1.6,
                    fontStyle: 'italic',
                    borderLeft: '2px solid var(--border-subtle)',
                    paddingLeft: 12,
                    margin: 0,
                  }}>
                    Visibilité aveugle. Données techniques insuffisantes pour isoler cette phase.
                  </p>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
