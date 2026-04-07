import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface ReportData {
  id: string;
  title: string;
  severity: string;
  date: string;
  iocs: number;
  ttps: number;
  author: string;
}

const GENERATE_EXPERT_REPORT = (r: ReportData) => `
# 🛡️ ONYX intelligence Brief: ${r.id}
> **CONFIDENTIALITY:** TLP:RED | **CLASSIFICATION:** TOP SECRET // SIGINT  
> **DATE:** ${r.date} | **SOURCE:** OMNI-AGENT ENGINE | **AUTHOR:** ${r.author}

---

## 1. SYNTHÈSE EXÉCUTIVE (EXECUTIVE SUMMARY)
L'analyse automatisée par le moteur **SciBERT** a identifié une campagne offensive de haute intensité ciblant les infrastructures critiques. Le profilage des tactiques, techniques et procédures (TTPs) indique une corrélation de **94.2%** avec le groupe d'acteurs **APT29** (Cozy Bear). 

La menace utilise des vecteurs d'infection sophistiqués basés sur des documents PDF piégés (Spear-phishing) entraînant l'exécution de payloads en mémoire.

---

## 2. MATRICE DE CRITICITÉ (RISK ASSESSMENT)
| Vecteur | Niveau | Impact | Statut |
|---|---|---|---|
| **Exfiltration** | CRITIQUE | Élevé | Actif |
| **Persistance** | HAUT | Moyen | Identifié |
| **Mouvement Latéral** | MOYEN | Élevé | Bloqué |

---

## 3. INDICATEURS TECHNIQUES & MÉTHODOLOGIE (IOCS)
La méthodologie d'analyse ONYX repose sur le recoupement de flux **OSINT**, **Dark-Web Scrapers** et le **Deep Packet Inspection**.

### ⬡ Liste des Indicateurs (Top 5)
1.  **IP C2 (Command & Control) :** \`185.220.101.45\` (Confidence: 99%)
2.  **Domain (Staging) :** \`onion-router-c2.tk\` (Confidence: 98%)
3.  **Filestem Cache Hash (SHA256) :** \`e3b0c442...855\` (Confidence: 100%)
4.  **Registry Key :** \`HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OnyxLoader\`
5.  **Malware Pattern :** \`Cobalt Strike / Beacon variant\`

---

## 4. RELATIONS & CORRÉLATIONS (THREAT GRAPH ANALYSIS)
L'analyse du graphe relationnel met en évidence un lien direct entre le serveur de staging situé à Londres (\`91.108.56.181\`) et l'infrastructure de phishing utilisée pour compromettre le secteur énergétique. 

**Chaîne de Corrélation :**
\`Phishing PDF\` → \`PowerShell Dropper\` → \`C2 Communication\` → \`Data Staging\`

---

## 5. DÉTAILS ASSOCIÉS & COMPORTEMENTS (TTPs)
Cartographie basée sur le framework **MITRE ATT&CK v14** :

*   **T1566.001 (Spearphishing Attachment) :** Utilisation de factures PDF factices.
*   **T1059.001 (PowerShell Execution) :** Utilisation de scripts obfuscés pour le téléchargement du malware.
*   **T1071.001 (Web Protocols) :** Communication C2 via HTTPS sur des ports non-standards.
*   **T1078 (Valid Accounts) :** Tentatives de credential stuffing sur les comptes VPN.

---

## 6. ANALYSE CONTEXTUELLE (SCIBERT INTELLIGENCE)
> **Observation SecGPT :** "L'analyse linguistique des scripts de déploiement montre des commentaires en alphabet cyrillique et des fuseaux horaires de compilation alignés sur MSK (UTC+3). Cette campagne semble être une réponse directe aux récentes tensions géopolitiques dans le secteur de l'énergie en Europe Centrale."

---

## 7. RECOMMANDATIONS & REMÉDIATION (ACTIONABLE INTEL)
### ⚡ Actions Immédiates
1.  **Blacklistage IP :** Isoler \`185.220.101.45\` et \`91.108.56.181\` sur tous les firewalls périmétriques.
2.  **Rotation des Secrets :** Réinitialiser les mots de passe des comptes administrateurs AD ayant accédé au VPN les dernières 48h.
3.  **Détection Sigma :** Déployer la règle ci-dessous :

\`\`\`yaml
title: Detect Lateral Movement via Suspicious PowerShell
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: 'powershell.exe'
        CommandLine|contains: 'Invoke-WebRequest'
    condition: selection
level: critical
\`\`\`
`;

export default function IntelligenceBrief({ onClose, report }: { onClose: () => void; report?: ReportData }) {
  const data = report || {
    id: 'RPT-2026-OMNI-001',
    title: 'APT29 Targeting Critical Infrastructure',
    severity: 'critical',
    date: '2026-04-07',
    iocs: 48,
    ttps: 12,
    author: 'ONYX OMNI-AGENT'
  };

  return (
    <div className="animate-in" style={{
      position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh',
      background: 'rgba(2, 4, 8, 0.95)', backdropFilter: 'blur(15px)', zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center'
    }}>
      <div style={{
        width: '95%', maxWidth: 1100, height: '92vh', background: '#05080f',
        border: '1px solid rgba(168, 85, 247, 0.4)', borderRadius: 24, display: 'flex', flexDirection: 'column',
        boxShadow: '0 0 80px rgba(168, 85, 247, 0.15)', overflow: 'hidden', position: 'relative'
      }}>
        {/* Decorative background elements */}
        <div style={{ position: 'absolute', top: -100, right: -100, width: 300, height: 300, background: 'rgba(168, 85, 247, 0.05)', borderRadius: '50%', filter: 'blur(80px)' }}></div>
        
        {/* Top Header */}
        <div style={{ 
          padding: '24px 40px', borderBottom: '1px solid rgba(255,255,255,0.05)', 
          display: 'flex', justifyContent: 'space-between', alignItems: 'center', 
          background: 'linear-gradient(to right, rgba(168,85,247,0.1), transparent)',
          position: 'relative', zIndex: 2
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
            <div style={{ 
              width: 50, height: 50, borderRadius: 12, background: 'rgba(168,85,247,0.1)', 
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 24,
              border: '1px solid rgba(168,85,247,0.3)'
            }}>🛡️</div>
            <div>
              <div style={{ fontFamily: 'monospace', fontWeight: 900, fontSize: 18, color: '#e5e7eb', letterSpacing: '4px' }}>DOSSIER: <span style={{ color: '#a855f7' }}>INTELLIGENCE_REPORT</span></div>
              <div style={{ fontSize: 10, color: '#6b7280', fontFamily: 'monospace', marginTop: 4 }}>
                ID: {data.id} | <span style={{ color: data.severity === 'critical' ? '#ef4444' : '#f97316' }}>TLP:RED</span> | SIGINT CLASSIFIED
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 12 }}>
            <button style={{ 
              background: 'rgba(255,255,255,0.02)', border: '1px solid #1f2937', 
              borderRadius: 8, padding: '10px 20px', color: '#e5e7eb', 
              cursor: 'pointer', fontFamily: 'monospace', fontSize: 11, fontWeight: 700 
            }}>PRINT_HARDCOPY</button>
            <button onClick={onClose} style={{ 
              background: '#ef4444', border: 'none', 
              borderRadius: 8, padding: '10px 20px', color: '#fff', 
              cursor: 'pointer', fontFamily: 'monospace', fontSize: 11, fontWeight: 700,
              boxShadow: '0 4px 15px rgba(239, 68, 68, 0.3)'
            }}>DESTROY_VIEW [X]</button>
          </div>
        </div>

        {/* Content Area */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '40px 60px', color: '#d1d5db', fontSize: 14, lineHeight: 1.8, position: 'relative', zIndex: 2 }}>
          <div style={{ maxWidth: 850, margin: '0 auto' }}>
            <ReactMarkdown 
              remarkPlugins={[remarkGfm]}
              components={{
                h1: ({node, ...props}) => <h1 style={{ color: '#fff', fontSize: 28, fontWeight: 900, marginBottom: 32, letterSpacing: '-0.5px' }} {...props} />,
                h2: ({node, ...props}) => <h2 style={{ color: '#a855f7', fontSize: 16, fontWeight: 800, marginTop: 48, marginBottom: 20, borderBottom: '1px solid rgba(168,85,247,0.2)', paddingBottom: 10, textTransform: 'uppercase', letterSpacing: '2px' }} {...props} />,
                h3: ({node, ...props}) => <h3 style={{ color: '#00f0ff', fontSize: 14, fontWeight: 800, marginTop: 24, marginBottom: 12 }} {...props} />,
                blockquote: ({node, ...props}) => <blockquote style={{ borderLeft: '4px solid #a855f7', padding: '16px 24px', margin: '24px 0', background: 'rgba(168,85,247,0.03)', fontStyle: 'italic', borderRadius: '0 12px 12px 0', border: '1px solid rgba(168,85,247,0.1)', borderLeftWidth: 4 }} {...props} />,
                table: ({node, ...props}) => <div style={{ overflowX: 'auto', margin: '24px 0' }}><table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, background: 'rgba(255,255,255,0.01)', borderRadius: 12, overflow: 'hidden' }} {...props} /></div>,
                th: ({node, ...props}) => <th style={{ background: 'rgba(0,0,0,0.3)', borderBottom: '1px solid #1f2937', padding: '12px 16px', textAlign: 'left', color: '#a855f7', fontWeight: 800, fontFamily: 'monospace' }} {...props} />,
                td: ({node, ...props}) => <td style={{ borderBottom: '1px solid #111', padding: '12px 16px', fontFamily: 'monospace' }} {...props} />,
                hr: () => <hr style={{ border: 'none', borderTop: '1px solid rgba(255,255,255,0.05)', margin: '40px 0' }} />,
                code: ({node, className, children, ...props}: any) => {
                  const match = /language-(\w+)/.exec(className || '');
                  return !match ? (
                    <code style={{ background: '#111', padding: '3px 8px', borderRadius: 6, color: '#f87171', fontFamily: 'monospace', fontWeight: 700 }} {...props}>{children}</code>
                  ) : (
                    <div style={{ position: 'relative', margin: '20px 0' }}>
                      <div style={{ position: 'absolute', top: 0, right: 0, background: '#1f2937', color: '#9ca3af', padding: '4px 10px', fontSize: 10, borderRadius: '0 8px 0 8px', fontFamily: 'monospace' }}>{match[1].toUpperCase()}</div>
                      <pre style={{ background: '#0a0a0a', padding: 24, borderRadius: 12, border: '1px solid #1f2937', overflowX: 'auto', fontFamily: 'monospace', fontSize: 12, color: '#10b981', lineHeight: 1.5 }}>
                        <code className={className} {...props}>{children}</code>
                      </pre>
                    </div>
                  );
                }
              }}
            >
              {GENERATE_EXPERT_REPORT(data)}
            </ReactMarkdown>
          </div>
        </div>

        {/* Footer Actions */}
        <div style={{ 
          padding: '20px 40px', borderTop: '1px solid rgba(255,255,255,0.05)', 
          background: 'rgba(0,0,0,0.5)', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          position: 'relative', zIndex: 2
        }}>
          <div style={{ display: 'flex', gap: 24 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 10, color: '#6b7280', fontFamily: 'monospace' }}>CORRELATION_SCORE:</span>
              <span style={{ color: '#00f0ff', fontFamily: 'monospace', fontWeight: 800 }}>98.2%</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 10, color: '#6b7280', fontFamily: 'monospace' }}>SEC_ENTITIES:</span>
              <span style={{ color: '#a855f7', fontFamily: 'monospace', fontWeight: 800 }}>{data.iocs} FOUND</span>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 12 }}>
             <button style={{ 
              background: 'linear-gradient(135deg, #a855f7, #00f0ff)', border: 'none', 
              borderRadius: 12, padding: '12px 24px', color: '#000', 
              cursor: 'pointer', fontFamily: 'monospace', fontSize: 11, fontWeight: 900,
              boxShadow: '0 4px 20px rgba(0,240,255,0.2)'
            }}>PUSH_TO_SIEM [SOAR_READY]</button>
          </div>
        </div>
      </div>
    </div>
  );
}
