"use client";

import React, { useState, useCallback } from 'react';
import { Target, Search, Lock, Zap, Server, Send, Skull, ChevronRight } from 'lucide-react';

const PHASES = [
  {
    id: 'recon', num: '01', titre: 'Reconnaissance', sousTitre: 'Collecte d\'informations',
    icon: <Search size={18}/>, colorClass: 'text-slate-500 dark:text-slate-400', bgClass: 'bg-slate-500',
    description: 'L\'attaquant collecte des informations sur la cible via OSINT, scan réseau actif, ingénierie sociale et exploitation des réseaux sociaux.',
    indicateurs: ['Scan de ports massif', 'Requêtes DNS inhabituelles', 'Harvesting LinkedIn/GitHub', 'Analyse de sous-domaines'],
    acteurs: ['APT29', 'Volt Typhoon', 'APT41'],
    criticite: 'moyen',
  },
  {
    id: 'weaponize', num: '02', titre: 'Militarisation', sousTitre: 'Développement des outils',
    icon: <Zap size={18}/>, colorClass: 'text-violet-500 dark:text-violet-400', bgClass: 'bg-violet-500',
    description: 'Création ou acquisition des outils offensifs : exploits zero-day, backdoors, droppers, infrastructure C2 déployée.',
    indicateurs: ['Enregistrement de domaines lookalike', 'Certificats TLS suspects', 'Infrastructure C2 hébergée', 'Compilation de payloads'],
    acteurs: ['Lazarus Group', 'FIN7', 'Cl0p'],
    criticite: 'eleve',
  },
  {
    id: 'delivery', num: '03', titre: 'Livraison', sousTitre: 'Vecteur d\'accès initial',
    icon: <Send size={18}/>, colorClass: 'text-blue-500 dark:text-blue-400', bgClass: 'bg-blue-500',
    description: 'Transmission du vecteur malveillant via spear-phishing ciblé, exploitation de services exposés, compromission supply-chain.',
    indicateurs: ['Emails de spear-phishing', 'Exploitation CVE récentes', 'Pièces jointes malveillantes', 'URLs de drive-by'],
    acteurs: ['APT29', 'APT41', 'Lazarus Group'],
    criticite: 'eleve',
  },
  {
    id: 'exploit', num: '04', titre: 'Exploitation', sousTitre: 'Exécution sur la cible',
    icon: <Target size={18}/>, colorClass: 'text-amber-500 dark:text-amber-400', bgClass: 'bg-amber-500',
    description: 'Déclenchement de l\'exploit sur le système cible : exécution de code arbitraire, injection de processus, abus d\'interpréteurs.',
    indicateurs: ['PowerShell encodé', 'WMI subscription', 'LOLBin abuse', 'Process injection détecté'],
    acteurs: ['FIN7', 'LockBit', 'APT41'],
    criticite: 'critique',
  },
  {
    id: 'install', num: '05', titre: 'Installation & Persistance', sousTitre: 'Ancrage système',
    icon: <Server size={18}/>, colorClass: 'text-pink-500 dark:text-pink-400', bgClass: 'bg-pink-500',
    description: 'Établissement de la persistance à long terme : backdoors, scheduled tasks, modification du registre, DLL hijacking.',
    indicateurs: ['Clé Run registry', 'Scheduled task suspecte', 'Service système créé', 'Implant installé'],
    acteurs: ['APT29', 'Volt Typhoon', 'Lazarus Group'],
    criticite: 'critique',
  },
  {
    id: 'c2', num: '06', titre: 'Commandement & Contrôle', sousTitre: 'Canal de communication',
    icon: <Lock size={18}/>, colorClass: 'text-cyan-500 dark:text-cyan-400', bgClass: 'bg-cyan-500',
    description: 'Maintien d\'un canal de communication avec l\'infrastructure de l\'attaquant : beaconing HTTPS, tunneling DNS, C2 over CDN.',
    indicateurs: ['Beaconing régulier HTTPS', 'Tunneling DNS', 'C2 via services légitimes', 'Chiffrement custom'],
    acteurs: ['APT29', 'APT41', 'FIN7'],
    criticite: 'critique',
  },
  {
    id: 'action', num: '07', titre: 'Actions sur Objectifs', sousTitre: 'Impact final',
    icon: <Skull size={18}/>, colorClass: 'text-rose-500 dark:text-rose-400', bgClass: 'bg-rose-500',
    description: 'Exécution de l\'objectif final : exfiltration de données, déploiement ransomware, destruction de systèmes, déni de service.',
    indicateurs: ['Exfiltration massive', 'Chiffrement ransomware', 'Suppression de logs', 'Destruction de données'],
    acteurs: ['LockBit', 'Cl0p', 'Lazarus Group'],
    criticite: 'critique',
  },
];

const TACTIC_TO_PHASE: Record<string, string> = {
  'T1595': 'recon', 'T1592': 'recon', 'T1589': 'recon', 'T1590': 'recon', 'T1598': 'recon',
  'T1583': 'weaponize', 'T1584': 'weaponize', 'T1587': 'weaponize', 'T1588': 'weaponize',
  'T1566': 'delivery', 'T1190': 'delivery', 'T1133': 'delivery', 'T1195': 'delivery', 'T1078': 'delivery',
  'T1059': 'exploit', 'T1204': 'exploit', 'T1203': 'exploit', 'T1106': 'exploit', 'T1047': 'exploit',
  'T1547': 'install', 'T1546': 'install', 'T1136': 'install', 'T1574': 'install', 'T1027': 'install', 'T1055': 'install',
  'T1071': 'c2', 'T1095': 'c2', 'T1573': 'c2', 'T1105': 'c2', 'T1572': 'c2', 'T1090': 'c2',
  'T1486': 'action', 'T1490': 'action', 'T1485': 'action', 'T1567': 'action', 'T1041': 'action', 'T1048': 'action',
};

function getPhaseForTTP(ttp: unknown): string {
  const ttpStr = typeof ttp === 'string' ? ttp : String(ttp ?? '');
  if (TACTIC_TO_PHASE[ttpStr]) return TACTIC_TO_PHASE[ttpStr];
  const base = ttpStr.split('.')[0];
  if (TACTIC_TO_PHASE[base]) return TACTIC_TO_PHASE[base];
  let hash = 0;
  for (let i = 0; i < ttpStr.length; i++) hash = ((hash << 5) - hash + ttpStr.charCodeAt(i)) | 0;
  return String(hash);
}

export default function KillChainTimelineRefonte({ actor }: { actor?: any }) {
  const [selectedPhaseId, setSelectedPhaseId] = useState<string | null>(null);

  const phaseData: Record<string, string[]> = {};
  if (actor?.techniques) {
    for (const ttp of actor.techniques as string[]) {
      const phase = getPhaseForTTP(ttp);
      if (!phaseData[phase]) phaseData[phase] = [];
      phaseData[phase].push(ttp);
    }
  }

  const totalTTPs = actor?.techniques?.length || 0;
  const coveredPhases = Object.keys(phaseData).length;

  const handlePhaseClick = useCallback((phaseId: string) => {
    setSelectedPhaseId(prev => prev === phaseId ? null : phaseId);
  }, []);

  return (
    <div className="flex flex-col h-full overflow-hidden bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
      <div className="px-6 py-5 bg-slate-50 dark:bg-slate-900/80 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center shrink-0">
        <div>
          <h3 className="text-lg font-black text-slate-900 dark:text-white flex items-center gap-3 uppercase tracking-widest">
            {actor && <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse shadow-[0_0_10px_rgba(244,63,94,0.6)]" />}
            {actor ? actor.name : 'Cartographie Kill Chain Tactique'}
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-1.5">
            {actor ? `Analyse dynamique : ${totalTTPs} TTPs cartographiées sur ${coveredPhases}/7 phases stratégiques.` : 'Sélectionnez un acteur pour projeter sa Kill Chain et identifier les axes de remédiation.'}
          </p>
        </div>
        <div className="flex gap-2">
          <span className="text-[10px] px-2.5 py-1 rounded-md bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-800 font-bold font-mono">
            {totalTTPs} TTPs
          </span>
          <span className="text-[10px] px-2.5 py-1 rounded-md bg-rose-100 dark:bg-rose-900/30 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-800 font-bold font-mono">
            {coveredPhases}/7 phases
          </span>
        </div>
      </div>

      <div className="flex h-2.5 shrink-0 w-full bg-slate-100 dark:bg-slate-800">
        {PHASES.map(phase => {
          const hasData = !!phaseData[phase.id]?.length;
          const isSelected = selectedPhaseId === phase.id;
          return (
            <div key={phase.id} onClick={() => handlePhaseClick(phase.id)} 
              className={`flex-1 cursor-pointer transition-all duration-300 ${hasData ? phase.bgClass : 'bg-transparent'} ${hasData ? 'opacity-100' : 'opacity-20'} ${isSelected ? 'shadow-[0_0_15px_currentColor] z-10' : ''}`} 
              title={phase.titre} 
            />
          );
        })}
      </div>

        <div className="flex-1 overflow-y-auto px-6 py-6 flex flex-col gap-4 custom-scrollbar">
          {PHASES.map((phase) => {
            const ttps = phaseData[phase.id] || [];
            const hasData = ttps.length > 0;
            const isSelected = selectedPhaseId === phase.id;

            return (
              <div key={phase.id} onClick={() => handlePhaseClick(phase.id)} 
                className={`flex gap-5 p-5 rounded-xl cursor-pointer transition-all duration-200 bg-[#0f172a] shadow-sm font-mono overflow-hidden ${isSelected ? 'ring-2 ring-opacity-50 ring-white' : 'hover:bg-[#1e293b]'} ${!actor || hasData ? 'opacity-100' : 'opacity-40'}`}
                style={{
                  borderTop: `3px solid ${phase.bgClass.replace('bg-', 'var(--').replace('-500', ')')}`,
                  borderColor: phase.id === 'recon' ? '#3b82f6' : phase.id === 'action' ? '#ef4444' : phase.id === 'exploit' ? '#f97316' : phase.id === 'weaponize' ? '#a855f7' : '#22c55e'
                }}
              >
                <div className="flex flex-col items-center gap-1.5 shrink-0">
                  <div className={`w-12 h-12 rounded-xl flex items-center justify-center text-white transition-all duration-300 shadow-lg ${isSelected ? 'scale-110' : ''}`}
                    style={{ background: phase.id === 'recon' ? '#3b82f6' : phase.id === 'action' ? '#ef4444' : phase.id === 'exploit' ? '#f97316' : phase.id === 'weaponize' ? '#a855f7' : '#22c55e' }}>
                    {phase.icon}
                  </div>
                  <span className="text-[10px] font-black text-slate-400 font-mono mt-1 px-2 py-0.5 bg-[#1e293b] rounded">{phase.num}</span>
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex justify-between items-start mb-1.5">
                    <div>
                      <h4 className={`text-base font-black uppercase tracking-wider truncate text-white`}>
                        {phase.titre}
                      </h4>
                      <span className="text-xs text-slate-400 font-bold">{phase.sousTitre}</span>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      {hasData && (
                        <span className={`text-[10px] px-2.5 py-1 rounded-md font-black font-mono border border-slate-200 dark:border-slate-700 shadow-sm ${phase.colorClass} bg-slate-100 dark:bg-slate-800`}>
                          {ttps.length} TTP{ttps.length > 1 ? 's' : ''}
                        </span>
                      )}
                      <span className={`text-[10px] px-2.5 py-1 rounded-md font-black font-mono shadow-sm ${phase.criticite === 'critique' ? 'text-[#ef4444] bg-[#ef4444]/10 border border-[#ef4444]/20' : phase.criticite === 'eleve' ? 'text-[#f97316] bg-[#f97316]/10 border border-[#f97316]/20' : 'text-[#22c55e] bg-[#22c55e]/10 border border-[#22c55e]/20'}`}>
                        {phase.criticite.toUpperCase()}
                      </span>
                      <ChevronRight size={18} className={`text-slate-400 transition-transform duration-300 ${isSelected ? 'rotate-90' : ''}`} />
                    </div>
                  </div>

                  <p className="text-[10px] text-slate-600 dark:text-slate-300 leading-relaxed m-0 mt-2 font-mono">
                    {phase.description}
                  </p>

                  {hasData && (
                    <div className="flex flex-wrap gap-2 mt-3">
                      {ttps.map(ttp => (
                        <span key={ttp} className="text-[10px] px-2 py-1 rounded font-bold font-mono bg-[#0f172a] text-slate-300 border border-slate-700 shadow-sm hover:border-[#00eeff] hover:text-[#00eeff] transition-colors cursor-pointer">
                          {ttp}
                        </span>
                      ))}
                    </div>
                  )}

                  {isSelected && (
                    <div className="mt-4 p-4 bg-[#0a0f1a] rounded-xl border border-slate-800 shadow-inner">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2 font-mono">
                            <span className="text-[#f97316]">⚡</span> Indicateurs de Détection
                          </div>
                          <div className="flex flex-col gap-2">
                            {phase.indicateurs.map((ind, i) => (
                              <div key={i} className="flex items-start gap-2 text-xs font-mono text-slate-300 bg-slate-900/50 p-2 rounded border border-slate-800/50">
                                <span className="text-[#00eeff] mt-0.5 opacity-70">▹</span>
                                <span>{ind}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                        
                        <div>
                          {actor && actor.tools && actor.tools.length > 0 && (
                            <div className="mb-4">
                              <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2 font-mono">
                                <span className="text-indigo-500">⚒</span> Outils & Arsenal
                              </div>
                              <div className="flex flex-wrap gap-2">
                                {actor.tools.slice(0, 4).map((tool: any, i: number) => (
                                  <span key={i} className="text-[10px] px-2 py-1 rounded font-bold font-mono bg-indigo-900/20 text-indigo-300 border border-indigo-800/50">
                                    {typeof tool === 'string' ? tool : tool.name}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                          <div>
                            <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2 font-mono">
                              <span className="text-rose-500">☠</span> Acteurs Connus
                            </div>
                            <div className="flex flex-col gap-2">
                              {phase.acteurs.map((act, i) => (
                                <div key={i} className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-slate-900/50 p-2 rounded border border-slate-800/50">
                                  <span className="text-rose-500 font-black">[{i + 1}]</span>
                                  <span className="font-bold">{act}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  }
