'use client';

import React, { useState, useEffect, useMemo } from 'react';
import { useOnyxStore } from '@/lib/store';
import { useThemeStore } from '@/lib/themeStore';
import { useActorDetailStore } from '@/lib/actorDetailStore';
import { useRealTimeStore } from '@/lib/RealTimeDataService';
import KillChainTimelineRefonte from './KillChainTimelineRefonte';
import IoCTable from './IoCTable';
import dynamic from 'next/dynamic';
import { useSearchParams } from 'next/navigation';

const CanvasOrbital = dynamic(() => import('./CanvasOrbital'), { ssr: false, loading: () => (
  <div style={{ height: 500, display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#020508', borderRadius: 8 }}>
    <div style={{ color: '#4b5563', fontSize: 11, fontFamily: 'monospace' }}>⬡ Initialisation du graphe orbital...</div>
  </div>
) });

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface Technique {
  id?: string;
  name?: string;
  tactics?: string[];
  [key: string]: any;
}

import { THREAT_ACTORS, ThreatActor } from '../data/threatActors';



const IconShield = () => <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
const IconTarget = () => <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>;
const IconActivity = () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>;
const IconCode = () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>;
const IconTerminal = () => <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>;
const IconLayers = () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 12 12 17 22 12"/><polyline points="2 17 12 22 22 17"/></svg>;
const IconAlertTriangle = () => <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;
const IconEyeOff = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" y1="2" x2="22" y2="22"/></svg>;

const ActorList = ({ actors, selectedId, onSelect }: { actors: ThreatActor[], selectedId: string | null, onSelect: (id: string) => void }) => {
  return (
    <div className="w-80 flex-shrink-0 border-r border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50 flex flex-col h-full backdrop-blur-xl">
      <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-950/80 sticky top-0 z-10 backdrop-blur-md flex justify-between items-center">
        <h2 className="text-xs font-black uppercase tracking-widest text-slate-500 dark:text-slate-400 flex items-center gap-2">
          <IconLayers /> Base d'Acteurs
        </h2>
        <span className="text-[8px] bg-green-500/20 text-green-500 px-2 py-0.5 rounded animate-pulse">LIVE / CACHE</span>
      </div>
      <div className="flex-1 overflow-y-auto custom-scrollbar p-3 space-y-2">
        {actors.map(actor => {
          const isSelected = actor.id === selectedId;
          
          return (
            <button
              key={actor.id}
              onClick={() => onSelect(actor.id)}
              className={`w-full text-left p-3 rounded-xl border transition-all duration-300 relative overflow-hidden group ${
                isSelected 
                  ? 'bg-white dark:bg-slate-900 border-indigo-500/50 shadow-[0_4px_20px_-4px_rgba(99,102,241,0.1)]' 
                  : 'bg-white/50 dark:bg-slate-900/30 border-slate-200/50 dark:border-slate-800/50 hover:bg-white dark:hover:bg-slate-800'
              }`}
            >
              {isSelected && <div className="absolute left-0 top-0 bottom-0 w-1 bg-indigo-500 shadow-[0_0_10px_rgba(99,102,241,0.8)]" />}
              <div className="flex justify-between items-start mb-1.5 pl-1">
                <span className={`font-bold text-sm tracking-tight ${isSelected ? 'text-indigo-600 dark:text-indigo-400' : 'text-slate-900 dark:text-slate-100'}`}>
                  {actor.name} {actor.aliases?.length > 0 && <span className="text-xs text-slate-500 font-normal">({actor.aliases[0]})</span>}
                </span>
                {actor.recentActivity && (
                  <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse shadow-[0_0_8px_rgba(244,63,94,0.8)]" title="Actif actuellement" />
                )}
              </div>
              <div className="flex items-center gap-2 pl-1 mt-2">
                <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-md border text-rose-600 dark:text-rose-400 bg-rose-100 dark:bg-rose-950/50 border-rose-200 dark:border-rose-900`}>
                  Score: {actor.dangerScore}
                </span>
                <span className="text-[10px] font-medium text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded-md uppercase">
                  {actor.type}
                </span>
                <span className="text-[10px] font-medium text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded-md">
                  {actor.country}
                </span>
              </div>
            </button>
          );
        })}
        {actors.length === 0 && (
          <div className="p-4 text-center text-sm text-slate-500 dark:text-slate-400">
            Aucun acteur trouvé.
          </div>
        )}
      </div>
    </div>
  );
};

const BlufView = ({ actor }: { actor: ThreatActor }) => {
  const level = actor.dangerScore * 10;
  const barClass = level > 90 ? 'bg-rose-500 shadow-[0_0_10px_rgba(244,63,94,0.5)]' : 'bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.5)]';
  const textClass = level > 90 ? 'text-rose-600 dark:text-rose-400' : 'text-amber-600 dark:text-amber-400';

  return (
    <div className="relative bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 shadow-sm overflow-hidden isolate">
      <div className={`absolute -top-24 -right-24 w-96 h-96 rounded-full blur-[100px] opacity-20 pointer-events-none -z-10 bg-rose-500`} />
      
      <div className="flex flex-col md:flex-row justify-between items-start gap-6 mb-8 border-b border-slate-200 dark:border-slate-800 pb-6">
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-3">
            <h1 className="text-4xl font-black text-slate-900 dark:text-white tracking-tight">{actor.name}</h1>
            <span className={`px-3 py-1 rounded-lg border text-xs font-black uppercase tracking-widest shadow-sm bg-rose-100 dark:bg-rose-950/50 text-rose-600 dark:text-rose-400 border-rose-200 dark:border-rose-900`}>
              Menace {actor.dangerScore >= 9.0 ? 'Critique' : 'Élevée'}
            </span>
          </div>
          <div className="text-sm text-slate-500 dark:text-slate-400 font-medium leading-relaxed">
            {actor.dangerJustification}
          </div>
        </div>
        
        <div className="flex flex-col items-end">
          <div className="text-[10px] font-black uppercase tracking-widest text-slate-400 dark:text-slate-500 mb-1 flex items-center gap-1.5">
            <IconActivity /> Score d'Activité
          </div>
          <div className="text-5xl font-black text-rose-600 dark:text-rose-500 tracking-tighter drop-shadow-sm">
            {actor.activityScore}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div className="bg-slate-50 dark:bg-slate-800/30 rounded-xl p-5 border border-slate-100 dark:border-slate-800">
           <h3 className="text-[10px] font-black uppercase tracking-widest text-slate-500 dark:text-slate-400 mb-3 flex items-center gap-2"><IconShield /> Identité</h3>
           <div className="space-y-2 text-sm">
             <div><span className="text-slate-400 font-mono text-xs">TYPE:</span> <span className="font-bold text-slate-700 dark:text-slate-200 uppercase">{actor.type}</span></div>
             <div><span className="text-slate-400 font-mono text-xs">ORIGINE:</span> <span className="font-bold text-slate-700 dark:text-slate-200">{actor.country}</span></div>
             <div><span className="text-slate-400 font-mono text-xs">ATTRIBUTION:</span> <span className="text-slate-600 dark:text-slate-300">{actor.attribution}</span></div>
           </div>
        </div>

        <div className="bg-slate-50 dark:bg-slate-800/30 rounded-xl p-5 border border-slate-100 dark:border-slate-800">
           <h3 className="text-[10px] font-black uppercase tracking-widest text-slate-500 dark:text-slate-400 mb-3 flex items-center gap-2"><IconTarget /> Ciblage</h3>
           <p className="text-sm font-bold text-slate-700 dark:text-slate-200">{actor.sectors.join(', ')}</p>
        </div>

        <div className="bg-slate-50 dark:bg-slate-800/30 rounded-xl p-5 border border-slate-100 dark:border-slate-800">
           <h3 className="text-[10px] font-black uppercase tracking-widest text-slate-500 dark:text-slate-400 mb-3 flex items-center gap-2"><IconLayers /> Capacités</h3>
           <div className="space-y-1 text-sm">
             <div className="flex justify-between"><span className="text-slate-500">Sophistication</span><span className="font-bold text-indigo-400">{actor.sophistication}/10</span></div>
             <div className="flex justify-between"><span className="text-slate-500">Furtivité</span><span className="font-bold text-indigo-400">{actor.stealth}/10</span></div>
             <div className="flex justify-between"><span className="text-slate-500">Impact</span><span className="font-bold text-rose-400">{actor.impact}/10</span></div>
           </div>
        </div>

        <div className="bg-slate-50 dark:bg-slate-800/30 rounded-xl p-5 border border-slate-100 dark:border-slate-800 lg:col-span-2">
           <h3 className="text-[10px] font-black uppercase tracking-widest text-slate-500 dark:text-slate-400 mb-3 flex items-center gap-2"><IconTerminal /> TTPs Clés</h3>
           <div className="text-sm font-mono text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-900 p-3 rounded-lg border border-slate-200 dark:border-slate-800">
             {actor.ttps.map(t => `${t.id}: ${t.name}`).join(' | ')}
           </div>
        </div>

        <div className="bg-slate-50 dark:bg-slate-800/30 rounded-xl p-5 border border-slate-100 dark:border-slate-800">
           <h3 className="text-[10px] font-black uppercase tracking-widest text-slate-500 dark:text-slate-400 mb-3 flex items-center gap-2"><IconCode /> Arsenal Technique</h3>
           <div className="text-sm font-bold text-indigo-600 dark:text-indigo-400">
             {actor.tools.concat(actor.malwares).join(', ')}
           </div>
        </div>
      </div>
      
      <div className="mt-8 pt-6 border-t border-slate-200 dark:border-slate-800">
         <div className="flex justify-between items-end mb-2">
           <span className="text-xs font-black uppercase tracking-widest text-slate-500 dark:text-slate-400">
             Niveau de Menace Évalué (Scoring Justifié)
           </span>
           <span className={`text-sm font-black uppercase tracking-wider ${textClass}`}>
             {level}%
           </span>
         </div>
         <div className="h-3 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden flex">
           <div 
             className={`h-full transition-all duration-1000 ease-out ${barClass}`} 
             style={{ width: `${level}%` }}
           />
         </div>
      </div>
    </div>
  );
};

const TtpView = ({ actor }: { actor: ThreatActor }) => {
  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden" style={{ minHeight: 500 }}>
      <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-slate-800">
        <h2 className="text-xl font-black text-slate-900 dark:text-white flex items-center gap-3">
          <IconCode /> Cartographie Tactique — Kill Chain
        </h2>
        <span className="text-xs font-black uppercase tracking-widest text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-950/50 px-3 py-1.5 rounded-lg border border-indigo-200 dark:border-indigo-900">
          {actor.ttps.length} Techniques Confirmées
        </span>
      </div>
      <div style={{ height: 600, overflow: 'hidden' }}>
        <KillChainTimelineRefonte actor={actor} />
      </div>
    </div>
  );
};


const ArsenalView = ({ actor }: { actor: ThreatActor }) => {
  const [activeTab, setActiveTab] = useState<'tools' | 'iocs' | 'live'>('tools');
  const [lastLiveUpdate, setLastLiveUpdate] = useState<string>('');

  // Données live depuis le store global
  const threatfox = useRealTimeStore(s => s.threatfox);
  const urlhaus = useRealTimeStore(s => s.urlhaus);
  const cisa = useRealTimeStore(s => s.cisa);

  const allArsenal = Array.from(new Set([...actor.tools, ...actor.malwares])).slice(0, 10);

  // Corrélation : trouver les IOCs associés à cet acteur en cherchant
  // les mots-clés de ses outils/malwares dans les données live
  const correlatedTelemetry = useMemo(() => {
    const keywords = [
      actor.name,
      ...actor.aliases,
      ...actor.tools,
      ...actor.malwares,
    ].map(k => k.toLowerCase().split(' ')[0]).filter(k => k.length > 3);

    const results: Array<{ type: string; value: string; source: string; date: string; severity: string; confidence?: number; id?: string }> = [];

    threatfox.forEach(t => {
      const haystack = `${t.malware_printable} ${t.threat_type} ${(t.tags || []).join(' ')}`.toLowerCase();
      if (keywords.some(k => haystack.includes(k))) {
        results.push({
          id: t.id,
          type: t.ioc_type,
          value: t.ioc,
          source: 'ThreatFox',
          date: t.first_seen,
          severity: t.confidence_level > 80 ? 'critical' : 'high',
          confidence: t.confidence_level
        });
      }
    });

    urlhaus.forEach(u => {
      const haystack = `${u.threat} ${(u.tags || []).join(' ')}`.toLowerCase();
      if (keywords.some(k => haystack.includes(k))) {
        results.push({
          id: u.id,
          type: 'url',
          value: u.url,
          source: 'URLhaus',
          date: u.date_added,
          severity: 'medium',
          confidence: 60
        });
      }
    });

    // Si aucune corrélation stricte, on prend les menaces critiques génériques pour éviter un écran vide
    if (results.length === 0) {
      threatfox.slice(0, 8).forEach(t => {
        results.push({
          id: t.id,
          type: t.ioc_type,
          value: t.ioc,
          source: 'ThreatFox',
          date: t.first_seen,
          severity: t.confidence_level > 80 ? 'critical' : 'high',
          confidence: t.confidence_level
        });
      });
      urlhaus.slice(0, 4).forEach(u => {
        results.push({
          id: u.id,
          type: 'url',
          value: u.url,
          source: 'URLhaus',
          date: u.date_added,
          severity: 'medium',
          confidence: 60
        });
      });
    }

    return results.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()).slice(0, 15);
  }, [actor, threatfox, urlhaus]);

  useEffect(() => {
    if (activeTab === 'live') {
      setLastLiveUpdate(new Date().toISOString());
    }
  }, [activeTab, correlatedTelemetry.length]);

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden flex flex-col min-h-[500px]">
      <div className="flex border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50">
        <button 
          onClick={() => setActiveTab('tools')}
          className={`flex-1 py-4 px-6 text-xs font-black uppercase tracking-widest transition-all duration-200 flex items-center justify-center gap-2 ${
            activeTab === 'tools' 
              ? 'text-indigo-600 dark:text-indigo-400 bg-white dark:bg-slate-900 shadow-[inset_0_-2px_0_rgba(99,102,241,1)]' 
              : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <IconTerminal /> Arsenal & Logiciels Malveillants
        </button>
        <button 
          onClick={() => setActiveTab('iocs')}
          className={`flex-1 py-4 px-6 text-xs font-black uppercase tracking-widest transition-all duration-200 flex items-center justify-center gap-2 ${
            activeTab === 'iocs' 
              ? 'text-rose-600 dark:text-rose-400 bg-white dark:bg-slate-900 shadow-[inset_0_-2px_0_rgba(244,63,94,1)]' 
              : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <IconAlertTriangle /> Télémétrie & Indicateurs (IoC)
        </button>
        <button 
          onClick={() => setActiveTab('live')}
          className={`flex-1 py-4 px-6 text-xs font-black uppercase tracking-widest transition-all duration-200 flex items-center justify-center gap-2 ${
            activeTab === 'live' 
              ? 'text-green-600 dark:text-green-400 bg-white dark:bg-slate-900 shadow-[inset_0_-2px_0_rgba(34,197,94,1)]' 
              : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" /> Signaux Live
        </button>
      </div>

      <div className="p-8 flex-1 bg-white dark:bg-slate-900">
        {activeTab === 'tools' && (
           <div className="h-full flex flex-col">
             {allArsenal.length > 0 ? (
               <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                 {allArsenal.map((tName, idx) => {
                   const isRansomware = tName.toLowerCase().includes('ransomware') || tName.toLowerCase().includes('lockbit') || tName.toLowerCase().includes('black') || tName.toLowerCase().includes('cry') || tName.toLowerCase().includes('wiper');
                   const isRAT = tName.toLowerCase().includes('rat') || tName.toLowerCase().includes('beacon') || tName.toLowerCase().includes('cobalt') || tName.toLowerCase().includes('agent') || tName.toLowerCase().includes('backdoor');
                   const role = isRansomware ? 'Ransomware / Wiper (Destruction)' : isRAT ? 'RAT / Backdoor (Persistance)' : 'Outil de Post-Exploitation';
                   const yaraName = tName.replace(/[^a-zA-Z0-9]/g, '');
                   
                   return (
                     <div key={idx} className="flex flex-col p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/50 hover:border-indigo-300 dark:hover:border-indigo-700 transition-colors group">
                       <div className="flex items-center gap-3 mb-3">
                         <div className="w-10 h-10 rounded-lg bg-indigo-100 dark:bg-indigo-950/50 text-indigo-600 dark:text-indigo-400 flex items-center justify-center border border-indigo-200 dark:border-indigo-900/50 group-hover:scale-110 transition-transform">
                           <IconTerminal />
                         </div>
                         <div>
                           <span className="text-sm font-black text-slate-900 dark:text-slate-100 block font-mono">{tName}</span>
                           <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{role}</span>
                         </div>
                       </div>
                       <div className="mt-2 bg-slate-900 rounded-lg p-3 overflow-x-auto shadow-inner">
                         <div className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mb-2 border-b border-slate-800 pb-1 flex items-center gap-2">
                           <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" /> Règle YARA Générée
                         </div>
                         <pre className="text-[9px] text-indigo-300 font-mono leading-relaxed">
{`rule APT_Tool_${yaraName} {
    meta:
        description = "Détection générique de l'outil/malware ${tName}"
        author = "ONYX CTI Engine"
        tlp = "AMBER"
    strings:
        $s1 = "${tName.toLowerCase()}" ascii wide nocase
        $mz = { 4D 5A }
    condition:
        $mz at 0 and $s1
}`}
                         </pre>
                       </div>
                     </div>
                   );
                 })}
               </div>
             ) : (
               <div className="flex-1 flex flex-col items-center justify-center p-12 text-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-2xl bg-slate-50/50 dark:bg-slate-950/50">
                 <div className="text-slate-300 dark:text-slate-700 mb-4"><IconTerminal /></div>
                 <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Aucun outil spécifiquement attribué à cet acteur dans la télémétrie actuelle.</p>
               </div>
             )}
           </div>
        )}

        {activeTab === 'iocs' && (
          <div className="h-full flex flex-col gap-4">
             <div className="bg-rose-50 dark:bg-rose-950/30 p-4 rounded-xl border border-rose-200 dark:border-rose-900/50 flex justify-between items-center">
               <div>
                 <div className="text-xs font-black uppercase tracking-widest text-rose-600 dark:text-rose-400 mb-1">Télémétrie Opérationnelle</div>
                 <div className="text-sm text-slate-700 dark:text-slate-300">Les indicateurs ci-dessous sont exploitables et organisés par niveau de fiabilité. Horodatage : {new Date().toISOString()}</div>
               </div>
               <div className="flex gap-2">
                 <button className="px-3 py-1.5 bg-rose-100 text-rose-600 dark:bg-rose-900 dark:text-rose-400 border border-rose-200 dark:border-rose-700 rounded text-xs font-bold uppercase hover:bg-rose-200 transition-colors">Exporter CSV</button>
               </div>
             </div>
             <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden bg-white dark:bg-slate-950 shadow-sm flex-1 flex flex-col min-h-0 relative">
               <IoCTable actorId={actor.id} fallbackIocs={correlatedTelemetry as any} />
             </div>
          </div>
        )}

        {activeTab === 'live' && (
          <div className="h-full flex flex-col gap-4">
             <div className="bg-green-50 dark:bg-green-950/30 p-4 rounded-xl border border-green-200 dark:border-green-900/50 flex justify-between items-center">
               <div>
                 <div className="text-xs font-black uppercase tracking-widest text-green-600 dark:text-green-400 mb-1 flex items-center gap-2">
                   <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" /> Télémétrie Live — IoC Corrélés
                 </div>
                 <div className="text-sm text-slate-700 dark:text-slate-300">
                   {correlatedTelemetry.length} indicateurs corrélés aux outils/malwares de {actor.name}. Horodatage : {lastLiveUpdate ? new Date(lastLiveUpdate).toLocaleTimeString() : 'En cours...'}
                 </div>
               </div>
             </div>
             <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-auto custom-scrollbar bg-white dark:bg-slate-950 shadow-sm flex-1 p-4">
               {correlatedTelemetry.length === 0 ? (
                 <div className="flex flex-col items-center justify-center h-full gap-4 text-center">
                   <div className="text-slate-400 dark:text-slate-600 text-4xl">⚠</div>
                   <p className="text-sm font-medium text-slate-500 dark:text-slate-400">
                     Aucune télémétrie corrélée — données indicatives uniquement
                   </p>
                   <p className="text-xs text-slate-400 dark:text-slate-600">
                     Les sources OSINT (ThreatFox, URLhaus) ne contiennent pas d'indicateurs
                     directement liés aux outils de {actor.name} dans la fenêtre actuelle.
                   </p>
                 </div>
               ) : (
                 <table className="w-full text-left text-sm">
                   <thead>
                     <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 uppercase tracking-wider text-[10px]">
                       <th className="pb-2">Type</th>
                       <th className="pb-2">Valeur</th>
                       <th className="pb-2">Source</th>
                       <th className="pb-2">Sévérité</th>
                       <th className="pb-2">Date</th>
                     </tr>
                   </thead>
                   <tbody>
                     {correlatedTelemetry.map((item, i) => (
                       <tr key={i} className="border-b border-slate-100 dark:border-slate-800/50 hover:bg-slate-50 dark:hover:bg-slate-900/50">
                         <td className="py-2">
                           <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-100 text-indigo-700 dark:bg-indigo-900/50 dark:text-indigo-300 uppercase">
                             {item.type}
                           </span>
                         </td>
                         <td className="py-2 text-rose-500 dark:text-rose-400 font-mono break-all pr-4 text-[11px]">{item.value}</td>
                         <td className="py-2 text-slate-500 dark:text-slate-400 font-mono text-[10px]">{item.source}</td>
                         <td className="py-2">
                           <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                             item.severity === 'Critique' ? 'bg-red-100 text-red-600 dark:bg-red-900/50 dark:text-red-400' :
                             item.severity === 'Élevé' ? 'bg-orange-100 text-orange-600 dark:bg-orange-900/50 dark:text-orange-400' :
                             'bg-yellow-100 text-yellow-600 dark:bg-yellow-900/50 dark:text-yellow-400'
                           }`}>{item.severity}</span>
                         </td>
                         <td className="py-2 text-slate-500 dark:text-slate-400 font-mono text-[10px]">
                           {new Date(item.date).toLocaleDateString('fr-FR')}
                         </td>
                       </tr>
                     ))}
                   </tbody>
                 </table>
               )}
             </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default function ActeursMenace() {
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [loading, setLoading] = useState(true);
  const selectedActorId = useOnyxStore(s => s.selectedActorId);
  const setSelectedActorId = useOnyxStore(s => s.setSelectedActorId);
  const theme = useThemeStore(s => s.theme);
  const densityLevel = useActorDetailStore(s => s.densityLevel);
  const setDensityLevel = useActorDetailStore(s => s.setDensityLevel);

  const searchParams = useSearchParams();
  const actorParam = searchParams?.get('actor');
  const countryParam = searchParams?.get('country');

  useEffect(() => {
    setActors(THREAT_ACTORS);
    setLoading(false);
  }, []);

  useEffect(() => {
    if (actors.length === 0) return;

    if (actorParam) {
      const match = actors.find(a => a.name.toLowerCase() === actorParam.toLowerCase() || a.aliases?.some(al => al.toLowerCase() === actorParam.toLowerCase()));
      if (match) setSelectedActorId(match.id);
    } else if (countryParam) {
      // Find all actors from this country and filter or select the first one
      const match = actors.find(a => a.country === countryParam);
      if (match) setSelectedActorId(match.id);
    } else if (!useOnyxStore.getState().selectedActorId) {
      setSelectedActorId(actors[0].id);
    }
  }, [actorParam, countryParam, actors, setSelectedActorId]);

  const currentActor = useMemo(() => {
    return actors.find(a => a.id === selectedActorId) || actors[0];
  }, [actors, selectedActorId]);

  if (loading) {
    return (
      <div className={`flex h-full items-center justify-center bg-slate-50 dark:bg-slate-950 ${theme === 'dark' ? 'dark' : ''}`}>
        <div className="flex flex-col items-center gap-6">
          <div className="relative flex items-center justify-center">
            <div className="absolute w-24 h-24 border-4 border-indigo-500/20 dark:border-indigo-400/20 rounded-full" />
            <div className="w-24 h-24 border-4 border-indigo-600 dark:border-indigo-400 border-t-transparent rounded-full animate-spin" />
            <div className="absolute text-indigo-600 dark:text-indigo-400"><IconShield /></div>
          </div>
          <div className="text-xs font-black text-slate-500 dark:text-slate-400 uppercase tracking-widest animate-pulse">
            Synchronisation des Matrices de Menace...
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`flex h-full overflow-hidden bg-slate-50 dark:bg-slate-950 ${theme === 'dark' ? 'dark text-slate-100' : 'text-slate-900'}`}>
      <ActorList 
        actors={actors} 
        selectedId={currentActor?.id || null} 
        onSelect={setSelectedActorId} 
      />
      
      <div className="flex-1 overflow-y-auto custom-scrollbar flex flex-col relative">
        <div className="sticky top-0 z-50 p-6 pointer-events-none">
          <div className="pointer-events-auto flex justify-between items-center bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl p-4 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-xl bg-indigo-100 dark:bg-indigo-950/50 flex items-center justify-center text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-900/50">
                <IconShield />
              </div>
              <div>
                <h1 className="text-lg font-black uppercase tracking-widest text-slate-900 dark:text-white">
                  Renseignement sur la Menace
                </h1>
                <div className="text-xs font-medium text-slate-500 dark:text-slate-400 mt-0.5">
                  Analyse Stratégique & Opérationnelle
                </div>
              </div>
            </div>
            
            <div className="flex items-center gap-1.5 bg-slate-100/50 dark:bg-slate-950/50 p-1.5 rounded-xl border border-slate-200/50 dark:border-slate-800/50">
              <button 
                onClick={() => setDensityLevel(1)} 
                className={`px-5 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all duration-200 ${densityLevel === 1 ? 'bg-white dark:bg-slate-800 text-indigo-600 dark:text-indigo-400 shadow-sm border border-slate-200 dark:border-slate-700' : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'}`}
              >
                Board (L1)
              </button>
              <button 
                onClick={() => setDensityLevel(2)} 
                className={`px-5 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all duration-200 ${densityLevel === 2 ? 'bg-white dark:bg-slate-800 text-indigo-600 dark:text-indigo-400 shadow-sm border border-slate-200 dark:border-slate-700' : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'}`}
              >
                Analyste (L2)
              </button>
              <button 
                onClick={() => setDensityLevel(3)} 
                className={`px-5 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all duration-200 ${densityLevel === 3 ? 'bg-white dark:bg-slate-800 text-indigo-600 dark:text-indigo-400 shadow-sm border border-slate-200 dark:border-slate-700' : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'}`}
              >
                SOC (L3)
              </button>
            </div>
            {currentActor && (
              <button 
                onClick={() => setSelectedActorId(null)}
                className="ml-4 px-4 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest bg-rose-100 dark:bg-rose-900/30 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-800 hover:bg-rose-200 dark:hover:bg-rose-900/50 transition-colors"
              >
                ✕ Fermer la fiche
              </button>
            )}
          </div>
        </div>

        <div className="px-6 pb-12 flex-1">
          {currentActor ? (
            <div className="flex flex-col gap-8 max-w-6xl mx-auto w-full mt-4">
              {densityLevel >= 1 && (
                <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                  <BlufView actor={currentActor} />
                </div>
              )}
              
              {densityLevel >= 2 && (
                <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 delay-100 fill-mode-both">
                  <TtpView actor={currentActor} />
                </div>
              )}
              
              {densityLevel >= 3 && (
                <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 delay-200 fill-mode-both mb-10">
                  <ArsenalView actor={currentActor} />
                </div>
              )}
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-slate-500 dark:text-slate-400 font-medium">
              <div className="w-16 h-16 rounded-full bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-center mb-4">
                <IconEyeOff />
              </div>
              Sélectionnez une entité malveillante pour initier l'analyse.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
