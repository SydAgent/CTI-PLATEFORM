"use client";

import React, { useMemo } from 'react';
import { useOnyxStore, type WSEvent } from '@/lib/store';
import * as Tooltip from '@radix-ui/react-tooltip';

interface NLPEntity {
  text: string;
  label: string;
  confidence: number;
  start: number;
  end: number;
}

interface NLPPayload {
  text: string;
  entities: NLPEntity[];
}

const COLOR_MAP: Record<string, string> = {
  ACTOR: 'bg-rose-500/20 text-rose-400 border-rose-500/40',
  TTP: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
  IP: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40',
  MALWARE: 'bg-purple-500/20 text-purple-400 border-purple-500/40',
  ORG: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
  LOC: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
};

export default function SciBERTEngine() {
  const events = useOnyxStore((s) => s.events);
  
  // Extraire le dernier événement NLP du store
  const lastNlpEvent = useMemo(() => {
    const nlpEvents = events.filter((e) => e.type === 'nlp_extraction');
    return nlpEvents.length > 0 ? nlpEvents[0] : null;
  }, [events]);

  if (!lastNlpEvent) {
    return (
      <div className="h-full min-h-[400px] w-full bg-[#0a0e17] border border-slate-800/60 rounded-xl flex flex-col items-center justify-center p-8 shadow-2xl relative overflow-hidden group">
        <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/5 to-purple-500/5 opacity-50" />
        <div className="relative z-10 flex flex-col items-center gap-6">
          <div className="relative flex items-center justify-center w-20 h-20">
            <div className="absolute inset-0 border-t-2 border-indigo-500 rounded-full animate-spin opacity-20" />
            <div className="absolute inset-2 border-r-2 border-purple-500 rounded-full animate-spin opacity-40 animation-delay-150" />
            <div className="absolute inset-4 border-b-2 border-cyan-500 rounded-full animate-spin opacity-60 animation-delay-300" />
            <span className="text-3xl">🧠</span>
          </div>
          <div className="text-center space-y-2">
            <h3 className="text-lg font-bold text-slate-200 tracking-wide font-mono uppercase">Moteur SciBERT</h3>
            <p className="text-sm text-slate-500 font-mono tracking-wider animate-pulse">En attente d'analyse NLP...</p>
          </div>
        </div>
      </div>
    );
  }

  const payload = lastNlpEvent.data as unknown as NLPPayload;
  const { text, entities } = payload;

  // Rendu intelligent du texte avec surbrillance
  const renderTextWithHighlights = () => {
    if (!text || !entities || entities.length === 0) return <p className="text-slate-300">{text || "Texte vide"}</p>;

    // Trier les entités par position de début
    const sortedEntities = [...entities].sort((a, b) => a.start - b.start);
    const nodes: React.ReactNode[] = [];
    let currentIndex = 0;

    sortedEntities.forEach((entity, index) => {
      if (entity.start > currentIndex) {
        nodes.push(
          <span key={`text-${index}`} className="text-slate-300 leading-relaxed">
            {text.substring(currentIndex, entity.start)}
          </span>
        );
      }

      const entityColorClass = COLOR_MAP[entity.label] || 'bg-slate-500/20 text-slate-400 border-slate-500/40';

      nodes.push(
        <Tooltip.Provider key={`entity-${index}`} delayDuration={100}>
          <Tooltip.Root>
            <Tooltip.Trigger asChild>
              <span className={`inline-block px-1.5 py-0.5 mx-0.5 border rounded cursor-pointer transition-all duration-200 hover:shadow-[0_0_15px_rgba(255,255,255,0.1)] hover:-translate-y-0.5 ${entityColorClass}`}>
                {text.substring(entity.start, entity.end)}
              </span>
            </Tooltip.Trigger>
            <Tooltip.Portal>
              <Tooltip.Content
                className="z-50 px-4 py-3 bg-[#0d1320] border border-slate-700/80 rounded-lg shadow-2xl animate-in fade-in zoom-in-95 duration-200"
                sideOffset={5}
              >
                <div className="flex flex-col gap-2">
                  <div className="flex items-center justify-between gap-4">
                    <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">{entity.label}</span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${entity.confidence >= 0.9 ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'}`}>
                      Confidence: {Math.round(entity.confidence * 100)}%
                    </span>
                  </div>
                  <p className="text-sm text-slate-200 font-semibold">{entity.text}</p>
                </div>
                <Tooltip.Arrow className="fill-[#0d1320]" />
              </Tooltip.Content>
            </Tooltip.Portal>
          </Tooltip.Root>
        </Tooltip.Provider>
      );

      currentIndex = entity.end;
    });

    if (currentIndex < text.length) {
      nodes.push(
        <span key="text-end" className="text-slate-300 leading-relaxed">
          {text.substring(currentIndex)}
        </span>
      );
    }

    return nodes;
  };

  return (
    <div className="h-full min-h-[400px] w-full bg-[#05080f] border border-slate-800 rounded-xl overflow-hidden flex flex-col shadow-2xl">
      <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800/80 bg-[#080c16]">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse shadow-[0_0_8px_#6366f1]" />
          <h2 className="text-sm font-bold text-slate-100 uppercase tracking-widest font-mono">SciBERT Recon Engine</h2>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-indigo-400 bg-indigo-500/10 border border-indigo-500/30 px-2 py-0.5 rounded">
            scibert-scivocab-uncased
          </span>
          <span className="text-[10px] font-mono text-slate-400 bg-slate-800/50 border border-slate-700 px-2 py-0.5 rounded">
            LIVE
          </span>
        </div>
      </div>
      
      <div className="p-6 overflow-y-auto flex-1 font-sans text-base">
        {renderTextWithHighlights()}
      </div>

      <div className="px-5 py-3 border-t border-slate-800/80 bg-[#080c16] flex flex-wrap gap-3">
        {Object.entries(COLOR_MAP).map(([label, colorClass]) => (
          <div key={label} className="flex items-center gap-1.5">
            <span className={`w-3 h-3 rounded-sm border ${colorClass}`} />
            <span className="text-[10px] font-mono text-slate-400 uppercase">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
