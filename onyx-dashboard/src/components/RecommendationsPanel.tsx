import React, { useEffect, useState } from 'react';
import { ShieldAlert, Terminal, Lock } from 'lucide-react';
import { useT as useTranslation } from '@/lib/i18n/useTranslation';

interface Recommendation {
  action: string;
  commande: string;
  priorite: "CRITIQUE" | "HAUTE" | "MOYENNE" | "FAIBLE";
  justification: string;
}

export function RecommendationsPanel() {
  const t = useTranslation();
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);

  useEffect(() => {
    // Dans le monde réel, on fetcherait /api/recommendations depuis dashboard.py
    // qui appellerait le RecommendationEngine.
    const fetchRecs = async () => {
      // Mock fetch pour l'UI, mais simulant l'API déterministe
      setRecommendations([
        {
          action: "Bloquer IP C2 (Lazarus)",
          commande: "iptables -A INPUT -s 91.108.56.181 -j DROP",
          priorite: "CRITIQUE",
          justification: "IP identifiée dans la campagne de spearphishing en cours."
        },
        {
          action: "Restreindre PowerShell (T1059)",
          commande: "Set-ExecutionPolicy Restricted -Scope LocalMachine",
          priorite: "HAUTE",
          justification: "Prévention d'exécution de payloads sans signature valide."
        }
      ]);
    };
    fetchRecs();
  }, []);

  return (
    <div className="bg-black/40 backdrop-blur-md border border-red-900/50 rounded-xl p-6 text-white font-mono shadow-[0_0_15px_rgba(220,38,38,0.1)]">
      <div className="flex items-center space-x-3 mb-6">
        <ShieldAlert className="w-6 h-6 text-red-500" />
        <h2 className="text-xl font-bold tracking-widest text-red-100 uppercase">
          {t('recommendations.title') || "Actions Recommandées"}
        </h2>
      </div>

      <div className="space-y-4">
        {recommendations.map((rec, idx) => (
          <div key={idx} className="bg-gray-900/50 border border-gray-800 rounded p-4 hover:border-red-500/30 transition-colors">
            <div className="flex justify-between items-start mb-2">
              <span className="text-sm font-bold text-gray-200">{rec.action}</span>
              <span className={`text-[10px] uppercase px-2 py-0.5 rounded tracking-wider ${
                rec.priorite === 'CRITIQUE' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                'bg-orange-500/20 text-orange-400 border border-orange-500/30'
              }`}>
                {rec.priorite}
              </span>
            </div>
            
            <p className="text-xs text-gray-400 mb-3 leading-relaxed">
              {rec.justification}
            </p>
            
            <div className="bg-black rounded border border-gray-800 p-2 flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-emerald-500 flex-shrink-0" />
              <code className="text-emerald-400 text-xs font-mono break-all selection:bg-emerald-900 overflow-x-auto whitespace-pre">
                {rec.commande}
              </code>
            </div>
            
            <div className="mt-3 flex justify-end">
              <button className="flex items-center space-x-1.5 text-xs bg-red-950/40 hover:bg-red-900/60 text-red-200 px-3 py-1.5 rounded transition-colors border border-red-900/50">
                <Lock className="w-3 h-3" />
                <span>Appliquer Automatiquement</span>
              </button>
            </div>
          </div>
        ))}
        {recommendations.length === 0 && (
          <div className="text-center py-8 text-gray-500 text-sm">
            Aucune action requise pour le moment.
          </div>
        )}
      </div>
    </div>
  );
}
