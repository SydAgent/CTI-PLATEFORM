import React, { useState, useEffect } from 'react';
import { useOnyxStore } from '@/lib/store';
import { useThemeStore } from '@/lib/themeStore';
import { useRealTimeStore } from '@/lib/RealTimeDataService';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
} from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

function CountingNumber({ value, duration = 1500 }: { value: number, duration?: number }) {
  const [count, setCount] = useState(0);
  
  useEffect(() => {
    let startTime: number;
    let animationFrame: number;
    
    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const progress = timestamp - startTime;
      const percentage = Math.min(progress / duration, 1);
      const easeOut = percentage === 1 ? 1 : 1 - Math.pow(2, -10 * percentage);
      
      setCount(Math.floor(easeOut * value));
      
      if (percentage < 1) {
        animationFrame = requestAnimationFrame(animate);
      }
    };
    
    animationFrame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationFrame);
  }, [value, duration]);
  
  return <>{count.toLocaleString('fr-FR')}</>;
}

function Sparkline({ data, trend }: { data: number[], trend: 'up' | 'down' }) {
  const color = trend === 'up' ? '#22c55e' : '#ef4444';
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const width = 100;
  const height = 20;
  
  const points = data.map((val, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - ((val - min) / range) * height;
    return `${x},${y}`;
  }).join(' ');

  return (
    <svg width="100%" height="20" viewBox="0 0 100 20" preserveAspectRatio="none">
      <polyline points={points} fill="none" stroke={color} strokeWidth="2" />
    </svg>
  );
}

function RiskGauge({ score }: { score: number }) {
  const [currentScore, setCurrentScore] = useState(0);
  
  useEffect(() => {
    let startTime: number;
    let animationFrame: number;
    
    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const progress = timestamp - startTime;
      const percentage = Math.min(progress / 1500, 1);
      const easeOut = percentage === 1 ? 1 : 1 - Math.pow(2, -10 * percentage);
      
      setCurrentScore(Math.floor(easeOut * score));
      
      if (percentage < 1) {
        animationFrame = requestAnimationFrame(animate);
      }
    };
    
    animationFrame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationFrame);
  }, [score]);

  const color = currentScore < 40 ? '#22c55e' : currentScore <= 70 ? '#f59e0b' : '#ef4444';
  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (currentScore / 100) * circumference;

  return (
    <div className="relative flex items-center justify-center w-32 h-32">
      <svg className="transform -rotate-90 w-full h-full">
        <circle cx="64" cy="64" r={radius} stroke="rgba(255,255,255,0.05)" strokeWidth="12" fill="none" />
        <circle cx="64" cy="64" r={radius} stroke={color} strokeWidth="12" fill="none" strokeDasharray={circumference} strokeDashoffset={strokeDashoffset} className="transition-all duration-75" strokeLinecap="round" />
      </svg>
      <div className="absolute flex flex-col items-center justify-center text-white">
        <span className="text-3xl font-black font-mono" style={{ color }}>{currentScore}</span>
      </div>
    </div>
  );
}

export default function ExecutiveDashboard() {
  const stats = useOnyxStore(s => s.stats);
  const actorsCount = stats?.threats?.total_threats?.value || 12;

  // RealTimeDataService
  const urlhaus = useRealTimeStore(s => s.urlhaus);
  const cisa = useRealTimeStore(s => s.cisa);
  const feodo = useRealTimeStore(s => s.feodo);

  const iocTotal = urlhaus.length;
  const cveTotal = cisa.length;
  const botnetTotal = feodo.length;

  // Dynamic values
  const riskScore = 84; // Simulated dynamic score
  const trend = 'baisse';

  // Heatmap generation (github style)
  const renderHeatmap = () => {
    const days = 30;
    const cells = [];
    for (let i = 0; i < days; i++) {
      const intensity = Math.random();
      let color = 'var(--bg-elevated)'; // default slate-800
      if (intensity > 0.8) color = 'var(--color-danger)';
      else if (intensity > 0.6) color = 'var(--color-warning)';
      else if (intensity > 0.3) color = 'var(--color-info)';
      else if (intensity > 0.1) color = 'var(--border-default)';

      cells.push(
        <div key={i} className="w-3 h-3 rounded-sm hover:scale-125 transition-transform cursor-help" style={{ backgroundColor: color }} title={`Activité: ${Math.floor(intensity * 100)}`}></div>
      );
    }
    return (
      <div className="flex gap-1 flex-wrap w-[140px] mt-2">
        {cells}
      </div>
    );
  };

  const theme = useThemeStore(s => s.theme);

  // Chart.js cannot resolve CSS custom properties — use explicit hex colors per theme
  const isLight = theme === 'light';
  const chartTextColor   = isLight ? '#334155' : '#CBD5E1'; // slate-700 / slate-300
  const chartGridColor   = isLight ? 'rgba(203,213,225,0.5)' : 'rgba(148,163,184,0.15)';
  const chartAxisColor   = isLight ? 'rgba(148,163,225,0.6)' : 'rgba(148,163,184,0.4)';

  // Dataset colours — hex only, no CSS vars
  const colors = {
    espionnage: { stroke: '#22D3EE', fill: 'rgba(34,211,238,0.18)' },
    ransomware:  { stroke: '#EC4899', fill: 'rgba(236,72,153,0.18)' },
    ddos:        { stroke: '#FBBF24', fill: 'rgba(251,191,36,0.18)' },
    info:        isLight ? '#0891B2' : '#38BDF8',
    danger:      isLight ? '#DC2626' : '#EF4444',
    warning:     isLight ? '#EA580C' : '#F97316',
    accent:      isLight ? '#7C3AED' : '#A855F7',
    success:     isLight ? '#16A34A' : '#22C55E',
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: { color: chartTextColor, font: { family: 'Outfit', size: 12 }, padding: 24, boxWidth: 10 },
      },
      tooltip: {
        backgroundColor: 'rgba(15,23,42,0.95)',
        borderColor: 'rgba(34,211,238,0.3)',
        borderWidth: 1,
        titleColor: '#94A3B8',
        bodyColor: '#FFFFFF',
        padding: 12,
        cornerRadius: 8,
      },
    },
    scales: {
      x: {
        ticks: { color: chartTextColor, font: { size: 12 } },
        grid: { color: chartGridColor },
        border: { color: chartAxisColor },
      },
      y: {
        ticks: { color: chartTextColor, font: { size: 12 } },
        grid: { color: chartGridColor },
        border: { color: chartAxisColor },
      },
    },
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right' as const,
        labels: { color: chartTextColor, font: { family: 'Outfit', size: 12 } },
      },
    },
    cutout: '75%',
  };

  return (
    <div className="flex flex-col gap-6 section-enter">
      {/* KPI Header */}
      <div className="grid grid-cols-5 gap-4">
        {/* Risk Score */}
        <div className="col-span-1 onyx-card flex flex-col items-center justify-center relative overflow-hidden" style={{ borderTop: '4px solid var(--color-danger)' }}>
          <div className="absolute inset-0 bg-gradient-to-b from-[var(--color-danger-bg)] to-transparent pointer-events-none" />
          <div className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-widest mb-2 z-10">Score de Risque Global</div>
          <RiskGauge score={riskScore} />
        </div>

        {/* 4 Standard KPIs */}
        <div className="col-span-4 grid grid-cols-4 gap-4">
          <div className="onyx-card flex flex-col justify-between p-4">
            <div>
              <div className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-widest mb-1">IoCs Actifs (URLhaus)</div>
              <div className="text-3xl font-black text-[var(--text-primary)] font-mono"><CountingNumber value={iocTotal} /></div>
            </div>
            <div className="mt-2">
              <Sparkline data={[20, 30, 45, 60, 55, 70, iocTotal]} trend="up" />
            </div>
          </div>
          <div className="onyx-card flex flex-col justify-between p-4">
            <div>
              <div className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-widest mb-1">CVEs Critiques (CISA KEV)</div>
              <div className="text-3xl font-black text-[var(--text-primary)] font-mono"><CountingNumber value={cveTotal} /></div>
            </div>
            <div className="mt-2">
              <Sparkline data={[120, 115, 130, 140, 125, 110, cveTotal]} trend="down" />
            </div>
          </div>
          <div className="onyx-card flex flex-col justify-between p-4">
            <div>
              <div className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-widest mb-1">Botnets C2 (Feodo)</div>
              <div className="text-3xl font-black text-[var(--text-primary)] font-mono"><CountingNumber value={botnetTotal} /></div>
            </div>
            <div className="mt-2">
              <Sparkline data={[50, 45, 55, 65, 60, 75, botnetTotal]} trend="up" />
            </div>
          </div>
          <div className="onyx-card flex flex-col justify-between p-4">
            <div>
              <div className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-widest mb-1">Acteurs Actifs</div>
              <div className="text-3xl font-black text-[var(--text-primary)] font-mono"><CountingNumber value={actorsCount} /></div>
            </div>
            <div className="mt-2">
              <Sparkline data={[8, 9, 10, 11, 10, 12, actorsCount]} trend="up" />
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Left Column */}
        <div className="col-span-2 flex flex-col gap-6">
          {/* Threat Distribution Chart */}
          <div className="onyx-card" style={{ height: 320, minHeight: 320 }}>
            <h3 className="text-[11px] uppercase tracking-widest font-bold text-[var(--text-secondary)] mb-4 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: colors.espionnage.stroke }}></span> Distribution des Menaces (30 Jours)
            </h3>
            <div style={{ height: 260 }}>
              <Line
                data={{
                  labels: ['J-30', 'J-25', 'J-20', 'J-15', 'J-10', 'J-5', 'Auj'],
                  datasets: [
                    {
                      label: 'Espionnage',
                      data: [12, 19, 15, 25, 22, 30, 28],
                      borderColor: colors.espionnage.stroke,
                      backgroundColor: colors.espionnage.fill,
                      borderWidth: 2.5,
                      fill: true,
                      tension: 0.4,
                      pointRadius: 3,
                      pointHoverRadius: 5,
                    },
                    {
                      label: 'Ransomware',
                      data: [5, 8, 12, 10, 15, 18, 24],
                      borderColor: colors.ransomware.stroke,
                      backgroundColor: colors.ransomware.fill,
                      borderWidth: 2.5,
                      fill: true,
                      tension: 0.4,
                      pointRadius: 3,
                      pointHoverRadius: 5,
                    },
                    {
                      label: 'DDoS',
                      data: [30, 20, 25, 15, 10, 12, 8],
                      borderColor: colors.ddos.stroke,
                      backgroundColor: colors.ddos.fill,
                      borderWidth: 2.5,
                      fill: true,
                      tension: 0.4,
                      pointRadius: 3,
                      pointHoverRadius: 5,
                    },
                  ],
                }}
                options={chartOptions}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-6">
            {/* Top 5 Actors */}
            <div className="onyx-card">
              <h3 className="text-[11px] uppercase tracking-widest font-bold text-[var(--text-secondary)] mb-4 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[var(--color-danger)]"></span> Top 5 Acteurs Actifs
              </h3>
              <div className="flex flex-col gap-3">
                {[
                  { name: 'APT28', danger: 9.8, type: 'Espionnage' },
                  { name: 'Volt Typhoon', danger: 9.5, type: 'Prépositionnement' },
                  { name: 'LockBit 3.0', danger: 9.2, type: 'Ransomware' },
                  { name: 'Sandworm', danger: 8.9, type: 'Sabotage' },
                  { name: 'Lazarus Group', danger: 8.7, type: 'Finance' },
                ].map((a, i) => (
                  <div key={i} className="flex items-center justify-between p-2 rounded bg-[var(--bg-elevated)] border border-[var(--border-default)] hover:bg-white hover:shadow-md transition-all">
                    <div className="flex items-center gap-3">
                      <span className="text-[var(--text-muted)] font-mono font-bold text-xs">{i+1}</span>
                      <div>
                        <div className="text-sm font-bold text-[var(--text-primary)]">{a.name}</div>
                        <div className="text-[10px] text-[var(--text-muted)] uppercase">{a.type}</div>
                      </div>
                    </div>
                    <div className="flex flex-col items-end">
                      <div className="text-[var(--severity-high)] font-mono font-bold">{a.danger}/10</div>
                      <div className="w-16 h-1 bg-[var(--border-default)] rounded-full mt-1">
                        <div className="h-full bg-[var(--severity-high)] rounded-full" style={{ width: `${a.danger * 10}%` }}></div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Distribution Sectorielle */}
            <div className="onyx-card">
              <h3 className="text-[11px] uppercase tracking-widest font-bold text-[var(--text-secondary)] mb-4 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[var(--color-accent)]"></span> Cibles Sectorielles
              </h3>
              <div className="h-[180px]">
                <Doughnut
                  data={{
                    labels: ['Gouvernement', 'Finance', 'Santé', 'Énergie', 'Tech'],
                    datasets: [{
                      data: [35, 25, 20, 15, 5],
                      backgroundColor: [colors.info, colors.danger, colors.warning, colors.accent, colors.success],
                      borderWidth: 0,
                    }],
                  }}
                  options={doughnutOptions}
                />
              </div>
              <div className="mt-4">
                <div className="text-[10px] text-slate-400 font-bold uppercase tracking-widest mb-1">Activité 30 Jours</div>
                {renderHeatmap()}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Live Priority Alerts */}
        <div className="col-span-1 onyx-card flex flex-col">
          <h3 className="text-[11px] uppercase tracking-widest font-bold text-[var(--text-secondary)] mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[var(--color-danger)] animate-pulse"></span> Flux d'Alertes Prioritaires
          </h3>
          <div className="flex-1 overflow-y-auto pr-2 flex flex-col gap-3">
            {[
              { time: 'À L\'INSTANT', title: 'Nouvelle infrastructure C2 détectée', desc: 'Cluster lié à APT29 actif sur AWS', level: 'critique' },
              { time: 'IL Y A 12 MIN', title: 'Campagne Phishing en cours', desc: 'Ciblage des secteurs financiers FR', level: 'eleve' },
              { time: 'IL Y A 45 MIN', title: 'Vulnérabilité exploitée (Ivanti)', desc: 'Scan massif détecté sur les IP publiques', level: 'eleve' },
              { time: 'IL Y A 2H', title: 'Fuite de données signalée', desc: 'Forum LockBit: annonce concernant un sous-traitant aéronautique', level: 'critique' },
              { time: 'IL Y A 5H', title: 'Mise à jour STIX', desc: 'Ingestion de 1450 nouveaux IoCs depuis MISP', level: 'info' },
              { time: 'IL Y A 8H', title: 'Activité suspecte', desc: 'Trafic sortant inhabituel vers la Corée du Nord', level: 'moyen' },
            ].map((alert, i) => {
              const bg = alert.level === 'critique' ? 'bg-[var(--color-danger-bg)] border-[var(--color-danger)] text-[var(--color-danger)]' :
                         alert.level === 'eleve' ? 'bg-[var(--color-warning-bg)] border-[var(--color-warning)] text-[var(--color-warning)]' :
                         alert.level === 'info' ? 'bg-[var(--color-info-bg)] border-[var(--color-info)] text-[var(--color-info)]' :
                         'bg-[var(--color-warning-bg)] border-[var(--color-warning)] text-[var(--color-warning)]';
              return (
                <div key={i} className={`p-3 rounded-lg border-l-4 flex flex-col gap-1 ${bg}`}>
                  <div className="flex justify-between items-center">
                    <span className="text-[9px] font-bold tracking-widest uppercase opacity-80">{alert.time}</span>
                    <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-current text-[var(--text-inverse)] opacity-90">{alert.level}</span>
                  </div>
                  <div className="text-sm font-bold text-[var(--text-primary)] mt-1">{alert.title}</div>
                  <div className="text-xs text-[var(--text-secondary)]">{alert.desc}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
