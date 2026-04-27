'use client';

/**
 * CanvasTimeline — 4-layer SVG analytical timeline.
 *
 * Layer 1 (top):    Campaigns — Gantt bars per real kill-chain phase events
 * Layer 2:          TTP drift — scatter dots from real timeline events
 * Layer 3:          IoC density — KDE from real IoC first_seen timestamps
 * Layer 4 (bottom): Composite score — real decay_score time series
 *
 * POLICY: No synthetic/generated data. Layers with no real data show an
 * explicit EmptyState so analysts can trust what they see.
 *
 * D3 brush on the overview band sets brushedTimeRange in actorDetailStore.
 */

import React, { useEffect, useRef, useCallback } from 'react';
import * as d3 from 'd3';
import { useActorDetailStore } from '@/lib/actorDetailStore';

// ─── Types ────────────────────────────────────────────────────────────────────

interface TimelineEvent {
  id: string;
  date: string;
  phase: string;
  description: string;
  severity: string;
}

interface IoCSummary {
  id: string;
  type: string;
  value: string;
  first_seen?: string;
  decay_score?: number | null;
  decay_state?: string | null;
}

export interface CanvasTimelineProps {
  actorId: string;
  events?: TimelineEvent[];
  iocs?: IoCSummary[];
  techniques?: string[];
}

// ─── Palette ──────────────────────────────────────────────────────────────────

const PHASE_COLORS: Record<string, string> = {
  'Reconnaissance': '#6366f1',
  'Initial Access': '#ef4444',
  'Execution': '#f97316',
  'Persistence': '#14b8a6',
  'Privilege Escalation': '#ec4899',
  'Defense Evasion': '#8b5cf6',
  'Credential Access': '#eab308',
  'Discovery': '#06b6d4',
  'Lateral Movement': '#14b8a6',
  'Collection': '#f59e0b',
  'Command and Control': '#ff3b5c',
  'Exfiltration': '#dc2626',
  'Impact': '#dc2626',
  'Initial Compromise': '#ef4444',
  'Establish Foothold': '#f97316',
  'Data Exfiltration': '#f59e0b',
  'C2 Established': '#ff3b5c',
};

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
};

// ─── KDE (real data only) ─────────────────────────────────────────────────────

function gaussian(x: number, mu: number, sigma: number): number {
  return Math.exp(-0.5 * ((x - mu) / sigma) ** 2) / (sigma * Math.sqrt(2 * Math.PI));
}

function kdeFromReal(
  timestamps: number[],
  bandwidth: number,
  steps: number,
  xMin: number,
  xMax: number,
): { x: Date; y: number }[] {
  if (timestamps.length === 0) return [];
  const step = (xMax - xMin) / steps;
  const raw = Array.from({ length: steps }, (_, i) => {
    const x = xMin + i * step;
    const density = timestamps.reduce((s, t) => s + gaussian(x, t, bandwidth), 0) / timestamps.length;
    return { x, density };
  });
  const maxDensity = Math.max(...raw.map(d => d.density), 1e-12);
  return raw.map(d => ({ x: new Date(d.x), y: d.density / maxDensity }));
}

// ─── Layout constants ─────────────────────────────────────────────────────────

const MARGIN = { top: 12, right: 24, bottom: 40, left: 108 };
const LAYER_HEIGHTS = { gantt: 100, scatter: 90, kde: 90, score: 80, brush: 30 };
const GAP = 8;
const SVG_HEIGHT =
  MARGIN.top +
  LAYER_HEIGHTS.gantt + GAP +
  LAYER_HEIGHTS.scatter + GAP +
  LAYER_HEIGHTS.kde + GAP +
  LAYER_HEIGHTS.score + GAP +
  LAYER_HEIGHTS.brush +
  MARGIN.bottom;

// ─── EmptyState overlay helper ────────────────────────────────────────────────

function drawEmptyLayer(
  g: d3.Selection<SVGGElement, unknown, null, undefined>,
  yTop: number,
  height: number,
  innerW: number,
  label: string,
) {
  g.append('rect')
    .attr('x', 0).attr('y', yTop).attr('width', innerW).attr('height', height)
    .attr('fill', '#050a0f').attr('rx', 4);
  g.append('text')
    .attr('x', innerW / 2).attr('y', yTop + height / 2)
    .attr('dominant-baseline', 'middle').attr('text-anchor', 'middle')
    .attr('fill', '#374151').attr('font-size', 10)
    .attr('font-family', '"JetBrains Mono", monospace')
    .text(`— ${label} —`);
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function CanvasTimeline({
  actorId,
  events = [],
  iocs = [],
}: CanvasTimelineProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const setBrushedTimeRange = useActorDetailStore(s => s.setBrushedTimeRange);
  const brushedTimeRange = useActorDetailStore(s => s.brushedTimeRange);

  // Keep brushedTimeRange accessible inside render without adding it to render deps
  const brushedTimeRangeRef = useRef(brushedTimeRange);
  useEffect(() => { brushedTimeRangeRef.current = brushedTimeRange; }, [brushedTimeRange]);

  const render = useCallback(() => {
    const svgEl = svgRef.current;
    if (!svgEl) return;

    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();

    const container = svgEl.parentElement;
    const W = container?.clientWidth || 700;
    svg.attr('width', W).attr('height', SVG_HEIGHT);

    const innerW = W - MARGIN.left - MARGIN.right;

    // ── Build data from REAL sources only ─────────────────────────────────

    // Gantt: group events by phase
    const phaseMap: Record<string, { dates: Date[]; severity: string }> = {};
    for (const ev of events) {
      const d = new Date(ev.date);
      if (isNaN(d.getTime())) continue;
      if (!phaseMap[ev.phase]) phaseMap[ev.phase] = { dates: [], severity: ev.severity };
      phaseMap[ev.phase].dates.push(d);
      const ranks: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
      if ((ranks[ev.severity] ?? 0) > (ranks[phaseMap[ev.phase].severity] ?? 0)) {
        phaseMap[ev.phase].severity = ev.severity;
      }
    }
    const ganttBars = Object.entries(phaseMap).map(([phase, { dates, severity }]) => ({
      phase,
      start: new Date(Math.min(...dates.map(d => d.getTime()))),
      end: new Date(Math.max(...dates.map(d => d.getTime()))),
      severity,
      color: PHASE_COLORS[phase] ?? '#6b7280',
    }));

    // Scatter: real event dots
    const scatterDots: { date: Date; label: string; severity: string }[] = [];
    for (const ev of events) {
      const d = new Date(ev.date);
      if (!isNaN(d.getTime())) {
        scatterDots.push({ date: d, label: ev.phase, severity: ev.severity });
      }
    }

    // KDE: real IoC first_seen timestamps
    const iocTimes: number[] = [];
    for (const ioc of iocs) {
      if (ioc.first_seen) {
        const d = new Date(ioc.first_seen);
        if (!isNaN(d.getTime())) iocTimes.push(d.getTime());
      }
    }

    // Score: real decay_score series from IoCs that have first_seen + decay_score
    const scorePoints: { date: Date; score: number }[] = [];
    for (const ioc of iocs) {
      if (ioc.first_seen && ioc.decay_score != null) {
        const d = new Date(ioc.first_seen);
        if (!isNaN(d.getTime())) scorePoints.push({ date: d, score: ioc.decay_score });
      }
    }
    // Sort score series by date
    scorePoints.sort((a, b) => a.date.getTime() - b.date.getTime());

    // ── Compute shared time domain from real data only ──────────────────────
    const allDates: Date[] = [
      ...events.map(e => new Date(e.date)).filter(d => !isNaN(d.getTime())),
      ...iocs.filter(i => i.first_seen).map(i => new Date(i.first_seen!)).filter(d => !isNaN(d.getTime())),
    ];
    const hasAnyData = allDates.length >= 2;

    if (!hasAnyData) {
      // Full empty state — no real dates in any layer
      svg.append('rect').attr('width', W).attr('height', SVG_HEIGHT).attr('fill', '#020508');
      svg.append('text')
        .attr('x', W / 2).attr('y', SVG_HEIGHT / 2)
        .attr('text-anchor', 'middle').attr('dominant-baseline', 'middle')
        .attr('fill', '#374151').attr('font-size', 11)
        .attr('font-family', '"JetBrains Mono", monospace')
        .text('Aucune donnée temporelle disponible pour cet acteur');
      return;
    }

    const xMin = new Date(Math.min(...allDates.map(d => d.getTime())));
    const xMax = new Date(Math.max(...allDates.map(d => d.getTime())));
    const xScale = d3.scaleTime().domain([xMin, xMax]).range([0, innerW]);

    // ── Layer Y offsets ──────────────────────────────────────────────────────
    let yOff = MARGIN.top;
    const ganttY = yOff; yOff += LAYER_HEIGHTS.gantt + GAP;
    const scatterY = yOff; yOff += LAYER_HEIGHTS.scatter + GAP;
    const kdeY = yOff; yOff += LAYER_HEIGHTS.kde + GAP;
    const scoreY = yOff; yOff += LAYER_HEIGHTS.score + GAP;
    const brushY = yOff;

    const g = svg.append('g').attr('transform', `translate(${MARGIN.left},0)`);

    const labelStyle = (sel: d3.Selection<SVGTextElement, unknown, null, undefined>) => {
      sel
        .attr('fill', '#6b7280').attr('font-size', 9)
        .attr('font-family', '"JetBrains Mono", monospace').attr('font-weight', 700)
        .attr('letter-spacing', '0.1em').attr('text-anchor', 'end')
        .attr('dominant-baseline', 'middle');
    };

    const drawBg = (y: number, h: number) =>
      g.append('rect').attr('x', 0).attr('y', y).attr('width', innerW).attr('height', h)
        .attr('fill', '#050a0f').attr('rx', 4);

    // ── Shared X axis ──────────────────────────────────────────────────────
    const xAxis = g.append('g')
      .attr('transform', `translate(0,${brushY + LAYER_HEIGHTS.brush})`)
      .call(
        d3.axisBottom(xScale)
          .ticks(6)
          .tickFormat(d3.timeFormat('%b %y') as (v: Date | d3.NumberValue, i: number) => string),
      );
    xAxis.selectAll('path,line').attr('stroke', '#374151');
    xAxis.selectAll('text').attr('fill', '#6b7280').attr('font-size', 9)
      .attr('font-family', '"JetBrains Mono", monospace');

    // ── Layer 1: Gantt ─────────────────────────────────────────────────────
    g.append('text').attr('x', -6).attr('y', ganttY + LAYER_HEIGHTS.gantt / 2)
      .text('CAMPAGNES').call(labelStyle);

    if (ganttBars.length === 0) {
      drawEmptyLayer(g, ganttY, LAYER_HEIGHTS.gantt, innerW, 'Pas d\'événements kill-chain');
    } else {
      drawBg(ganttY, LAYER_HEIGHTS.gantt);
      const rowH = Math.max(10, Math.min(22, (LAYER_HEIGHTS.gantt - 20) / ganttBars.length));
      ganttBars.forEach((bar, i) => {
        const barY = ganttY + 10 + i * (rowH + 2);
        const x1 = xScale(bar.start);
        const x2 = xScale(bar.end);
        const barW = Math.max(4, x2 - x1);
        g.append('rect').attr('x', x1).attr('y', barY).attr('width', barW)
          .attr('height', rowH - 2).attr('fill', `${bar.color}50`)
          .attr('stroke', bar.color).attr('stroke-width', 1).attr('rx', 2);
        if (barW > 40) {
          g.append('text').attr('x', x1 + 4).attr('y', barY + rowH / 2)
            .attr('dominant-baseline', 'middle').attr('fill', bar.color)
            .attr('font-size', 8).attr('font-family', '"JetBrains Mono", monospace')
            .text(bar.phase.slice(0, 20));
        }
        g.append('circle').attr('cx', x1 + barW - 6).attr('cy', barY + rowH / 2)
          .attr('r', 3).attr('fill', SEV_COLOR[bar.severity] ?? '#6b7280');
      });
    }

    // ── Layer 2: TTP Scatter ───────────────────────────────────────────────
    g.append('text').attr('x', -6).attr('y', scatterY + LAYER_HEIGHTS.scatter / 2)
      .text('TTP DRIFT').call(labelStyle);

    if (scatterDots.length === 0) {
      drawEmptyLayer(g, scatterY, LAYER_HEIGHTS.scatter, innerW, 'Pas d\'observations TTP horodatées');
    } else {
      drawBg(scatterY, LAYER_HEIGHTS.scatter);
      const phases = Array.from(new Set(scatterDots.map(d => d.label))).slice(0, 6);
      const scatterYScale = d3.scaleBand()
        .domain(phases)
        .range([scatterY + 10, scatterY + LAYER_HEIGHTS.scatter - 10])
        .padding(0.3);
      scatterDots.forEach(dot => {
        const cy = (scatterYScale(dot.label) ?? 0) + scatterYScale.bandwidth() / 2;
        g.append('circle').attr('cx', xScale(dot.date)).attr('cy', cy).attr('r', 3.5)
          .attr('fill', `${SEV_COLOR[dot.severity] ?? '#6b7280'}cc`)
          .attr('stroke', SEV_COLOR[dot.severity] ?? '#6b7280').attr('stroke-width', 0.5);
      });
      phases.forEach(phase => {
        const cy = (scatterYScale(phase) ?? 0) + scatterYScale.bandwidth() / 2;
        g.append('text').attr('x', -4).attr('y', cy)
          .attr('dominant-baseline', 'middle').attr('text-anchor', 'end')
          .attr('fill', '#4b5563').attr('font-size', 7)
          .attr('font-family', '"JetBrains Mono", monospace')
          .text(phase.slice(0, 14));
      });
    }

    // ── Layer 3: IoC KDE ───────────────────────────────────────────────────
    g.append('text').attr('x', -6).attr('y', kdeY + LAYER_HEIGHTS.kde / 2)
      .text('DENSITÉ IoC').call(labelStyle);

    if (iocTimes.length < 2) {
      drawEmptyLayer(g, kdeY, LAYER_HEIGHTS.kde, innerW, 'Pas de timestamps IoC (first_seen requis)');
    } else {
      drawBg(kdeY, LAYER_HEIGHTS.kde);
      const kdePad = 8;
      const bandwidth = (xMax.getTime() - xMin.getTime()) * 0.06;
      const kdeData = kdeFromReal(iocTimes, bandwidth, 60, xMin.getTime(), xMax.getTime());
      const kdeYScale = d3.scaleLinear().domain([0, 1])
        .range([kdeY + LAYER_HEIGHTS.kde - kdePad, kdeY + kdePad]);

      const kdeArea = d3.area<{ x: Date; y: number }>()
        .x(d => xScale(d.x)).y0(kdeY + LAYER_HEIGHTS.kde - kdePad).y1(d => kdeYScale(d.y))
        .curve(d3.curveBasis);
      const kdeLine = d3.line<{ x: Date; y: number }>()
        .x(d => xScale(d.x)).y(d => kdeYScale(d.y)).curve(d3.curveBasis);

      g.append('path').datum(kdeData).attr('d', kdeArea).attr('fill', '#f59e0b18');
      g.append('path').datum(kdeData).attr('d', kdeLine)
        .attr('fill', 'none').attr('stroke', '#f59e0b').attr('stroke-width', 1.5);
    }

    // ── Layer 4: Composite Score ───────────────────────────────────────────
    g.append('text').attr('x', -6).attr('y', scoreY + LAYER_HEIGHTS.score / 2)
      .text('SCORE COMP.').call(labelStyle);

    if (scorePoints.length < 2) {
      drawEmptyLayer(g, scoreY, LAYER_HEIGHTS.score, innerW, 'Pas de scores decay disponibles');
    } else {
      drawBg(scoreY, LAYER_HEIGHTS.score);
      const scorePad = 8;
      const scoreYScale = d3.scaleLinear().domain([0, 1])
        .range([scoreY + LAYER_HEIGHTS.score - scorePad, scoreY + scorePad]);

      const scoreArea = d3.area<{ date: Date; score: number }>()
        .x(d => xScale(d.date)).y0(scoreY + LAYER_HEIGHTS.score - scorePad)
        .y1(d => scoreYScale(d.score)).curve(d3.curveCatmullRom);
      const scoreLine = d3.line<{ date: Date; score: number }>()
        .x(d => xScale(d.date)).y(d => scoreYScale(d.score)).curve(d3.curveCatmullRom);

      g.append('path').datum(scorePoints).attr('d', scoreArea).attr('fill', '#00eeff10');
      g.append('path').datum(scorePoints).attr('d', scoreLine)
        .attr('fill', 'none').attr('stroke', '#00eeff').attr('stroke-width', 1.5);

      [0.5, 0.8].forEach(v => {
        const y = scoreYScale(v);
        g.append('line').attr('x1', 0).attr('y1', y).attr('x2', innerW).attr('y2', y)
          .attr('stroke', '#374151').attr('stroke-width', 0.5).attr('stroke-dasharray', '3,4');
      });
    }

    // ── Brush overview ─────────────────────────────────────────────────────
    g.append('rect').attr('x', 0).attr('y', brushY)
      .attr('width', innerW).attr('height', LAYER_HEIGHTS.brush)
      .attr('fill', '#050a0f').attr('rx', 3);

    // Mini KDE fill in brush only when real data exists
    if (iocTimes.length >= 2) {
      const bandwidth = (xMax.getTime() - xMin.getTime()) * 0.06;
      const kdeData = kdeFromReal(iocTimes, bandwidth, 60, xMin.getTime(), xMax.getTime());
      const miniY = d3.scaleLinear().domain([0, 1])
        .range([brushY + LAYER_HEIGHTS.brush - 2, brushY + 2]);
      const miniArea = d3.area<{ x: Date; y: number }>()
        .x(d => xScale(d.x)).y0(brushY + LAYER_HEIGHTS.brush - 2).y1(d => miniY(d.y))
        .curve(d3.curveBasis);
      g.append('path').datum(kdeData).attr('d', miniArea)
        .attr('fill', '#00eeff12').attr('stroke', '#00eeff30').attr('stroke-width', 0.5);
    }

    g.append('text').attr('x', -6).attr('y', brushY + LAYER_HEIGHTS.brush / 2)
      .text('ZOOM').call(labelStyle);

    const brush = d3.brushX()
      .extent([[0, brushY], [innerW, brushY + LAYER_HEIGHTS.brush]])
      .on('end', (event) => {
        if (!event.selection) { setBrushedTimeRange(null); return; }
        const [x0, x1] = event.selection as [number, number];
        setBrushedTimeRange([xScale.invert(x0).toISOString(), xScale.invert(x1).toISOString()]);
      });

    const brushG = g.append('g').attr('class', 'brush').call(brush);
    brushG.selectAll('.selection')
      .attr('fill', '#00eeff18').attr('stroke', '#00eeff60').attr('stroke-width', 1);

    // Restore previous brush without triggering the 'end' event
    const saved = brushedTimeRangeRef.current;
    if (saved) {
      const t0 = new Date(saved[0]);
      const t1 = new Date(saved[1]);
      if (!isNaN(t0.getTime()) && !isNaN(t1.getTime())) {
        brushG.call(brush.move, [xScale(t0), xScale(t1)]);
      }
    }

  }, [events, iocs, setBrushedTimeRange]);
  // NOTE: brushedTimeRange intentionally excluded from deps — restored via ref
  // to avoid the render loop: render → brush.move → 'end' → setBrushedTimeRange → render

  useEffect(() => { render(); }, [render]);

  useEffect(() => {
    const el = svgRef.current?.parentElement;
    if (!el) return;
    const obs = new ResizeObserver(() => render());
    obs.observe(el);
    return () => obs.disconnect();
  }, [render]);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between px-1">
        <div className="flex items-center gap-4 text-[9px] font-mono">
          {[
            { color: '#6b7280', label: 'Campagnes (Gantt)' },
            { color: '#ef4444', label: 'Drift TTP (scatter)' },
            { color: '#f59e0b', label: 'Densité IoC (KDE)' },
            { color: '#00eeff', label: 'Score decay réel' },
          ].map(({ color, label }) => (
            <span key={label} className="flex items-center gap-1 text-gray-500">
              <span style={{ display: 'inline-block', width: 20, height: 2, background: color, verticalAlign: 'middle' }} />
              {label}
            </span>
          ))}
        </div>
        {brushedTimeRange && (
          <button
            onClick={() => setBrushedTimeRange(null)}
            className="text-[9px] font-mono px-2 py-0.5 rounded border border-gray-700 text-gray-500 hover:text-white hover:border-gray-500 transition-colors"
          >
            ✕ Reset zoom
          </button>
        )}
      </div>
      <div className="bg-[#020508] rounded-lg overflow-hidden border border-gray-800/40">
        <svg ref={svgRef} style={{ display: 'block', width: '100%' }} />
      </div>
      <p className="text-[8px] font-mono text-gray-700 px-1">
        Données exclusivement issues de la base · Glisser la bande de zoom pour filtrer le tableau IoC
      </p>
    </div>
  );
}
