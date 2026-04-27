'use client';

/**
 * DecaySparkline — inline D3 mini-SVG showing exponential decay curve.
 *
 * Renders a 64×20px area chart from t=0 (first_seen) to t=now, with a
 * vertical marker at the current decay score. Color matches the decay state.
 * Zero external dependencies beyond d3 (already in project).
 */

import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';

// Half-life defaults per IoC type (hours) — mirrors decay_engine.py
const HALF_LIFE_HOURS: Record<string, number> = {
  ipv4: 36, ipv6: 36, domain: 480, url: 48,
  sha256: 17520, sha1: 13152, md5: 8760,
  email: 720, ja3: 4320, ja4: 4320,
  mutex: 2160, registry_key: 1440, named_pipe: 1800,
  user_agent: 1080, yara_rule: 336, cve: 4380,
};

const LN2 = Math.log(2);

function expDecay(hours: number, halfLifeHours: number): number {
  return Math.exp(-LN2 * hours / halfLifeHours);
}

export const DECAY_STATE_COLORS: Record<string, string> = {
  valid:     '#22c55e',
  degrading: '#eab308',
  stale:     '#f97316',
  obsolete:  '#ef4444',
};

function decayStateFromScore(score: number): string {
  if (score > 0.80) return 'valid';
  if (score > 0.50) return 'degrading';
  if (score > 0.15) return 'stale';
  return 'obsolete';
}

interface DecaySparklineProps {
  iocType: string;
  hoursOld: number;
  currentScore?: number | null;
  width?: number;
  height?: number;
}

export default function DecaySparkline({
  iocType,
  hoursOld,
  currentScore,
  width = 64,
  height = 20,
}: DecaySparklineProps) {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const halfLife = HALF_LIFE_HOURS[iocType] ?? 36;
    const totalHours = Math.max(hoursOld, halfLife * 4);
    const score = currentScore ?? expDecay(hoursOld, halfLife);
    const state = decayStateFromScore(score);
    const color = DECAY_STATE_COLORS[state];

    const xScale = d3.scaleLinear().domain([0, totalHours]).range([0, width]);
    const yScale = d3.scaleLinear().domain([0, 1]).range([height - 1, 1]);

    // Build curve points
    const points = d3.range(0, totalHours, totalHours / 60).map(h => ({
      x: xScale(h),
      y: yScale(expDecay(h, halfLife)),
    }));

    const area = d3.area<{ x: number; y: number }>()
      .x(d => d.x)
      .y0(height)
      .y1(d => d.y)
      .curve(d3.curveBasis);

    const line = d3.line<{ x: number; y: number }>()
      .x(d => d.x)
      .y(d => d.y)
      .curve(d3.curveBasis);

    // Area fill
    svg.append('path')
      .datum(points)
      .attr('d', area)
      .attr('fill', `${color}22`);

    // Line
    svg.append('path')
      .datum(points)
      .attr('d', line)
      .attr('fill', 'none')
      .attr('stroke', color)
      .attr('stroke-width', 1.5);

    // Current position marker
    const cx = xScale(hoursOld);
    const cy = yScale(score);
    svg.append('circle')
      .attr('cx', cx)
      .attr('cy', cy)
      .attr('r', 2.5)
      .attr('fill', color)
      .attr('stroke', '#050a0f')
      .attr('stroke-width', 1);

    // Vertical dotted line at current position
    svg.append('line')
      .attr('x1', cx).attr('y1', cy)
      .attr('x2', cx).attr('y2', height)
      .attr('stroke', `${color}60`)
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', '2,2');

  }, [iocType, hoursOld, currentScore, width, height]);

  return (
    <svg
      ref={svgRef}
      width={width}
      height={height}
      style={{ display: 'block', overflow: 'visible' }}
      aria-label={`Courbe de décroissance — ${Math.round((currentScore ?? 0) * 100)}%`}
    />
  );
}

// ── Standalone DecayStateBadge (reusable outside sparkline) ──────────────────

interface DecayStateBadgeProps {
  state: string | null | undefined;
  score?: number | null;
  compact?: boolean;
}

const DECAY_STATE_LABELS: Record<string, string> = {
  valid: 'VALIDE', degrading: 'DÉGRADÉ', stale: 'PÉRIMÉ', obsolete: 'OBSOLÈTE',
};

const DECAY_STATE_SHAPES: Record<string, string> = {
  valid: '●', degrading: '◆', stale: '▲', obsolete: '✕',
};

export function DecayStateBadge({ state, score, compact = false }: DecayStateBadgeProps) {
  const resolvedState = state ?? (score != null ? decayStateFromScore(score) : null);
  if (!resolvedState) {
    return <span style={{ color: '#4b5563', fontSize: 9, fontFamily: 'monospace' }}>—</span>;
  }
  const color = DECAY_STATE_COLORS[resolvedState] ?? '#6b7280';
  const label = DECAY_STATE_LABELS[resolvedState] ?? resolvedState.toUpperCase();
  const shape = DECAY_STATE_SHAPES[resolvedState] ?? '●';

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 3,
        fontSize: compact ? 8 : 9,
        fontFamily: 'monospace',
        fontWeight: 'bold',
        color,
        background: `${color}18`,
        padding: compact ? '1px 4px' : '2px 6px',
        borderRadius: 3,
        border: `1px solid ${color}40`,
        whiteSpace: 'nowrap',
      }}
      title={score != null ? `Score: ${(score * 100).toFixed(1)}%` : undefined}
    >
      <span aria-hidden="true">{shape}</span>
      {!compact && <span>{label}</span>}
    </span>
  );
}
