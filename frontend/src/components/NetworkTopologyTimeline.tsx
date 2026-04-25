import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Anomaly } from '../services/anomalyService';
import { Severity } from '../services/topologyService';

/**
 * Timeline scrubber for the Network Topology view.
 *
 * Shows a severity-stacked histogram of anomaly events across the full
 * time range, with a draggable window that drives the topology's "what
 * happened between T1 and T2" filter.
 *
 * Pure presentational component - all state is lifted to the parent.
 */

export interface TimeWindow {
  start: number; // epoch ms (inclusive)
  end: number;   // epoch ms (inclusive)
}

interface Props {
  anomalies: Anomaly[];
  /** The full available time range - bounds the scrubber. */
  fullRange: TimeWindow;
  /** The currently-selected window. */
  window: TimeWindow;
  onWindowChange: (w: TimeWindow) => void;
  /** Baseline period - everything before `baselineEnd` is treated as "normal". */
  baselineEnd: number; // epoch ms
  onBaselineEndChange: (ms: number) => void;
  /** Auto-advance the window (play replay). */
  isPlaying: boolean;
  onPlayToggle: () => void;
  /** Lock the window to "now" (live mode). */
  isLive: boolean;
  onLiveToggle: () => void;
  /** Step size for each advance tick when playing, in ms. Default 30_000 (30 s). */
  playStepMs?: number;
}

const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: '#DC2626',
  HIGH: '#EA580C',
  MEDIUM: '#D97706',
  LOW: '#16A34A',
  INFO: '#2563EB',
  NONE: '#9CA3AF',
};

// Bottom-to-top stacking order for bars (CRITICAL at bottom = most visible)
const STACK_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const BIN_COUNT = 60;
const HISTOGRAM_HEIGHT = 56;

const fmtTime = (ms: number): string => {
  const d = new Date(ms);
  const hh = d.getHours().toString().padStart(2, '0');
  const mm = d.getMinutes().toString().padStart(2, '0');
  const ss = d.getSeconds().toString().padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
};

const fmtDate = (ms: number): string => {
  const d = new Date(ms);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
};

const fmtDuration = (ms: number): string => {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return rm === 0 ? `${h}h` : `${h}h ${rm}m`;
};

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v));

// Round a value up to a "nice" number for axis scaling
const niceCeil = (v: number): number => {
  if (v <= 0) return 1;
  const exp = Math.floor(Math.log10(v));
  const f = v / Math.pow(10, exp);
  const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  return nice * Math.pow(10, exp);
};

const NetworkTopologyTimeline: React.FC<Props> = ({
  anomalies,
  fullRange,
  window,
  onWindowChange,
  baselineEnd,
  onBaselineEndChange,
  isPlaying,
  onPlayToggle,
  isLive,
  onLiveToggle,
  playStepMs = 30_000,
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [svgWidth, setSvgWidth] = useState<number>(800);
  const [drag, setDrag] = useState<
    | { kind: 'left' | 'right' | 'move' | 'baseline'; anchorMs: number; originalWindow: TimeWindow }
    | null
  >(null);

  // Observe the svg's client width so the bars reflow on resize
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const update = () => {
      const w = el.clientWidth;
      if (w > 0) setSvgWidth(w);
    };
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // --- Auto-advance when playing ------------------------------------------
  // Advances the window by `playStepMs` per tick. When it reaches the end of
  // the full range, it wraps back to the start - makes the demo loop nicely.
  useEffect(() => {
    if (!isPlaying) return;
    const timer = globalThis.setInterval(() => {
      const duration = window.end - window.start;
      let nextStart = window.start + playStepMs;
      let nextEnd = nextStart + duration;
      if (nextEnd > fullRange.end) {
        nextStart = fullRange.start;
        nextEnd = Math.min(fullRange.start + duration, fullRange.end);
      }
      onWindowChange({ start: nextStart, end: nextEnd });
    }, 800);
    return () => { globalThis.clearInterval(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isPlaying, window.start, window.end, fullRange.start, fullRange.end, playStepMs]);

  // --- Histogram bins -----------------------------------------------------
  const span = Math.max(1, fullRange.end - fullRange.start);
  const bins = useMemo(() => {
    const out: Record<Severity, number>[] = Array.from({ length: BIN_COUNT }, () => ({
      CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, NONE: 0,
    }));
    for (const a of anomalies) {
      const t = a.detectedAt ? new Date(a.detectedAt).getTime() : NaN;
      if (!Number.isFinite(t)) continue;
      const idx = clamp(Math.floor(((t - fullRange.start) / span) * BIN_COUNT), 0, BIN_COUNT - 1);
      const sev = (a.severity || 'NONE') as Severity;
      out[idx][sev] = (out[idx][sev] || 0) + 1;
    }
    return out;
    // `span` is derived from fullRange.start/end, so it already covers those
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anomalies, fullRange.start, span]);

  const maxBin = useMemo(() => {
    let m = 0;
    for (const b of bins) {
      const total = STACK_ORDER.reduce((acc, s) => acc + b[s], 0);
      if (total > m) m = total;
    }
    return niceCeil(m);
  }, [bins]);

  // --- Coordinate helpers --------------------------------------------------
  const msToX = useCallback(
    (ms: number) => ((ms - fullRange.start) / span) * svgWidth,
    [fullRange.start, span, svgWidth],
  );

  const xToMs = useCallback(
    (x: number) => fullRange.start + (x / svgWidth) * span,
    [fullRange.start, span, svgWidth],
  );

  // --- Drag handling -------------------------------------------------------
  const onPointerDown = (e: React.PointerEvent<SVGElement>, kind: 'left' | 'right' | 'move' | 'baseline') => {
    e.preventDefault();
    e.stopPropagation();
    (e.target as Element).setPointerCapture(e.pointerId);
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    const anchorMs = xToMs(e.clientX - rect.left);
    setDrag({ kind, anchorMs, originalWindow: { ...window } });
  };

  const onPointerMove = (e: React.PointerEvent<SVGElement>) => {
    if (!drag) return;
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    const pointerMs = xToMs(clamp(e.clientX - rect.left, 0, svgWidth));
    const minSpan = Math.max(Math.round(span / BIN_COUNT), 1000); // at least 1 bin or 1 s

    if (drag.kind === 'baseline') {
      onBaselineEndChange(clamp(pointerMs, fullRange.start, fullRange.end));
      return;
    }

    if (drag.kind === 'left') {
      const ns = clamp(pointerMs, fullRange.start, drag.originalWindow.end - minSpan);
      onWindowChange({ start: ns, end: drag.originalWindow.end });
    } else if (drag.kind === 'right') {
      const ne = clamp(pointerMs, drag.originalWindow.start + minSpan, fullRange.end);
      onWindowChange({ start: drag.originalWindow.start, end: ne });
    } else {
      const delta = pointerMs - drag.anchorMs;
      const winSpan = drag.originalWindow.end - drag.originalWindow.start;
      let ns = drag.originalWindow.start + delta;
      let ne = drag.originalWindow.end + delta;
      if (ns < fullRange.start) { ns = fullRange.start; ne = ns + winSpan; }
      if (ne > fullRange.end) { ne = fullRange.end; ns = ne - winSpan; }
      onWindowChange({ start: ns, end: ne });
    }
  };

  const onPointerUp = (e: React.PointerEvent<SVGElement>) => {
    try { (e.target as Element).releasePointerCapture(e.pointerId); } catch { /* ignore */ }
    setDrag(null);
  };

  // --- Quick-range presets -------------------------------------------------
  const selectLastNMin = (n: number) => {
    const end = fullRange.end;
    const start = Math.max(fullRange.start, end - n * 60_000);
    onWindowChange({ start, end });
  };

  const selectFullRange = () => {
    onWindowChange({ start: fullRange.start, end: fullRange.end });
  };

  // --- Rendering -----------------------------------------------------------
  const xLeft = msToX(window.start);
  const xRight = msToX(window.end);

  // Axis tick labels - 5 evenly-spaced ticks across the full range
  const ticks = useMemo(() => {
    const out: { x: number; label: string }[] = [];
    const N = 5;
    for (let i = 0; i <= N; i += 1) {
      const ms = fullRange.start + (span * i) / N;
      out.push({ x: (svgWidth * i) / N, label: fmtTime(ms) });
    }
    return out;
  }, [fullRange.start, span, svgWidth]);

  const anomaliesInWindow = useMemo(() => {
    let c = 0;
    for (const a of anomalies) {
      const t = a.detectedAt ? new Date(a.detectedAt).getTime() : NaN;
      if (Number.isFinite(t) && t >= window.start && t <= window.end) c += 1;
    }
    return c;
  }, [anomalies, window.start, window.end]);

  const anomaliesInBaseline = useMemo(() => {
    let c = 0;
    for (const a of anomalies) {
      const t = a.detectedAt ? new Date(a.detectedAt).getTime() : NaN;
      if (Number.isFinite(t) && t >= fullRange.start && t <= baselineEnd) c += 1;
    }
    return c;
  }, [anomalies, fullRange.start, baselineEnd]);

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-3">
      {/* Controls row */}
      <div className="flex flex-wrap items-center gap-3 mb-2">
        <button
          onClick={onPlayToggle}
          className={`px-3 py-1 rounded-md text-xs font-medium inline-flex items-center gap-1 border ${
            isPlaying
              ? 'bg-blue-600 text-white border-blue-600'
              : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
          }`}
          title={isPlaying ? 'Pause replay' : 'Replay over time'}
        >
          {isPlaying ? (
            <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor"><rect x="1" y="1" width="3" height="8"/><rect x="6" y="1" width="3" height="8"/></svg>
          ) : (
            <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor"><path d="M1 1 L1 9 L9 5 Z"/></svg>
          )}
          {isPlaying ? 'Pause' : 'Play'}
        </button>

        <button
          onClick={onLiveToggle}
          className={`px-3 py-1 rounded-md text-xs font-medium inline-flex items-center gap-1 border ${
            isLive
              ? 'bg-red-50 text-red-700 border-red-300'
              : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
          }`}
          title={isLive ? 'Window is locked to the latest events' : 'Click to lock window to "now"'}
        >
          <span className={`inline-block w-2 h-2 rounded-full ${isLive ? 'bg-red-500 animate-pulse' : 'bg-gray-400'}`} />
          {isLive ? 'Live' : 'Go Live'}
        </button>

        <div className="flex items-center gap-1">
          <span className="text-[10px] uppercase text-gray-500 font-semibold">Quick</span>
          {[1, 5, 15, 60].map((n) => (
            <button
              key={n}
              onClick={() => selectLastNMin(n)}
              className="px-2 py-0.5 rounded text-xs text-gray-600 hover:bg-gray-100 border border-gray-200"
            >
              {n < 60 ? `${n}m` : '1h'}
            </button>
          ))}
          <button
            onClick={selectFullRange}
            className="px-2 py-0.5 rounded text-xs text-gray-600 hover:bg-gray-100 border border-gray-200"
          >
            All
          </button>
        </div>

        <div className="ml-auto text-xs text-gray-600">
          <span className="text-gray-400">Window: </span>
          <span className="font-medium text-gray-800">
            {fmtTime(window.start)} → {fmtTime(window.end)}
          </span>
          <span className="text-gray-400"> · </span>
          <span className="text-gray-700">{fmtDuration(Math.max(1, window.end - window.start))}</span>
          <span className="text-gray-400"> · </span>
          <span className="text-gray-700">{anomaliesInWindow} anomaly event(s)</span>
        </div>
      </div>

      {/* SVG histogram + window overlay */}
      <div className="relative">
        <svg
          ref={svgRef}
          width="100%"
          height={HISTOGRAM_HEIGHT + 22}
          className="block select-none cursor-crosshair"
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
        >
          {/* Axis base */}
          <line
            x1={0}
            y1={HISTOGRAM_HEIGHT + 0.5}
            x2={svgWidth}
            y2={HISTOGRAM_HEIGHT + 0.5}
            stroke="#E5E7EB"
          />

          {/* Histogram bars */}
          {bins.map((bin, i) => {
            const barX = (svgWidth * i) / BIN_COUNT;
            const barW = svgWidth / BIN_COUNT - 1;
            let yCursor = HISTOGRAM_HEIGHT;
            const rects: React.ReactNode[] = [];
            for (const sev of STACK_ORDER) {
              const v = bin[sev];
              if (v <= 0) continue;
              const h = maxBin > 0 ? (v / maxBin) * HISTOGRAM_HEIGHT : 0;
              yCursor -= h;
              rects.push(
                <rect
                  key={`${i}-${sev}`}
                  x={barX}
                  y={yCursor}
                  width={Math.max(1, barW)}
                  height={Math.max(1, h)}
                  fill={SEVERITY_COLOR[sev]}
                  opacity={0.85}
                />
              );
            }
            return <g key={i}>{rects}</g>;
          })}

          {/* Baseline period tint - everything before the baseline handle */}
          <rect
            x={0}
            y={0}
            width={Math.max(0, msToX(baselineEnd))}
            height={HISTOGRAM_HEIGHT}
            fill="rgba(20, 184, 166, 0.12)"
          />
          <text
            x={4}
            y={11}
            fontSize={9}
            fontWeight={700}
            fill="#0F766E"
            style={{ letterSpacing: 0.5 }}
          >
            BASELINE
          </text>

          {/* Outside-window dimmer (drawn on top of baseline tint) */}
          <rect
            x={0}
            y={0}
            width={Math.max(0, xLeft)}
            height={HISTOGRAM_HEIGHT}
            fill="rgba(255,255,255,0.55)"
          />
          <rect
            x={Math.min(svgWidth, xRight)}
            y={0}
            width={Math.max(0, svgWidth - xRight)}
            height={HISTOGRAM_HEIGHT}
            fill="rgba(255,255,255,0.55)"
          />

          {/* Window rectangle */}
          <rect
            x={xLeft}
            y={0}
            width={Math.max(2, xRight - xLeft)}
            height={HISTOGRAM_HEIGHT}
            fill="rgba(37, 99, 235, 0.10)"
            stroke="#2563EB"
            strokeWidth={1.2}
            onPointerDown={(e) => onPointerDown(e, 'move')}
            style={{ cursor: 'grab' }}
          />

          {/* Left handle */}
          <g onPointerDown={(e) => onPointerDown(e, 'left')} style={{ cursor: 'ew-resize' }}>
            <line x1={xLeft} y1={0} x2={xLeft} y2={HISTOGRAM_HEIGHT} stroke="#2563EB" strokeWidth={2} />
            <rect x={xLeft - 4} y={HISTOGRAM_HEIGHT / 2 - 9} width={8} height={18} rx={2} fill="#2563EB" />
          </g>

          {/* Right handle */}
          <g onPointerDown={(e) => onPointerDown(e, 'right')} style={{ cursor: 'ew-resize' }}>
            <line x1={xRight} y1={0} x2={xRight} y2={HISTOGRAM_HEIGHT} stroke="#2563EB" strokeWidth={2} />
            <rect x={xRight - 4} y={HISTOGRAM_HEIGHT / 2 - 9} width={8} height={18} rx={2} fill="#2563EB" />
          </g>

          {/* Baseline-end draggable marker (teal) */}
          <g onPointerDown={(e) => onPointerDown(e, 'baseline')} style={{ cursor: 'ew-resize' }}>
            <line
              x1={msToX(baselineEnd)}
              y1={0}
              x2={msToX(baselineEnd)}
              y2={HISTOGRAM_HEIGHT}
              stroke="#0F766E"
              strokeWidth={1.5}
              strokeDasharray="4,3"
            />
            <polygon
              points={`${msToX(baselineEnd) - 6},${HISTOGRAM_HEIGHT - 10} ${msToX(baselineEnd) + 6},${HISTOGRAM_HEIGHT - 10} ${msToX(baselineEnd)},${HISTOGRAM_HEIGHT - 2}`}
              fill="#0F766E"
            />
          </g>

          {/* X-axis labels */}
          {ticks.map((t, i) => (
            <text
              key={i}
              x={clamp(t.x, 18, svgWidth - 18)}
              y={HISTOGRAM_HEIGHT + 15}
              fontSize={10}
              fill="#6B7280"
              textAnchor={i === 0 ? 'start' : i === ticks.length - 1 ? 'end' : 'middle'}
            >
              {t.label}
            </text>
          ))}
        </svg>
      </div>

      <div className="text-[10px] text-gray-400 mt-1 flex flex-wrap gap-x-3 gap-y-1">
        <span>
          {fmtDate(fullRange.start)} {fmtTime(fullRange.start)} → {fmtDate(fullRange.end)} {fmtTime(fullRange.end)}
        </span>
        <span className="inline-flex items-center gap-1 text-teal-700">
          <span className="inline-block w-2 h-2 rounded-sm" style={{ background: 'rgba(20,184,166,0.5)' }} />
          Baseline: {fmtTime(fullRange.start)} → {fmtTime(baselineEnd)} ({anomaliesInBaseline} events)
        </span>
        <span className="text-gray-500">
          Drag the blue window to pick a range, the teal marker to resize the baseline. New comms will be flagged on the graph.
        </span>
      </div>
    </div>
  );
};

export default NetworkTopologyTimeline;
