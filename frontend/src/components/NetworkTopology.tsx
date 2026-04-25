import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Network, DataSet } from 'vis-network/standalone/esm/vis-network';
import Layout from './Layout';
import { User } from '../types/user';
import topologyService, {
  TopologyGraph,
  TopologyNode,
  TopologyEdge,
  TopologyRawData,
  Severity,
  ZONES,
  ZONE_ORDER,
  buildGraph,
  EdgeAnalytics,
} from '../services/topologyService';
import { Anomaly } from '../services/anomalyService';
import dpiService, { DpiEvent, FunctionCodeStat } from '../services/dpiService';
import {
  AssetIconKey,
  detectAssetIconKey,
  makeIconDataUri,
  ICON_LABEL,
} from './topologyIcons';
import NetworkTopologyTimeline, { TimeWindow } from './NetworkTopologyTimeline';
import DpiEventModal, { DpiModalScope } from './DpiEventModal';

// --- Visual constants -------------------------------------------------------

const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: '#DC2626', // red-600
  HIGH: '#EA580C',     // orange-600
  MEDIUM: '#D97706',   // amber-600
  LOW: '#16A34A',      // green-600
  INFO: '#2563EB',     // blue-600
  NONE: '#6B7280',     // gray-500
};

const PURDUE_LABELS: Record<number, string> = {
  0: 'L0 · Field Devices (Sensors/Actuators)',
  1: 'L1 · Basic Control (PLC/RTU)',
  2: 'L2 · Supervisory (HMI/SCADA)',
  3: 'L3 · Operations (MES/Historian)',
  4: 'L4 · Enterprise (ERP/Business)',
  5: 'L5 · DMZ / External',
};

const PURDUE_SHORT: Record<number, string> = {
  0: 'Field Devices',
  1: 'Basic Control',
  2: 'Supervisory',
  3: 'Operations',
  4: 'Enterprise',
  5: 'DMZ / External',
};

// Subtle alternating band colors - chosen so the graph remains the visual hero
const BAND_BG: Record<number, string> = {
  0: 'rgba(16, 185, 129, 0.05)',   // L0 green tint - physical
  1: 'rgba(14, 165, 233, 0.05)',   // L1 blue tint
  2: 'rgba(99, 102, 241, 0.05)',   // L2 indigo tint
  3: 'rgba(139, 92, 246, 0.05)',   // L3 violet tint
  4: 'rgba(236, 72, 153, 0.05)',   // L4 pink tint
  5: 'rgba(239, 68, 68, 0.06)',    // L5 red tint - riskiest zone
};

const BAND_ACCENT: Record<number, string> = {
  0: '#10B981', // emerald
  1: '#0EA5E9', // sky
  2: '#6366F1', // indigo
  3: '#8B5CF6', // violet
  4: '#EC4899', // pink
  5: '#EF4444', // red
};

const ALL_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

type ViewMode = 'purdue' | 'zones';

// --- Helpers (pure) ---------------------------------------------------------

/**
 * Compute the full time range covered by the anomaly dataset. Pads the right
 * edge to "now" so the Live mode always has room to advance into.
 */
const computeFullRange = (anomalies: Anomaly[]): TimeWindow => {
  const now = Date.now();
  let min = Infinity;
  let max = -Infinity;
  for (const a of anomalies) {
    const t = a.detectedAt ? new Date(a.detectedAt).getTime() : NaN;
    if (!Number.isFinite(t)) continue;
    if (t < min) min = t;
    if (t > max) max = t;
  }
  if (!Number.isFinite(min)) {
    // No anomalies at all - give the scrubber a reasonable default
    return { start: now - 30 * 60_000, end: now };
  }
  // Guarantee a positive span and give a little breathing room on each side
  const spanPad = Math.max(60_000, (max - min) * 0.05);
  return {
    start: min - spanPad,
    end: Math.max(max + spanPad, now),
  };
};

// --- Component --------------------------------------------------------------

export interface NetworkTopologyProps {
  /**
   * When true, render a compact, chrome-less version suitable for embedding
   * inside another page (e.g. the Dashboard). Hides the page header, filter
   * bar, timeline, detail side-panel and Layout wrapper; shrinks the canvas
   * to a fixed height and shows an "Open full view →" shortcut.
   */
  embedded?: boolean;
}

const NetworkTopology: React.FC<NetworkTopologyProps> = ({ embedded = false }) => {
  const navigate = useNavigate();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const networkRef = useRef<Network | null>(null);
  const nodesDsRef = useRef<DataSet<any> | null>(null);
  const edgesDsRef = useRef<DataSet<any> | null>(null);

  const [user, setUser] = useState<User | undefined>(undefined);
  const [rawData, setRawData] = useState<TopologyRawData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<TopologyNode | null>(null);
  // DPI detail modal - opened on edge double-click (single click still shows tooltip)
  const [dpiModalScope, setDpiModalScope] = useState<DpiModalScope | null>(null);

  // Timeline state ----------------------------------------------------------
  const [timeWindow, setTimeWindow] = useState<TimeWindow | null>(null);
  /** Everything between fullRange.start and `baselineEnd` is treated as normal
   *  behavior - comms seen *only* after this point get a "NEW" badge. */
  const [baselineEnd, setBaselineEnd] = useState<number | null>(null);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [isLive, setIsLive] = useState<boolean>(false);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(
    new Set(ALL_SEVERITIES)
  );
  const [levelFilter, setLevelFilter] = useState<Set<number>>(new Set([0, 1, 2, 3, 4, 5]));
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [showUnknownOnly, setShowUnknownOnly] = useState<boolean>(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [viewMode, setViewMode] = useState<ViewMode>('purdue');
  const [scenarioOpen, setScenarioOpen] = useState<boolean>(true);
  /**
   * Explicit "Show demo scenario" toggle. Defaults to false so a fresh
   * install shows an empty graph (with a diagnostic panel explaining why)
   * instead of the hardcoded attack simulation - that had been confusing
   * users into thinking the fake attack was coming from their own network.
   */
  const [showDemo, setShowDemo] = useState<boolean>(false);

  // --- User bootstrap -------------------------------------------------------
  useEffect(() => {
    const raw = localStorage.getItem('user');
    if (raw) {
      try { setUser(JSON.parse(raw)); } catch { /* ignore */ }
    }
  }, []);

  // --- Data load ------------------------------------------------------------
  const loadGraph = async () => {
    setIsRefreshing(true);
    try {
      const raw = await topologyService.getRawData({ forceDemo: showDemo });
      setRawData(raw);
      // On first load, initialize the timeline window to cover the full range.
      const full = computeFullRange(raw.anomalies);
      setTimeWindow((prev) => prev ?? full);
      // Default: baseline covers the first 40% of the time range. Operators
      // can then drag the teal marker if they know more about when things
      // started getting weird.
      setBaselineEnd((prev) => prev ?? full.start + (full.end - full.start) * 0.4);
      setError(null);
    } catch (e: any) {
      setError(e?.message || 'Failed to load topology');
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadGraph();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showDemo]);

  // --- Live refresh (only when isLive) --------------------------------------
  useEffect(() => {
    if (!isLive) return;
    const id = globalThis.setInterval(() => { loadGraph(); }, 30_000);
    return () => globalThis.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLive]);

  // When isLive is on, snap the window end to "now" whenever data reloads.
  useEffect(() => {
    if (!isLive || !rawData) return;
    setTimeWindow((w) => {
      const full = computeFullRange(rawData.anomalies);
      const duration = w ? w.end - w.start : 5 * 60_000;
      return { start: Math.max(full.start, full.end - duration), end: full.end };
    });
  }, [isLive, rawData]);

  // --- Full time range (from anomaly timestamps) ----------------------------
  const fullRange: TimeWindow = useMemo(() => {
    if (!rawData) {
      const now = Date.now();
      return { start: now - 30 * 60_000, end: now };
    }
    return computeFullRange(rawData.anomalies);
  }, [rawData]);

  // --- Build the graph from raw data, filtered by the selected window ------
  const graph = useMemo<TopologyGraph | null>(() => {
    if (!rawData) return null;
    const w = timeWindow;
    const filteredAnomalies: Anomaly[] = w
      ? rawData.anomalies.filter((a) => {
          const t = a.detectedAt ? new Date(a.detectedAt).getTime() : NaN;
          return Number.isFinite(t) && t >= w.start && t <= w.end;
        })
      : rawData.anomalies;
    return buildGraph(rawData.assets, filteredAnomalies, {
      demo: rawData.isDemo,
      scenario: rawData.scenario,
      baselineConnections: rawData.baselineConnections,
      analytics: (w && baselineEnd !== null)
        ? {
            allAnomalies: rawData.anomalies,
            baselineWindow: { start: fullRange.start, end: baselineEnd },
            selectedWindow: w,
            fullRange,
          }
        : undefined,
    });
  }, [rawData, timeWindow, baselineEnd, fullRange]);

  // --- Filtered graph view --------------------------------------------------
  const filteredGraph = useMemo<TopologyGraph | null>(() => {
    if (!graph) return null;

    const edgesAfterProtocol = graph.edges.filter((e) =>
      protocolFilter === 'ALL' ? true : e.protocols.includes(protocolFilter)
    );

    const nodesPass = (n: TopologyNode): boolean => {
      if (!levelFilter.has(n.purdueLevel)) return false;
      if (showUnknownOnly && n.isKnown) return false;
      // Keep node if any edge touching it matches the severity filter OR
      // (node has no anomaly edges) AND severity filter still includes NONE/LOW
      return true;
    };

    const allowedNodeIds = new Set(graph.nodes.filter(nodesPass).map((n) => n.id));

    const edges = edgesAfterProtocol.filter(
      (e) => severityFilter.has(e.severity) && allowedNodeIds.has(e.source) && allowedNodeIds.has(e.target)
    );

    const nodes = graph.nodes.filter((n) => allowedNodeIds.has(n.id));

    return { ...graph, nodes, edges };
  }, [graph, severityFilter, levelFilter, protocolFilter, showUnknownOnly]);

  // --- Available protocol list ---------------------------------------------
  const protocolOptions = useMemo<string[]>(() => {
    if (!graph) return [];
    const set = new Set<string>();
    graph.edges.forEach((e) => e.protocols.forEach((p) => set.add(p)));
    return Array.from(set).sort();
  }, [graph]);

  // --- Icon types present in the current view (for the icon legend) --------
  const usedIconKeys = useMemo<AssetIconKey[]>(() => {
    if (!filteredGraph) return [];
    const set = new Set<AssetIconKey>();
    filteredGraph.nodes.forEach((n) => {
      const key = n.isKnown
        ? detectAssetIconKey(n.asset?.assetType, n.asset?.assetCategory)
        : 'UNKNOWN';
      set.add(key);
    });
    return Array.from(set);
  }, [filteredGraph]);

  // --- Vis-network init -----------------------------------------------------
  useEffect(() => {
    if (!containerRef.current || !filteredGraph) return;

    const nodes = new DataSet<any>(
      filteredGraph.nodes.map((n) => buildVisNode(n, viewMode))
    );
    const edges = new DataSet<any>(
      filteredGraph.edges.map((e) => buildVisEdge(e, viewMode))
    );
    nodesDsRef.current = nodes;
    edgesDsRef.current = edges;

    const isZones = viewMode === 'zones';

    const options = {
      autoResize: true,
      layout: isZones
        ? { hierarchical: { enabled: false }, improvedLayout: true }
        : {
            // `improvedLayout:false` disables vis-network's extra post-pass
            // that can re-run on zoom and nudge Y coordinates, which caused
            // nodes to visibly drift between Purdue bands while zooming.
            improvedLayout: false,
            hierarchical: {
              enabled: true,
              direction: 'DU', // Down → Up so that L0 (field) is at the bottom
              sortMethod: 'directed',
              levelSeparation: 120,
              nodeSpacing: 160,
              treeSpacing: 200,
            },
          },
      interaction: {
        hover: true,
        tooltipDelay: 120,
        zoomView: true,
        dragView: true,
        navigationButtons: true,
      },
      physics: isZones
        ? {
            // Physics-on only for zones view: a gentle barnesHut force clusters
            // same-zone nodes together (each zone has a common "gravity well")
            // and then stabilization freezes them.
            enabled: true,
            solver: 'barnesHut',
            stabilization: { iterations: 220, fit: true },
            barnesHut: {
              gravitationalConstant: -6000,
              centralGravity: 0.1,
              springLength: 120,
              springConstant: 0.05,
              damping: 0.18,
              avoidOverlap: 0.4,
            },
          }
        : { enabled: false },
      nodes: {
        shape: 'dot',
        size: 18,
        borderWidth: 2,
        font: { color: '#111827', size: 12, face: 'Inter, system-ui, sans-serif' },
      },
      edges: {
        smooth: { enabled: true, type: 'curvedCW', roundness: 0.15 },
        arrows: { to: { enabled: true, scaleFactor: 0.6 } },
        font: { size: 10, align: 'middle' },
      },
    };

    if (networkRef.current) {
      networkRef.current.destroy();
    }
    const network = new Network(containerRef.current, { nodes, edges }, options as any);
    networkRef.current = network;

    // ----------------------------------------------------------------------
    // Initial framing
    // ----------------------------------------------------------------------
    // vis-network's built-in fit is too aggressive on short graphs: when only
    // a handful of Purdue levels / nodes are present it zooms the whole
    // layout way out, producing tiny nodes on first render. We override by
    // calling fit() ourselves with generous padding, then enforcing a minimum
    // scale floor so the graph never loads smaller than readable.
    //
    // For the zones view we wait for stabilization to finish; for the
    // hierarchical Purdue view positions are instant so we run on the next
    // animation frame.
    const applyInitialFraming = () => {
      try {
        network.fit({
          animation: false,
          // Ask vis-network to leave roughly a node's worth of margin around
          // the bbox - keeps the graph from hugging the canvas edges.
          // (Padding is expressed as screen pixels.)
          // @ts-ignore - vis-network typings don't include `offset` but accept it
          minZoomLevel: 0.6,
          // @ts-ignore
          maxZoomLevel: 1.6,
        } as any);
      } catch {
        // ignore - best-effort
      }
      // Enforce a minimum zoom floor after fit so small graphs don't render
      // at 0.3× and look tiny. 0.9 keeps nodes at a comfortable size without
      // clipping medium-sized topologies.
      try {
        const scale = network.getScale();
        const MIN_SCALE = 0.9;
        if (scale < MIN_SCALE) {
          // Preserve the current view center while zooming in.
          const view = (network as any).getViewPosition?.() || { x: 0, y: 0 };
          network.moveTo({
            position: view,
            scale: MIN_SCALE,
            animation: false,
          } as any);
        }
      } catch {
        // ignore
      }
    };

    if (isZones) {
      // Physics-driven layout: fit once stabilization finishes so node
      // positions have settled.
      network.once('stabilizationIterationsDone', () => applyInitialFraming());
      // Safety net in case `stabilizationIterationsDone` doesn't fire
      // (e.g. very small graphs stabilize before the listener attaches).
      setTimeout(applyInitialFraming, 400);
    } else {
      // Hierarchical layout: positions are known immediately.
      // requestAnimationFrame lets the first paint happen so the badge text
      // metrics can be measured against real canvas state.
      requestAnimationFrame(applyInitialFraming);
    }

    // Draw IEC 62443 zone rectangles underneath the nodes in zones view.
    // We compute each zone's bbox from the live node positions so the
    // boundary follows nodes when the user drags them.
    if (isZones) {
      network.on('beforeDrawing', (ctx: CanvasRenderingContext2D) => {
        drawZoneBackdrops(ctx, network, filteredGraph.nodes);
      });
    } else {
      // Purdue view: paint horizontal level bands *inside* the canvas so they
      // share the same transform as the nodes. Drawing them on the canvas (not
      // as a static HTML sidebar) keeps nodes and bands aligned regardless of
      // zoom or pan - previously the HTML sidebar was fixed-height while the
      // canvas zoomed, so nodes drifted into the wrong band visually.
      network.on('beforeDrawing', (ctx: CanvasRenderingContext2D) => {
        drawPurdueBands(ctx, network, filteredGraph.nodes);
      });
    }

    network.on('click', (params: any) => {
      if (params.nodes && params.nodes.length > 0) {
        const id = params.nodes[0];
        const node = filteredGraph.nodes.find((n) => n.id === id) || null;
        setSelected(node);
      } else {
        setSelected(null);
      }
    });

    // Double-click on an edge opens the DPI detail modal for that src↔dst pair.
    // Double-click on a node opens the node-scoped DPI modal.
    network.on('doubleClick', (params: any) => {
      if (params.edges && params.edges.length > 0 && (!params.nodes || params.nodes.length === 0)) {
        const edgeId = params.edges[0];
        const edge = filteredGraph.edges.find((e) => e.id === edgeId);
        if (!edge) return;
        const srcNode = filteredGraph.nodes.find((n) => n.id === edge.source);
        const dstNode = filteredGraph.nodes.find((n) => n.id === edge.target);
        if (srcNode?.ip && dstNode?.ip) {
          setDpiModalScope({
            kind: 'edge',
            sourceIp: srcNode.ip,
            destinationIp: dstNode.ip,
            title: `DPI · ${srcNode.label} → ${dstNode.label}`,
          });
        }
      } else if (params.nodes && params.nodes.length > 0) {
        const id = params.nodes[0];
        const node = filteredGraph.nodes.find((n) => n.id === id);
        if (node?.ip) {
          setDpiModalScope({ kind: 'node', ip: node.ip, title: `DPI · ${node.label}` });
        }
      }
    });

    return () => {
      network.off('click');
      network.off('doubleClick');
      network.off('beforeDrawing');
    };
  }, [filteredGraph, viewMode]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (networkRef.current) {
        networkRef.current.destroy();
        networkRef.current = null;
      }
    };
  }, []);

  // --- Helpers --------------------------------------------------------------

  const toggleSeverity = (s: Severity) => {
    const next = new Set(severityFilter);
    next.has(s) ? next.delete(s) : next.add(s);
    setSeverityFilter(next);
  };
  const toggleLevel = (lvl: number) => {
    const next = new Set(levelFilter);
    next.has(lvl) ? next.delete(lvl) : next.add(lvl);
    setLevelFilter(next);
  };

  // --- Render ---------------------------------------------------------------

  // In embedded mode we render a chrome-less, fixed-height mini topology that
  // lives inside a Dashboard card - no Layout wrapper, no page-level header,
  // no timeline/filters/detail panel, just the graph with a shortcut to the
  // full page. This lets Dashboard use the same rendering pipeline as the
  // /topology page without double-wrapping Layout or duplicating code.
  if (embedded) {
    const canvasHeight = 420;
    return (
      <div className="flex flex-col gap-2">
        {/* Compact header: title + "Open full view" shortcut */}
        <div className="flex items-center justify-between px-4 pt-4">
          <div>
            <h3 className="text-base font-semibold text-gray-900">Network Topology</h3>
            <p className="text-xs text-gray-500">
              Assets grouped by Purdue Model. Anomalous paths highlighted in red.
            </p>
          </div>
          <div className="flex items-center gap-2">
            {graph && !loading && (
              <span
                className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold ${
                  graph.isDemo
                    ? 'bg-amber-500 text-white'
                    : 'bg-emerald-600 text-white'
                }`}
              >
                <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
                {graph.isDemo ? 'DEMO' : 'LIVE'}
              </span>
            )}
            <button
              onClick={() => navigate('/topology')}
              className="text-xs font-medium text-blue-700 hover:text-blue-800 hover:underline"
              title="Open the full Network Topology page with filters, timeline and detail panel"
            >
              Open full view →
            </button>
          </div>
        </div>

        {/* Canvas only - purdue bands on the left, graph on the right */}
        <div className="relative overflow-hidden mx-4 mb-4 rounded-md border border-gray-200 bg-white">
          {loading && (
            <div className="absolute inset-0 flex items-center justify-center bg-white/70 z-30 text-gray-500 text-sm">
              Loading topology…
            </div>
          )}
          {error && !loading && (
            <div className="absolute inset-0 flex items-center justify-center text-red-600 z-30 text-sm">
              {error}
            </div>
          )}
          <div className="flex" style={{ height: canvasHeight }}>
            {/* Sidebar removed: Purdue level labels are painted directly onto
                the canvas inside drawPurdueBands and share the zoom/pan
                transform with the nodes, so a separate HTML column would only
                duplicate them. */}
            <div className="relative flex-1">
              {/* Purdue level bands are painted onto the vis-network canvas
                  itself (see drawPurdueBands) so they share the zoom/pan
                  transform with the nodes. An earlier static HTML overlay
                  lived here but caused nodes to drift across bands on zoom. */}
              <div
                ref={containerRef}
                className="absolute inset-0 z-10"
                style={{ background: 'transparent' }}
              />
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <Layout user={user}>
      <div className="flex flex-col gap-6">
        {/* Hero */}
        <div
          className="relative overflow-hidden rounded-2xl p-8 md:p-10 text-white"
          style={{ background: 'linear-gradient(135deg, #1e1b4b 0%, #4c1d95 45%, #7c3aed 100%)' }}
        >
          <div className="absolute -top-20 -right-20 w-72 h-72 rounded-full bg-fuchsia-500/20 blur-3xl" />
          <div className="absolute -bottom-10 -left-10 w-60 h-60 rounded-full bg-violet-400/10 blur-3xl" />
          <div className="relative flex flex-col md:flex-row md:items-end md:justify-between gap-6">
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 ring-1 ring-white/20 text-xs font-semibold tracking-wider backdrop-blur-sm mb-4">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>
                PURDUE MODEL
              </div>
              <h1 className="text-3xl md:text-4xl font-bold leading-tight">
                Network Topology
                <span className="block text-violet-100/90 font-medium text-lg md:text-xl mt-2">
                  Live view of OT/IT assets by Purdue level with highlighted anomalous paths.
                </span>
              </h1>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => setShowDemo((v) => !v)}
                title={
                  showDemo
                    ? 'Currently showing the built-in demo attack scenario. Click to switch back to your real data.'
                    : 'Load a scripted demo attack chain (phishing → ICS pivot) for exploring the UI.'
                }
                className={`px-3 py-2 rounded-xl text-sm font-semibold transition ${
                  showDemo
                    ? 'bg-amber-400/90 text-amber-950 hover:bg-amber-300'
                    : 'bg-white/10 ring-1 ring-white/20 text-white hover:bg-white/15 backdrop-blur-sm'
                }`}
              >
                {showDemo ? 'Showing demo scenario' : 'Show demo scenario'}
              </button>
              <button
                onClick={() => loadGraph()}
                disabled={isRefreshing}
                className="px-4 py-2 rounded-xl text-sm font-semibold bg-white text-violet-700 hover:bg-violet-50 shadow-lg shadow-black/10 disabled:opacity-60 transition"
              >
                {isRefreshing ? 'Refreshing…' : 'Refresh'}
              </button>
            </div>
          </div>
        </div>

        {/* Mode banner - impossible-to-miss indicator of whether the graph
            currently shows DEMO data or LIVE pcap-derived data. */}
        {graph && !loading && (
          <div
            className={`rounded-lg border px-4 py-2 flex items-center gap-3 text-sm ${
              graph.isDemo
                ? 'bg-amber-100 border-amber-300 text-amber-900'
                : 'bg-emerald-50 border-emerald-300 text-emerald-900'
            }`}
          >
            <span
              className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-bold ${
                graph.isDemo
                  ? 'bg-amber-500 text-white'
                  : 'bg-emerald-600 text-white'
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
              {graph.isDemo ? 'DEMO MODE' : 'LIVE DATA'}
            </span>
            <span>
              {graph.isDemo
                ? 'You are looking at a scripted attack scenario. None of this is your real network.'
                : rawData?.diagnostics
                  ? `Showing live data from your backend: ${rawData.diagnostics.assetCount} asset(s), ${rawData.diagnostics.anomalyCount} anomaly record(s), ${rawData.diagnostics.observedConnectionCount} DPI pair(s).`
                  : 'Showing live data from your backend.'}
            </span>
          </div>
        )}

        {/* KPI strip */}
        {graph && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <KpiCard label="Known Assets" value={graph.stats.assetCount} tone="blue" />
            <KpiCard label="Unknown External IPs" value={graph.stats.unknownIpCount} tone="amber" />
            <KpiCard label="Anomalous Edges" value={graph.stats.anomalousEdges} tone="red" />
            <KpiCard
              label="Worst Severity"
              value={
                graph.edges.reduce<Severity>(
                  (acc, e) => (rank(e.severity) > rank(acc) ? e.severity : acc),
                  'NONE'
                )
              }
              tone="gray"
            />
          </div>
        )}

        {/* Diagnostic panel - shows operators exactly which real data sources
            populated this graph so they aren't left guessing whether the view
            is demo or real. Also renders an "empty DB" hint when the topology
            is legitimately blank. */}
        {rawData?.diagnostics && !rawData.isDemo && (
          <DataSourcePanel
            diagnostics={rawData.diagnostics}
            onShowDemo={() => setShowDemo(true)}
          />
        )}
        {rawData?.isDemo && rawData.diagnostics?.fellBackToDemo && (
          <div className="rounded-lg border border-red-300 bg-red-50 px-4 py-2 text-sm text-red-800">
            <span className="font-semibold">Backend unreachable.</span> All three
            data sources (/api/assets, anomalies, /api/dpi/observed-connections)
            failed. Showing the built-in demo scenario as a placeholder. Check
            the backend service and click <span className="font-mono">Refresh</span>.
          </div>
        )}

        {/* Icon legend - which device types are present in this view */}
        {usedIconKeys.length > 0 && (
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 px-3 py-2 flex flex-wrap items-center gap-x-4 gap-y-2">
            <span className="text-xs font-semibold text-gray-600 uppercase">Device Types</span>
            {usedIconKeys.map((key) => (
              <div key={key} className="flex items-center gap-1.5 text-xs text-gray-700">
                <img
                  src={makeIconDataUri(key)}
                  alt={ICON_LABEL[key]}
                  className="w-5 h-5 rounded-full ring-1 ring-gray-300"
                />
                <span>{ICON_LABEL[key]}</span>
              </div>
            ))}
          </div>
        )}

        {/* Scenario banner - only shown when demo scenario data is loaded */}
        {graph?.isDemo && graph.scenario && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3">
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="text-xs uppercase tracking-wide text-amber-700 font-semibold">
                  Demo scenario
                </div>
                <div className="text-sm font-semibold text-amber-900">
                  {graph.scenario.title}
                </div>
                <div className="text-xs text-amber-800 mt-1">
                  {graph.scenario.summary}
                </div>
              </div>
              <button
                onClick={() => setScenarioOpen((v) => !v)}
                className="text-xs font-medium text-amber-800 hover:text-amber-900 underline"
              >
                {scenarioOpen ? 'Hide steps' : 'Show steps'}
              </button>
            </div>
            {scenarioOpen && (
              <ol className="mt-2 space-y-1 text-xs text-amber-900 list-none">
                {graph.scenario.steps.map((s, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="flex-shrink-0 font-mono text-amber-700">→</span>
                    <span>{s}</span>
                  </li>
                ))}
              </ol>
            )}
          </div>
        )}

        {/* Filter bar */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-3 flex flex-wrap gap-4 items-center">
          {/* View mode toggle */}
          <div className="flex items-center gap-1 bg-gray-100 rounded-md p-0.5">
            <button
              onClick={() => setViewMode('purdue')}
              className={`px-3 py-1 text-xs rounded-md font-medium ${
                viewMode === 'purdue'
                  ? 'bg-white shadow-sm text-blue-700'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
              title="Group nodes by Purdue Model level"
            >
              Purdue
            </button>
            <button
              onClick={() => setViewMode('zones')}
              className={`px-3 py-1 text-xs rounded-md font-medium ${
                viewMode === 'zones'
                  ? 'bg-white shadow-sm text-blue-700'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
              title="Group nodes by IEC 62443 security zones"
            >
              Zones
            </button>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-gray-600 uppercase">Severity</span>
            {ALL_SEVERITIES.map((s) => (
              <button
                key={s}
                onClick={() => toggleSeverity(s)}
                className={`px-2 py-1 text-xs rounded-md border ${
                  severityFilter.has(s)
                    ? 'text-white'
                    : 'text-gray-500 bg-white'
                }`}
                style={{
                  backgroundColor: severityFilter.has(s) ? SEVERITY_COLOR[s] : undefined,
                  borderColor: SEVERITY_COLOR[s],
                }}
              >
                {s}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-gray-600 uppercase">Purdue Level</span>
            {[0, 1, 2, 3, 4, 5].map((lvl) => (
              <button
                key={lvl}
                onClick={() => toggleLevel(lvl)}
                className={`px-2 py-1 text-xs rounded-md border ${
                  levelFilter.has(lvl)
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white text-gray-600 border-gray-300'
                }`}
                title={PURDUE_LABELS[lvl]}
              >
                L{lvl}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-gray-600 uppercase">Protocol</span>
            <select
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
              className="text-xs border border-gray-300 rounded-md px-2 py-1"
            >
              <option value="ALL">All</option>
              {protocolOptions.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </div>

          <label className="flex items-center gap-1 text-xs text-gray-700 ml-auto">
            <input
              type="checkbox"
              checked={showUnknownOnly}
              onChange={(e) => setShowUnknownOnly(e.target.checked)}
            />
            Show unknown/external only
          </label>
        </div>

        {/* Main canvas + side panel */}
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-4">
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 relative overflow-hidden">
            {loading && (
              <div className="absolute inset-0 flex items-center justify-center bg-white/70 z-30 text-gray-500">
                Loading topology…
              </div>
            )}
            {error && !loading && (
              <div className="absolute inset-0 flex items-center justify-center text-red-600 z-30">
                {error}
              </div>
            )}

            {/* Main drawing area. Layout swaps based on viewMode:
                - Purdue: left labels column + horizontal layer bands behind canvas
                - Zones: no bands; zone rectangles are painted on the canvas itself */}
            <div className="flex" style={{ height: 640 }}>
              {/* The left-side HTML column (labels + level filter toggles)
                  was removed - Purdue level labels are now painted onto the
                  canvas inside drawPurdueBands. Per-level filter toggles live
                  in the Level filter bar above the canvas. */}

              {/* Drawing surface. In Purdue mode the level bands are painted
                  onto the vis-network canvas (drawPurdueBands) so they share
                  the node transform and stay aligned through zoom/pan. An
                  older HTML overlay used to live here but caused nodes to
                  visibly drift across bands whenever the user zoomed. The
                  left-side column still provides per-level filter toggles. */}
              <div className="relative flex-1">
                <div
                  ref={containerRef}
                  className="absolute inset-0 z-10"
                  style={{ background: 'transparent' }}
                />

                {viewMode === 'zones' && <ZoneLegendOverlay />}
              </div>
            </div>

            <Legend />
          </div>

          <DetailPanel
            node={selected}
            anomalies={rawData?.anomalies ?? []}
            graph={graph}
            selectedWindow={timeWindow}
          />
        </div>

        {/* Timeline scrubber - replay / live / draggable time window */}
        {rawData && timeWindow && baselineEnd !== null && (
          <NetworkTopologyTimeline
            anomalies={rawData.anomalies}
            fullRange={fullRange}
            window={timeWindow}
            onWindowChange={(w) => {
              setTimeWindow(w);
              // Any manual window change exits Live mode; that's the right
              // mental model - the user is taking manual control.
              if (isLive) setIsLive(false);
            }}
            baselineEnd={baselineEnd}
            onBaselineEndChange={setBaselineEnd}
            isPlaying={isPlaying}
            onPlayToggle={() => {
              setIsPlaying((v) => !v);
              if (isLive) setIsLive(false);
            }}
            isLive={isLive}
            onLiveToggle={() => {
              setIsLive((v) => {
                const next = !v;
                if (next) setIsPlaying(false);
                return next;
              });
            }}
          />
        )}
      </div>
      <DpiEventModal
        open={dpiModalScope !== null}
        scope={dpiModalScope}
        onClose={() => setDpiModalScope(null)}
      />
    </Layout>
  );
};

// --- Sub-components ---------------------------------------------------------

const KpiCard: React.FC<{ label: string; value: number | string; tone: 'blue' | 'red' | 'amber' | 'gray' }> = ({
  label, value, tone,
}) => {
  const toneMap: Record<string, string> = {
    blue: 'bg-blue-50 text-blue-700 border-blue-100',
    red: 'bg-red-50 text-red-700 border-red-100',
    amber: 'bg-amber-50 text-amber-700 border-amber-100',
    gray: 'bg-gray-50 text-gray-700 border-gray-200',
  };
  return (
    <div className={`rounded-lg border p-3 ${toneMap[tone]}`}>
      <div className="text-xs uppercase tracking-wide">{label}</div>
      <div className="text-2xl font-semibold">{value}</div>
    </div>
  );
};

/**
 * Explains *why* the graph looks the way it does, source by source. Replaces
 * the old silent "empty → demo fallback" behavior: if the DB genuinely is
 * empty, the operator now sees "Assets: 0, Anomalies: 0, DPI events: 0" and a
 * hint about uploading a pcap, rather than looking at fake attack traffic and
 * thinking it was real.
 */
const DataSourcePanel: React.FC<{
  diagnostics: NonNullable<TopologyRawData['diagnostics']>;
  onShowDemo: () => void;
}> = ({ diagnostics, onShowDemo }) => {
  const {
    assetCount, anomalyCount, observedConnectionCount,
    assetsError, anomaliesError, observedConnectionsError, allEmpty,
  } = diagnostics;

  const anyError = assetsError || anomaliesError || observedConnectionsError;

  if (allEmpty && !anyError) {
    // DB is empty - help the user take the next step.
    return (
      <div className="rounded-lg border border-gray-200 bg-gray-50 px-4 py-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="text-xs uppercase tracking-wide text-gray-600 font-semibold">
              No real data yet
            </div>
            <div className="text-sm text-gray-800 mt-1">
              The topology graph is empty because no assets, anomalies, or DPI
              events have been recorded yet. Upload a pcap on the Dashboard to
              populate the graph with real traffic. Modbus, S7Comm and IEC104
              flows will appear here automatically.
            </div>
            <div className="mt-2 text-xs text-gray-600 font-mono">
              Assets: {assetCount} · Anomalies: {anomalyCount} · Observed DPI pairs: {observedConnectionCount}
            </div>
          </div>
          <button
            onClick={onShowDemo}
            className="flex-shrink-0 px-3 py-1.5 text-xs font-medium rounded-md bg-white border border-gray-300 text-gray-700 hover:bg-gray-100"
          >
            Explore demo instead
          </button>
        </div>
      </div>
    );
  }

  // Some data present - render a compact source-summary badge row.
  const pill = (label: string, count: number, errored: boolean) => {
    if (errored) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 border border-red-200">
          <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
          {label}: error
        </span>
      );
    }
    const empty = count === 0;
    return (
      <span
        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${
          empty
            ? 'bg-gray-100 text-gray-600 border-gray-200'
            : 'bg-emerald-50 text-emerald-800 border-emerald-200'
        }`}
      >
        <span className={`w-1.5 h-1.5 rounded-full ${empty ? 'bg-gray-400' : 'bg-emerald-500'}`} />
        {label}: {count}
      </span>
    );
  };

  return (
    <div className="rounded-lg border border-gray-200 bg-white px-3 py-2 flex flex-wrap items-center gap-2">
      <span className="text-xs font-semibold text-gray-600 uppercase mr-1">
        Data sources
      </span>
      {pill('Assets', assetCount, assetsError)}
      {pill('Anomalies', anomalyCount, anomaliesError)}
      {pill('Observed DPI pairs', observedConnectionCount, observedConnectionsError)}
      {anyError && (
        <span className="text-xs text-red-700 ml-1">
          One or more APIs failed. Graph may be incomplete.
        </span>
      )}
    </div>
  );
};

const Legend: React.FC = () => (
  <div className="absolute bottom-3 left-3 bg-white/95 rounded-md shadow border border-gray-200 p-2 text-xs space-y-1">
    <div className="font-semibold text-gray-700">Legend</div>
    {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'] as Severity[]).map((s) => (
      <div key={s} className="flex items-center gap-2">
        <span className="inline-block w-3 h-3 rounded-full" style={{ background: SEVERITY_COLOR[s] }} />
        <span className="text-gray-600">{s === 'NONE' ? 'No anomaly' : s}</span>
      </div>
    ))}
    <div className="flex items-center gap-2 pt-1 border-t border-gray-100">
      <span className="inline-block w-3 h-3 rounded-full border-2 border-dashed border-gray-500 bg-white" />
      <span className="text-gray-600">Unknown IP (external)</span>
    </div>
  </div>
);

const DetailPanel: React.FC<{
  node: TopologyNode | null;
  anomalies: Anomaly[];
  graph: TopologyGraph | null;
  selectedWindow: TimeWindow | null;
}> = ({ node, anomalies, graph, selectedWindow }) => {
  // Build comm history for the selected node: recent anomalies + baseline edges.
  const history = useMemo(() => {
    if (!node) return [];
    const ip = node.ip;
    const rows: Array<{
      kind: 'anomaly' | 'baseline';
      ts?: number;
      peerLabel: string;
      peerIp?: string;
      protocol?: string;
      severity?: Severity;
      direction: 'out' | 'in' | 'peer';
      inWindow?: boolean;
      isNew?: boolean;
    }> = [];

    // Anomalies touching this node's IP
    if (ip) {
      for (const a of anomalies) {
        if (a.sourceIp !== ip && a.destinationIp !== ip) continue;
        const t = a.detectedAt ? new Date(a.detectedAt).getTime() : undefined;
        const isSrc = a.sourceIp === ip;
        const peerIp = isSrc ? a.destinationIp : a.sourceIp;
        const inWindow =
          selectedWindow && t !== undefined
            ? t >= selectedWindow.start && t <= selectedWindow.end
            : undefined;
        rows.push({
          kind: 'anomaly',
          ts: t,
          peerLabel: peerIp || 'Unknown',
          peerIp,
          protocol: a.protocol,
          severity: (a.severity as Severity) || 'INFO',
          direction: isSrc ? 'out' : 'in',
          inWindow,
        });
      }
    }

    // Baseline edges touching this node - shown at the bottom, undated
    if (graph) {
      for (const e of graph.edges) {
        if (!e.isBaseline) continue;
        if (e.source !== node.id && e.target !== node.id) continue;
        const peerId = e.source === node.id ? e.target : e.source;
        const peer = graph.nodes.find((n) => n.id === peerId);
        rows.push({
          kind: 'baseline',
          peerLabel: peer?.label || peerId,
          peerIp: peer?.ip,
          protocol: e.protocols[0],
          direction: 'peer',
        });
      }
    }

    // NEW flag: anomaly peers whose edge is marked isNewInWindow
    if (graph) {
      const newPeerIps = new Set<string>();
      for (const e of graph.edges) {
        if (!e.analytics?.isNewInWindow) continue;
        if (e.source !== node.id && e.target !== node.id) continue;
        const peerId = e.source === node.id ? e.target : e.source;
        const peer = graph.nodes.find((n) => n.id === peerId);
        if (peer?.ip) newPeerIps.add(peer.ip);
      }
      for (const r of rows) {
        if (r.kind === 'anomaly' && r.peerIp && newPeerIps.has(r.peerIp)) {
          r.isNew = true;
        }
      }
    }

    // Sort anomalies desc by ts, baseline rows after
    rows.sort((x, y) => {
      if (x.kind !== y.kind) return x.kind === 'anomaly' ? -1 : 1;
      return (y.ts ?? 0) - (x.ts ?? 0);
    });

    return rows.slice(0, 10);
  }, [node, anomalies, graph, selectedWindow]);

  if (!node) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4 text-sm text-gray-500">
        <div className="font-semibold text-gray-700 mb-1">Asset details</div>
        Click a node in the topology to inspect it. Nodes involved in anomalies are colored by severity.
      </div>
    );
  }

  const a = node.asset;
  const iconKey: AssetIconKey = node.isKnown
    ? detectAssetIconKey(a?.assetType, a?.assetCategory)
    : 'UNKNOWN';
  const ring = SEVERITY_COLOR[node.worstSeverity !== 'NONE' ? node.worstSeverity : node.criticality];
  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4 text-sm space-y-3">
      <div className="flex items-start gap-3">
        <img
          src={makeIconDataUri(iconKey)}
          alt={ICON_LABEL[iconKey]}
          className="w-12 h-12 rounded-full flex-shrink-0"
          style={{ boxShadow: `0 0 0 3px ${ring}` }}
        />
        <div className="flex-1 min-w-0">
          <div className="text-xs uppercase text-gray-500">
            {node.isKnown ? ICON_LABEL[iconKey] : 'External / Unknown'}
          </div>
          <div className="text-base font-semibold text-gray-900 truncate">{node.label}</div>
          {node.ip && <div className="text-xs text-gray-500">IP: {node.ip}</div>}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <Field label="Zone" value={ZONES[node.zone]?.label || node.zone} />
        <Field label="Purdue Level" value={PURDUE_LABELS[node.purdueLevel] || `L${node.purdueLevel}`} />
        <Field label="Criticality" value={node.criticality} />
        <Field label="Online" value={node.isOnline ? 'Yes' : 'No'} />
        <Field label="Anomalies" value={String(node.anomalyCount)} />
        {a?.assetType && <Field label="Type" value={a.assetType} />}
        {a?.manufacturer && <Field label="Vendor" value={a.manufacturer} />}
        {a?.model && <Field label="Model" value={a.model} />}
        {typeof a?.riskScore === 'number' && <Field label="Risk score" value={String(a.riskScore)} />}
        {typeof a?.vulnerabilityCount === 'number' && (
          <Field label="Vulnerabilities" value={String(a.vulnerabilityCount)} />
        )}
        {a?.location && <Field label="Location" value={a.location} />}
        {a?.department && <Field label="Department" value={a.department} />}
      </div>

      <NodeCommHistory rows={history} />
      {node.ip && <NodeDpiPanel ip={node.ip} />}
    </div>
  );
};

/**
 * Fetches real DPI events & function-code histogram for the selected node
 * from {@code /api/dpi/*}. Falls back silently when nothing has been
 * dissected yet (empty arrays). Surfaces the "rare command" signal by
 * highlighting function codes that represent less than 2% of the histogram.
 */
const NodeDpiPanel: React.FC<{ ip: string }> = ({ ip }) => {
  const [events, setEvents] = useState<DpiEvent[] | null>(null);
  const [stats, setStats] = useState<FunctionCodeStat[] | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([
      dpiService.recentForNode(ip, 10).catch(() => [] as DpiEvent[]),
      dpiService.nodeStats(ip).catch(() => [] as FunctionCodeStat[]),
    ])
      .then(([ev, st]) => {
        if (cancelled) return;
        setEvents(ev);
        setStats(st);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e?.message || 'Failed to load DPI data');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [ip]);

  const total = (stats || []).reduce((s, r) => s + (r.count || 0), 0);

  if (loading && !events) {
    return (
      <div className="pt-2 mt-2 border-t border-gray-100">
        <div className="text-[11px] uppercase tracking-wide text-gray-500 mb-1">DPI activity</div>
        <div className="text-xs text-gray-400">Loading…</div>
      </div>
    );
  }
  if (error) {
    return (
      <div className="pt-2 mt-2 border-t border-gray-100">
        <div className="text-[11px] uppercase tracking-wide text-gray-500 mb-1">DPI activity</div>
        <div className="text-xs text-gray-400">{error}</div>
      </div>
    );
  }
  if ((!events || events.length === 0) && (!stats || stats.length === 0)) {
    // Empty state is normal before any pcap with ICS traffic has been uploaded.
    return (
      <div className="pt-2 mt-2 border-t border-gray-100">
        <div className="text-[11px] uppercase tracking-wide text-gray-500 mb-1">DPI activity</div>
        <div className="text-xs text-gray-400 italic">
          No deep-packet events for this node yet. Upload a .pcap with Modbus/S7 traffic to populate.
        </div>
      </div>
    );
  }

  return (
    <div className="pt-2 mt-2 border-t border-gray-100 space-y-2">
      <div className="text-[11px] uppercase tracking-wide text-gray-500">DPI activity</div>

      {stats && stats.length > 0 && (
        <div>
          <div className="text-[10px] uppercase text-gray-400 mb-1">Function codes</div>
          <ul className="flex flex-wrap gap-1">
            {stats.slice(0, 8).map((s, idx) => {
              const pct = total > 0 ? (s.count / total) * 100 : 0;
              const isRare = total >= 20 && pct < 2;
              return (
                <li
                  key={`${s.protocol}-${s.functionCode}-${idx}`}
                  className={`text-[10px] rounded px-1.5 py-0.5 flex items-center gap-1 ${
                    isRare
                      ? 'bg-fuchsia-50 text-fuchsia-800 border border-fuchsia-200'
                      : 'bg-gray-100 text-gray-700'
                  }`}
                  title={`${s.protocol} ${s.functionCode} · ${s.count} PDU · ${pct.toFixed(1)}%`}
                >
                  <span className="font-mono">{s.functionCode}</span>
                  <span className="truncate max-w-[110px]">{s.functionName || ''}</span>
                  <span className="tabular-nums text-gray-500">×{s.count}</span>
                  {isRare && (
                    <span className="uppercase font-semibold text-fuchsia-700">rare</span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {events && events.length > 0 && (
        <div>
          <div className="text-[10px] uppercase text-gray-400 mb-1">
            Recent DPI events · last {events.length}
          </div>
          <ul className="space-y-1 max-h-44 overflow-y-auto pr-1">
            {events.map((e) => {
              const isOut = e.sourceIp === ip;
              const arrow = isOut ? '→' : '←';
              const peer = isOut ? e.destinationIp : e.sourceIp;
              const ts = e.eventTime ? formatRelativeTs(new Date(e.eventTime).getTime()) : '';
              const dot = e.isException ? '#DC2626' : e.isWrite ? '#D97706' : '#16A34A';
              return (
                <li key={e.id} className="flex items-center gap-2 text-xs">
                  <span
                    className="inline-block w-2 h-2 rounded-full flex-shrink-0"
                    style={{ background: dot }}
                  />
                  <span className="text-gray-500 w-12 flex-shrink-0 tabular-nums">{ts}</span>
                  <span className="text-gray-400">{arrow}</span>
                  <span className="flex-1 min-w-0 truncate text-gray-800" title={e.summary || ''}>
                    {e.functionName || e.functionCode || e.protocol}
                    {e.registerAddress ? ` @ ${e.registerAddress}` : ''}
                    {e.value ? ` = ${e.value}` : ''}
                  </span>
                  <span className="text-[10px] uppercase text-gray-500 px-1 rounded bg-gray-100">
                    {e.protocol}
                  </span>
                  <span className="text-[10px] text-gray-400 truncate max-w-[90px]">{peer}</span>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
};

/**
 * Last 10 communication events touching the selected node. Anomalies are
 * listed newest first with severity dot and direction arrow; baseline comms
 * are appended as gray pills.
 */
const NodeCommHistory: React.FC<{
  rows: Array<{
    kind: 'anomaly' | 'baseline';
    ts?: number;
    peerLabel: string;
    peerIp?: string;
    protocol?: string;
    severity?: Severity;
    direction: 'out' | 'in' | 'peer';
    inWindow?: boolean;
    isNew?: boolean;
  }>;
}> = ({ rows }) => {
  if (rows.length === 0) {
    return (
      <div className="pt-2 mt-2 border-t border-gray-100">
        <div className="text-[11px] uppercase tracking-wide text-gray-500 mb-1">Recent comms</div>
        <div className="text-xs text-gray-400">No events in the current dataset.</div>
      </div>
    );
  }

  return (
    <div className="pt-2 mt-2 border-t border-gray-100">
      <div className="text-[11px] uppercase tracking-wide text-gray-500 mb-1">
        Recent comms · last {rows.length}
      </div>
      <ul className="space-y-1 max-h-60 overflow-y-auto pr-1">
        {rows.map((r, idx) => {
          const isBaseline = r.kind === 'baseline';
          const dot = isBaseline ? '#9CA3AF' : SEVERITY_COLOR[r.severity || 'NONE'];
          const arrow = r.direction === 'out' ? '→' : r.direction === 'in' ? '←' : '↔';
          const time = r.ts ? formatRelativeTs(r.ts) : '';
          return (
            <li
              key={idx}
              className={`flex items-center gap-2 text-xs rounded px-1.5 py-1 ${
                r.isNew ? 'bg-fuchsia-50' : r.inWindow ? 'bg-amber-50' : isBaseline ? 'bg-gray-50' : ''
              }`}
            >
              <span
                className="inline-block w-2 h-2 rounded-full flex-shrink-0"
                style={{ background: dot }}
              />
              <span className="text-gray-500 w-12 flex-shrink-0 tabular-nums">{time}</span>
              <span className="text-gray-400">{arrow}</span>
              <span className="flex-1 min-w-0 truncate text-gray-800">{r.peerLabel}</span>
              {r.protocol && (
                <span className="text-[10px] uppercase text-gray-500 px-1 rounded bg-gray-100">
                  {r.protocol}
                </span>
              )}
              {r.isNew && (
                <span className="text-[10px] font-semibold text-fuchsia-700 uppercase">new</span>
              )}
              {isBaseline && !r.isNew && (
                <span className="text-[10px] text-gray-400 italic">baseline</span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
};

/** "5m ago", "2h ago", etc. for the comm-history timestamps. */
const formatRelativeTs = (ms: number): string => {
  const diff = Date.now() - ms;
  if (diff < 0) return 'soon';
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h`;
  const d = Math.floor(hr / 24);
  return `${d}d`;
};

const Field: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div>
    <div className="text-[10px] uppercase text-gray-400">{label}</div>
    <div className="text-gray-800">{value}</div>
  </div>
);

const ZoneLegendOverlay: React.FC = () => (
  <div className="absolute top-3 right-3 z-20 bg-white/95 rounded-md shadow border border-gray-200 p-2 text-xs space-y-1">
    <div className="font-semibold text-gray-700">IEC 62443 Zones</div>
    {ZONE_ORDER.map((zid) => {
      const z = ZONES[zid];
      return (
        <div key={zid} className="flex items-center gap-2">
          <span
            className="inline-block w-3 h-3 rounded"
            style={{ background: z.background, border: `1.5px dashed ${z.accent}` }}
          />
          <span className="text-gray-700">{z.label}</span>
        </div>
      );
    })}
    <div className="pt-1 mt-1 border-t border-gray-100 text-[10px] text-gray-500 italic">
      Cross-zone edges are "conduits"
    </div>
  </div>
);

// --- vis-network adapters ---------------------------------------------------

const rank = (s: Severity) =>
  ({ NONE: 0, INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 } as Record<Severity, number>)[s];

const buildVisNode = (n: TopologyNode, mode: ViewMode) => {
  const tone = n.worstSeverity !== 'NONE' ? n.worstSeverity : n.criticality;
  const ringColor = SEVERITY_COLOR[tone];

  // Pick an icon from the asset type; fall back to UNKNOWN for external IPs.
  const iconKey: AssetIconKey = n.isKnown
    ? detectAssetIconKey(n.asset?.assetType, n.asset?.assetCategory)
    : 'UNKNOWN';
  const background = n.isOnline ? '#FFFFFF' : '#F3F4F6';
  const imageUri = makeIconDataUri(iconKey, { background });

  return {
    id: n.id,
    label: n.label,
    // Only emit `level` in Purdue mode - hierarchical layout uses it; in
    // zones mode physics is running and `level` would just pin nodes.
    //
    // vis-network hierarchical + direction:'DU' convention: rows are ordered
    // by `level` *ascending from bottom to top* - level 0 sits at the bottom
    // and higher level values climb upward. We want L0 (field devices like the
    // cooling pump) on the bottom and L5 (DMZ/external) on top, so we map
    // Purdue level directly to vis-network level without inverting it.
    // (An earlier version used `5 - n.purdueLevel` which inverted everything
    //  - that made the Cooling Pump drift up near L4/L5, nowhere near the
    //  plant floor where it belongs.)
    //
    // `fixed.y` pins the vertical position once the hierarchical layout has
    // placed the node, so zoom/drag events can't drift it into a neighbour
    // band. X stays free so the user can still reposition horizontally when
    // inspecting the graph.
    ...(mode === 'purdue' ? { level: n.purdueLevel, fixed: { x: false, y: true } } : {}),
    // Pass a zone hint through so the zones-view drawer can group by it.
    group: n.zone,
    shape: 'circularImage',
    image: imageUri,
    brokenImage: makeIconDataUri('DEFAULT', { background }),
    color: {
      background,
      border: ringColor,
      highlight: { background: '#FFFFFF', border: '#111827' },
    },
    // vis-network reads `shapeProperties.borderDashes` unconditionally later
    // on, so these keys must always exist. `useBorderWithImage` makes the
    // severity-colored ring visible on circularImage nodes.
    shapeProperties: {
      borderDashes: n.isKnown ? false : [5, 5],
      useBorderWithImage: true,
    },
    title: buildNodeTooltip(n),
    borderWidth: n.worstSeverity === 'CRITICAL' ? 4 : 2.5,
    size: n.worstSeverity === 'CRITICAL' ? 28 : 24,
  };
};

const buildVisEdge = (e: TopologyEdge, mode: ViewMode) => {
  const isConduit = Boolean(e.isConduit);
  const isNew = Boolean(e.analytics?.isNewInWindow);
  const color = isNew
    ? '#C026D3' // fuchsia - never-seen-before communication in baseline
    : e.isBaseline ? '#9CA3AF'
    : SEVERITY_COLOR[e.severity];

  // Thickness: severity sets the floor; windowCount bumps it further so busy
  // edges read as "heavy traffic" while rare probes stay thin.
  const severityWeight =
    e.severity === 'CRITICAL' ? 3
    : e.severity === 'HIGH' ? 2.2
    : e.isBaseline ? 1
    : 1.4;
  const activityBonus = Math.min(2.5, Math.log2(1 + (e.analytics?.windowCount ?? 0)) * 0.8);
  let width = severityWeight + activityBonus;
  if (mode === 'zones' && isConduit) width += 0.8;
  if (isNew) width += 0.6;

  // --- Label --------------------------------------------------------------
  // In zones mode we show the protocol on every cross-zone edge. For NEW
  // edges we always show a "NEW" prefix so the viewer can immediately see
  // which comms are unprecedented.
  const protoLabel = e.protocols[0];
  const showProto = mode === 'zones' && isConduit && !!protoLabel;
  let label: string | undefined;
  if (isNew) {
    label = protoLabel ? `⚑ NEW · ${protoLabel}` : '⚑ NEW';
  } else if (showProto) {
    label = e.count > 1 ? `${protoLabel} ×${e.count}` : protoLabel;
  } else if (e.count > 1) {
    label = `×${e.count}`;
  }

  return {
    id: e.id,
    from: e.source,
    to: e.target,
    color: { color, highlight: '#111827' },
    width,
    dashes: e.isBaseline ? [4, 4] : (e.severity === 'INFO' ? [2, 2] : false),
    label,
    font: isNew
      ? { size: 11, color: '#86198F', background: '#FDF4FF', strokeWidth: 0, align: 'middle', bold: true }
      : showProto
        ? { size: 10, color: '#7F1D1D', background: 'rgba(255,255,255,0.85)', strokeWidth: 0, align: 'middle' }
        : { size: 10, align: 'middle' },
    title: buildEdgeTooltip(e),
  };
};

const buildEdgeTooltip = (e: TopologyEdge): string => {
  const a = e.analytics;
  const isNew = Boolean(a?.isNewInWindow);
  const baseColor = isNew
    ? '#C026D3'
    : e.isBaseline
      ? '#9CA3AF'
      : SEVERITY_COLOR[e.severity];

  const header = isNew
    ? `<b style="color:#86198F">⚑ NEW COMMUNICATION</b>`
    : e.isBaseline
      ? '<b style="color:#4B5563">Baseline traffic</b>'
      : `<b style="color:${baseColor}">${e.severity}</b>`;

  const lines: string[] = [header];
  if (e.protocols.length) lines.push(`Protocol: ${escapeHtml(e.protocols.join(', '))}`);
  if (e.isConduit) lines.push('<span style="color:#B45309">Cross-zone conduit</span>');
  if (e.count > 0) lines.push(`Anomaly records: ${e.count}`);

  // Baseline / window split
  if (a && (a.baselineCount + a.windowCount + a.totalCount) > 0) {
    lines.push(
      `<span style="color:#6B7280;font-size:10px">` +
        `baseline ${a.baselineCount} · window ${a.windowCount} · total ${a.totalCount}` +
      `</span>`
    );
  }

  // SVG mini-sparkline
  const sparkSvg = buildSparklineSvg(a, baseColor, isNew);
  if (sparkSvg) lines.push(sparkSvg);

  // Suspicious-traffic hint - flags NEW, HIGH/CRITICAL, or cross-zone edges.
  // The truly "rare function code" verdict comes from the DPI modal, which
  // has access to the backend histogram; here we only nudge the user to
  // open it.
  const suspicious =
    isNew || e.severity === 'CRITICAL' || e.severity === 'HIGH' || Boolean(e.isConduit);
  if (suspicious) {
    lines.push(
      `<span style="color:#86198F;font-size:10px;font-weight:600;text-transform:uppercase">⚠ Examine DPI</span>`
    );
  }
  lines.push(
    `<span style="color:#9CA3AF;font-size:10px">Double-click edge for DPI detail</span>`
  );

  return lines.join('<br/>');
};

/**
 * Build an inline SVG sparkline for the edge tooltip. Bars are colored by
 * whether their bucket falls in the baseline period, the selected window,
 * or outside both.
 */
const buildSparklineSvg = (
  a: EdgeAnalytics | undefined,
  accentColor: string,
  isNew: boolean,
): string => {
  if (!a || !a.sparkline || a.sparkline.length === 0) return '';
  const buckets = a.sparkline;
  const n = buckets.length;

  const WIDTH = 168;
  const HEIGHT = 36;
  const PAD_X = 2;
  const PAD_TOP = 4;
  const PAD_BOTTOM = 8;
  const barAreaW = WIDTH - PAD_X * 2;
  const barAreaH = HEIGHT - PAD_TOP - PAD_BOTTOM;
  const barW = Math.max(1, barAreaW / n - 1);

  const max = Math.max(1, ...buckets);

  const [bStart, bEnd] = a.baselineBucketRange ?? [0, 0];
  const [wStart, wEnd] = a.windowBucketRange ?? [0, 0];

  const BASELINE_COLOR = '#CBD5E1'; // slate-300
  const WINDOW_COLOR = isNew ? '#C026D3' : accentColor;
  const NEUTRAL_COLOR = '#E5E7EB';  // gray-200

  const bars: string[] = [];
  for (let i = 0; i < n; i++) {
    const v = buckets[i];
    const h = v === 0 ? 1.5 : Math.max(2, (v / max) * barAreaH);
    const x = PAD_X + i * (barW + 1);
    const y = PAD_TOP + (barAreaH - h);
    let color = NEUTRAL_COLOR;
    if (i >= wStart && i < wEnd) color = WINDOW_COLOR;
    else if (i >= bStart && i < bEnd) color = BASELINE_COLOR;
    const opacity = v === 0 ? 0.45 : 1;
    bars.push(
      `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${h.toFixed(1)}" fill="${color}" opacity="${opacity}" rx="0.5"/>`
    );
  }

  // Baseline-end divider line
  const baselineEndX = PAD_X + bEnd * (barW + 1);
  const divider =
    bEnd > 0 && bEnd < n
      ? `<line x1="${baselineEndX.toFixed(1)}" y1="${PAD_TOP - 1}" x2="${baselineEndX.toFixed(1)}" y2="${HEIGHT - PAD_BOTTOM + 1}" stroke="#0F766E" stroke-width="1" stroke-dasharray="2,2"/>`
      : '';

  // Tiny legend row under the bars
  const legendY = HEIGHT - 1;
  const legend = [
    `<text x="${PAD_X}" y="${legendY}" font-size="8" fill="#64748B" font-family="Inter,system-ui,sans-serif">baseline</text>`,
    `<text x="${(WIDTH - PAD_X).toFixed(1)}" y="${legendY}" font-size="8" fill="#64748B" font-family="Inter,system-ui,sans-serif" text-anchor="end">now</text>`,
  ].join('');

  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${WIDTH}" height="${HEIGHT}" ` +
    `viewBox="0 0 ${WIDTH} ${HEIGHT}" style="display:block;margin-top:4px">` +
    `<rect x="0" y="0" width="${WIDTH}" height="${HEIGHT - PAD_BOTTOM + 2}" fill="#F8FAFC" rx="3"/>` +
    bars.join('') +
    divider +
    legend +
    `</svg>`
  );
};

/**
 * Paint IEC 62443 zone rectangles on the vis-network canvas, under the
 * edges/nodes. Each zone's bounding box is computed from the current
 * positions of its member nodes.
 */
const drawZoneBackdrops = (
  ctx: CanvasRenderingContext2D,
  network: Network,
  nodes: TopologyNode[],
) => {
  // Group node ids by zone
  const byZone: Record<string, string[]> = {};
  for (const n of nodes) {
    (byZone[n.zone] ||= []).push(n.id);
  }

  const PAD = 42;
  const RADIUS = 22;

  // Render in ZONE_ORDER so the legend order matches z-order (External painted first)
  for (const zoneId of ZONE_ORDER) {
    const ids = byZone[zoneId];
    if (!ids || ids.length === 0) continue;
    const zone = ZONES[zoneId];
    // getPositions returns { id: {x,y} } in graph coordinates
    const positions = network.getPositions(ids);
    const xs: number[] = [];
    const ys: number[] = [];
    for (const id of ids) {
      const p = positions[id];
      if (p && typeof p.x === 'number') { xs.push(p.x); ys.push(p.y); }
    }
    if (xs.length === 0) continue;

    const minX = Math.min(...xs) - PAD;
    const maxX = Math.max(...xs) + PAD;
    const minY = Math.min(...ys) - PAD;
    const maxY = Math.max(...ys) + PAD;
    const w = maxX - minX;
    const h = maxY - minY;

    // Rounded rect
    ctx.save();
    ctx.beginPath();
    const r = Math.min(RADIUS, w / 2, h / 2);
    ctx.moveTo(minX + r, minY);
    ctx.lineTo(maxX - r, minY);
    ctx.quadraticCurveTo(maxX, minY, maxX, minY + r);
    ctx.lineTo(maxX, maxY - r);
    ctx.quadraticCurveTo(maxX, maxY, maxX - r, maxY);
    ctx.lineTo(minX + r, maxY);
    ctx.quadraticCurveTo(minX, maxY, minX, maxY - r);
    ctx.lineTo(minX, minY + r);
    ctx.quadraticCurveTo(minX, minY, minX + r, minY);
    ctx.closePath();
    ctx.fillStyle = zone.background;
    ctx.fill();
    ctx.lineWidth = 1.5;
    ctx.setLineDash([6, 4]);
    ctx.strokeStyle = zone.accent;
    ctx.stroke();
    ctx.setLineDash([]);

    // Zone label badge (top-left corner, inside the rect)
    const labelText = zone.label.toUpperCase();
    ctx.font = 'bold 11px Inter, system-ui, sans-serif';
    const textW = ctx.measureText(labelText).width;
    const badgeX = minX + 10;
    const badgeY = minY + 8;
    const badgeW = textW + 14;
    const badgeH = 18;
    ctx.fillStyle = zone.accent;
    ctx.beginPath();
    ctx.moveTo(badgeX + 4, badgeY);
    ctx.lineTo(badgeX + badgeW - 4, badgeY);
    ctx.quadraticCurveTo(badgeX + badgeW, badgeY, badgeX + badgeW, badgeY + 4);
    ctx.lineTo(badgeX + badgeW, badgeY + badgeH - 4);
    ctx.quadraticCurveTo(badgeX + badgeW, badgeY + badgeH, badgeX + badgeW - 4, badgeY + badgeH);
    ctx.lineTo(badgeX + 4, badgeY + badgeH);
    ctx.quadraticCurveTo(badgeX, badgeY + badgeH, badgeX, badgeY + badgeH - 4);
    ctx.lineTo(badgeX, badgeY + 4);
    ctx.quadraticCurveTo(badgeX, badgeY, badgeX + 4, badgeY);
    ctx.closePath();
    ctx.fill();
    ctx.fillStyle = '#FFFFFF';
    ctx.textBaseline = 'middle';
    ctx.fillText(labelText, badgeX + 7, badgeY + badgeH / 2 + 0.5);
    ctx.restore();
  }
};

/**
 * Trace a rounded rectangle path on the given context. Per-corner toggles let
 * the caller round only specific corners (e.g. for "split" badges where two
 * shapes butt up against each other).
 */
const roundRect = (
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  w: number,
  h: number,
  r: number,
  corners: { tl?: boolean; tr?: boolean; br?: boolean; bl?: boolean } = {
    tl: true, tr: true, br: true, bl: true,
  },
) => {
  const rTL = corners.tl ? r : 0;
  const rTR = corners.tr ? r : 0;
  const rBR = corners.br ? r : 0;
  const rBL = corners.bl ? r : 0;
  ctx.beginPath();
  ctx.moveTo(x + rTL, y);
  ctx.lineTo(x + w - rTR, y);
  if (rTR) ctx.quadraticCurveTo(x + w, y, x + w, y + rTR);
  ctx.lineTo(x + w, y + h - rBR);
  if (rBR) ctx.quadraticCurveTo(x + w, y + h, x + w - rBR, y + h);
  ctx.lineTo(x + rBL, y + h);
  if (rBL) ctx.quadraticCurveTo(x, y + h, x, y + h - rBL);
  ctx.lineTo(x, y + rTL);
  if (rTL) ctx.quadraticCurveTo(x, y, x + rTL, y);
  ctx.closePath();
};

/**
 * Paint Purdue level bands on the vis-network canvas, under the edges/nodes.
 * Each band's vertical extent is derived from the current Y positions of the
 * nodes assigned to that level. Because the bands share the canvas transform
 * with the nodes, zoom and pan can no longer misalign them.
 *
 * The band spans the full visible width (extended well beyond the node bbox
 * on both sides) so it reads as a continuous horizontal stripe even when the
 * user pans sideways.
 */
const drawPurdueBands = (
  ctx: CanvasRenderingContext2D,
  network: Network,
  nodes: TopologyNode[],
) => {
  // Group node ids by Purdue level.
  const byLevel: Record<number, string[]> = {};
  for (const n of nodes) {
    (byLevel[n.purdueLevel] ||= []).push(n.id);
  }
  const levels = Object.keys(byLevel).map(Number).sort((a, b) => a - b);
  if (levels.length === 0) return;

  // Gather every node position once so we can compute a generous horizontal
  // span (min/max X across the whole graph) to paint bands onto.
  const allIds = nodes.map((n) => n.id);
  const allPos = network.getPositions(allIds);
  let gMinX = Infinity;
  let gMaxX = -Infinity;
  for (const id of allIds) {
    const p = allPos[id];
    if (p && typeof p.x === 'number') {
      if (p.x < gMinX) gMinX = p.x;
      if (p.x > gMaxX) gMaxX = p.x;
    }
  }
  if (!Number.isFinite(gMinX)) return;
  const SIDE_PAD = 2000; // extend well off-canvas - panning won't reveal a seam
  const bandLeft = gMinX - SIDE_PAD;
  const bandRight = gMaxX + SIDE_PAD;

  // Compute each level's vertical center from its member nodes. Hierarchical
  // layout puts every node on a level at the same Y, so averaging is safe and
  // robust to edge cases (e.g. a level with a single node).
  const centers: { level: number; y: number }[] = [];
  for (const lvl of levels) {
    const ids = byLevel[lvl];
    const ys: number[] = [];
    for (const id of ids) {
      const p = allPos[id];
      if (p && typeof p.y === 'number') ys.push(p.y);
    }
    if (ys.length === 0) continue;
    const avg = ys.reduce((a, b) => a + b, 0) / ys.length;
    centers.push({ level: lvl, y: avg });
  }
  if (centers.length === 0) return;

  // Band vertical extent is halfway to the neighbouring level; the outermost
  // bands extend by the same step so the top/bottom aren't cropped.
  const DEFAULT_STEP = 120; // matches levelSeparation in the layout options
  const steps: number[] = centers.map((c, i) => {
    const prev = centers[i - 1];
    const next = centers[i + 1];
    const dPrev = prev ? Math.abs(c.y - prev.y) : DEFAULT_STEP;
    const dNext = next ? Math.abs(next.y - c.y) : DEFAULT_STEP;
    return Math.max(dPrev, dNext);
  });

  for (let i = 0; i < centers.length; i++) {
    const { level, y } = centers[i];
    const step = steps[i];
    const half = step / 2;
    const top = y - half;
    const bottom = y + half;
    const h = bottom - top;

    // Fill
    ctx.save();
    ctx.fillStyle = BAND_BG[level] || 'rgba(148, 163, 184, 0.05)';
    ctx.fillRect(bandLeft, top, bandRight - bandLeft, h);

    // Top and bottom dashed dividers, dimmed.
    const accent = BAND_ACCENT[level] || '#94A3B8';
    ctx.strokeStyle = accent;
    ctx.globalAlpha = 0.35;
    ctx.lineWidth = 1;
    ctx.setLineDash([6, 4]);
    ctx.beginPath();
    ctx.moveTo(bandLeft, top);
    ctx.lineTo(bandRight, top);
    ctx.moveTo(bandLeft, bottom);
    ctx.lineTo(bandRight, bottom);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.globalAlpha = 1;

    // -- Pill badge label ---------------------------------------------------
    // Painted onto the canvas so it zooms/pans with the band. Two-part design:
    //   [ L1 ]  Basic Control
    //    ^^      ^^^^^^^^^^^^^
    //    accent  white-on-slate pill body
    // Gives strong visual hierarchy (the level number reads instantly) and a
    // consistent visual language with the zone badges.
    const levelTag = `L${level}`;
    const nameText = (PURDUE_SHORT[level] || '').trim();

    ctx.font = 'bold 12px Inter, system-ui, sans-serif';
    const tagW = ctx.measureText(levelTag).width;
    ctx.font = '600 11px Inter, system-ui, sans-serif';
    const nameW = nameText ? ctx.measureText(nameText).width : 0;

    const padX = 9;
    const tagSegW = tagW + padX * 2;       // accent square hugging "L1"
    const nameSegW = nameText ? nameW + padX * 2 : 0;
    const badgeH = 22;
    const radius = 6;
    const totalW = tagSegW + nameSegW;
    // Anchor the badge so its right edge sits a comfortable gap to the left of
    // the leftmost node. Falls back gracefully on narrow viewports.
    const badgeRight = gMinX - 32;
    const badgeX = badgeRight - totalW;
    const badgeY = y - badgeH / 2;

    // Subtle drop shadow for separation from the band fill.
    ctx.save();
    ctx.shadowColor = 'rgba(15, 23, 42, 0.18)';
    ctx.shadowBlur = 6;
    ctx.shadowOffsetY = 1;

    // Body (right segment): dark slate pill, full rounded rect - drawn first
    // so the accent tag overlaps cleanly on the left.
    ctx.fillStyle = '#0F172A';
    roundRect(ctx, badgeX, badgeY, totalW, badgeH, radius);
    ctx.fill();
    ctx.shadowColor = 'transparent';
    ctx.shadowBlur = 0;
    ctx.shadowOffsetY = 0;

    // Accent tag (left segment): solid colored block, only the left corners
    // rounded so it butts against the body cleanly.
    ctx.fillStyle = accent;
    roundRect(ctx, badgeX, badgeY, tagSegW, badgeH, radius, {
      tl: true, bl: true, tr: false, br: false,
    });
    ctx.fill();

    // Hairline accent on the right edge of the body for a polished finish.
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(badgeX + tagSegW, badgeY + 3);
    ctx.lineTo(badgeX + tagSegW, badgeY + badgeH - 3);
    ctx.stroke();

    // Tag text (white on accent)
    ctx.fillStyle = '#FFFFFF';
    ctx.font = 'bold 12px Inter, system-ui, sans-serif';
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'center';
    ctx.fillText(levelTag, badgeX + tagSegW / 2, badgeY + badgeH / 2 + 0.5);

    // Name text (light slate on dark body)
    if (nameText) {
      ctx.fillStyle = '#E2E8F0';
      ctx.font = '600 11px Inter, system-ui, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(
        nameText,
        badgeX + tagSegW + nameSegW / 2,
        badgeY + badgeH / 2 + 0.5,
      );
    }
    ctx.restore();

    ctx.restore();
  }
};

const buildNodeTooltip = (n: TopologyNode): string => {
  const lines = [
    `<b>${escapeHtml(n.label)}</b>`,
    n.ip ? `IP: ${escapeHtml(n.ip)}` : '',
    `Zone: ${escapeHtml(ZONES[n.zone]?.label || n.zone)}`,
    `Purdue: ${PURDUE_LABELS[n.purdueLevel] || `L${n.purdueLevel}`}`,
    `Criticality: ${n.criticality}`,
    `Anomalies: ${n.anomalyCount}`,
    n.isKnown ? '' : 'External / Unknown IP',
  ].filter(Boolean);
  return lines.join('<br/>');
};

const escapeHtml = (s: string) =>
  s.replace(/[&<>"]/g, (c) =>
    c === '&' ? '&amp;' :
    c === '<' ? '&lt;' :
    c === '>' ? '&gt;' : '&quot;'
  );

export default NetworkTopology;
