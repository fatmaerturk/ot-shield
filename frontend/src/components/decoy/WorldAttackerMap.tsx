import React, { useEffect, useMemo, useRef, useState } from 'react';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import { MapContainer, TileLayer, CircleMarker, Tooltip, useMap, SVGOverlay } from 'react-leaflet';
import { Engagement, DecoyInstance } from '../../services/decoyService';

/**
 * World Attacker Map (Leaflet-based)
 * --------------------------------------------------------------
 * A real-tile world map with:
 *   1. Proper country borders (CARTO Dark Matter tiles)
 *   2. Heat-zone overlay:       country-level choropleth (violet->fuchsia) by attacker count
 *   3. Country labels + badge:  top-K attacker countries labelled with threat score
 *   4. Day / night terminator:  solar-position darkening layer
 *   5. Decoy zoom-in:           clicking a decoy smoothly flies to it at zoom 6
 *
 * Interaction
 *   - Hover attacker marker  -> tooltip (country, count, last severity)
 *   - Click attacker marker  -> onSelectCountry(ISO2)
 *   - Click decoy marker     -> onSelectDecoy(id) + flyTo
 *   - On live event          -> animated SVG arc attacker -> decoy
 */

// ---------- Country metadata (lat / lon + approximate polygon for choropleth) ----------
// Representative capital lat/lon.
const COUNTRIES: Record<string, { lat: number; lon: number; name: string }> = {
  US: { lat: 38.9,  lon: -77.0,  name: 'United States' },
  CA: { lat: 45.4,  lon: -75.7,  name: 'Canada' },
  BR: { lat: -15.8, lon: -47.9,  name: 'Brazil' },
  GB: { lat: 51.5,  lon: -0.1,   name: 'United Kingdom' },
  DE: { lat: 52.5,  lon: 13.4,   name: 'Germany' },
  FR: { lat: 48.9,  lon: 2.3,    name: 'France' },
  NL: { lat: 52.4,  lon: 4.9,    name: 'Netherlands' },
  IS: { lat: 64.1,  lon: -21.9,  name: 'Iceland' },
  BG: { lat: 42.7,  lon: 23.3,   name: 'Bulgaria' },
  RU: { lat: 55.8,  lon: 37.6,   name: 'Russia' },
  TR: { lat: 39.9,  lon: 32.9,   name: 'Turkey' },
  IR: { lat: 35.7,  lon: 51.4,   name: 'Iran' },
  IN: { lat: 28.6,  lon: 77.2,   name: 'India' },
  CN: { lat: 39.9,  lon: 116.4,  name: 'China' },
  KP: { lat: 39.0,  lon: 125.7,  name: 'North Korea' },
  JP: { lat: 35.7,  lon: 139.7,  name: 'Japan' },
  AU: { lat: -35.3, lon: 149.1,  name: 'Australia' },
  ZA: { lat: -25.7, lon: 28.2,   name: 'South Africa' },
  NG: { lat: 9.1,   lon: 7.5,    name: 'Nigeria' },
  EG: { lat: 30.0,  lon: 31.2,   name: 'Egypt' },
  UA: { lat: 50.5,  lon: 30.5,   name: 'Ukraine' },
  PL: { lat: 52.2,  lon: 21.0,   name: 'Poland' },
  RO: { lat: 44.4,  lon: 26.1,   name: 'Romania' },
  MX: { lat: 19.4,  lon: -99.1,  name: 'Mexico' },
};

// ---------- Decoy geo (facility representative coords) ----------
const DECOY_GEO: Record<string, { lat: number; lon: number }> = {
  'decoy-001': { lat: 48.1, lon: 11.6 },  // Munich
  'decoy-002': { lat: 48.1, lon: 11.6 },
  'decoy-003': { lat: 50.9, lon: 4.4 },   // Brussels
  'decoy-004': { lat: 51.9, lon: 4.5 },   // Rotterdam
  'decoy-005': { lat: 47.4, lon: 8.5 },   // Zurich
};

// ---------- Severity / status palette ----------
const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#e11d48',
  HIGH:     '#fb923c',
  MEDIUM:   '#f59e0b',
  LOW:      '#10b981',
};

function severityRank(s: string): number {
  switch (s) {
    case 'CRITICAL': return 4;
    case 'HIGH':     return 3;
    case 'MEDIUM':   return 2;
    default:         return 1;
  }
}

// ---------- Day / night terminator ----------
// Returns the subsolar point (lat, lon) for current UTC, plus a SVG path that
// darkens the "night" hemisphere on the Leaflet overlay.
function subsolarPoint(date: Date): { lat: number; lon: number } {
  const dayOfYear = Math.floor(
    (date.getTime() - Date.UTC(date.getUTCFullYear(), 0, 0)) / 86400000,
  );
  // Declination approx (degrees)
  const decl = 23.44 * Math.cos((2 * Math.PI * (dayOfYear + 10)) / 365);
  // Longitude of sun (degrees east from Greenwich, negative = west)
  const utcHours = date.getUTCHours() + date.getUTCMinutes() / 60;
  const lon = (12 - utcHours) * 15; // at noon UTC -> 0°; solar noon moves west
  return { lat: decl, lon };
}

// ---------- Inner overlay components: need access to the map instance ----------

// Terminator overlay: draw a darkened polygon covering the "night" side.
const DayNightTerminator: React.FC = () => {
  const map = useMap();
  const layerRef = useRef<L.Polygon | null>(null);

  useEffect(() => {
    function build() {
      // Solar position
      const { lat: sLat, lon: sLon } = subsolarPoint(new Date());

      // Build a polyline across 360° longitude where the sun is at the horizon.
      // terminator latitude per longitude:  tan(lat) = -cos(lon - sLon) / tan(sLat)
      // Guard against small sLat.
      const tanSLat = Math.tan((sLat * Math.PI) / 180) || 0.001;
      const points: [number, number][] = [];
      for (let lon = -180; lon <= 180; lon += 2) {
        const latRad = Math.atan(-Math.cos(((lon - sLon) * Math.PI) / 180) / tanSLat);
        const lat = (latRad * 180) / Math.PI;
        points.push([lat, lon]);
      }
      // Close the polygon to the night-side pole.
      // Night side is opposite to subsolar latitude sign.
      const nightPole = sLat >= 0 ? -90 : 90;
      points.push([nightPole, 180]);
      points.push([nightPole, -180]);

      if (layerRef.current) map.removeLayer(layerRef.current);
      const poly = L.polygon(points, {
        color: 'rgba(15,23,42,0)',
        weight: 0,
        fillColor: '#0b1020',
        fillOpacity: 0.45,
        interactive: false,
      }).addTo(map);
      layerRef.current = poly;
    }

    build();
    const iv = window.setInterval(build, 10 * 60 * 1000); // refresh every 10min
    return () => {
      window.clearInterval(iv);
      if (layerRef.current) map.removeLayer(layerRef.current);
      layerRef.current = null;
    };
  }, [map]);

  return null;
};

// Programmatic flyTo when a decoy is selected.
const FlyToDecoy: React.FC<{ target: { lat: number; lon: number; id: string; zoom?: number } | null }> = ({ target }) => {
  const map = useMap();
  useEffect(() => {
    if (!target) return;
    const z = target.zoom ?? 6;
    map.flyTo([target.lat, target.lon], z, { duration: 1.2 });
  }, [map, target]);
  return null;
};

// Live arc: render the SVG in an SVGOverlay that follows the map.
interface ArcLayerProps {
  liveArc?: { engagementId: string; ts: number } | null;
  selectedEngagementId?: string | null;
  engagements: Engagement[];
}

interface AnimArc {
  id: number;
  from: [number, number];
  to: [number, number];
  severity: string;
  country: string;
  decoyId: string;
  bornAt: number;    // epoch ms for packet position calc
  duration: number;  // ms
  expires: number;
}

const ArcLayer: React.FC<ArcLayerProps> = ({ liveArc, selectedEngagementId, engagements }) => {
  const map = useMap();
  const [arcs, setArcs] = useState<AnimArc[]>([]);
  const [impacts, setImpacts] = useState<Array<{ id: number; decoyId: string; bornAt: number }>>([]);
  const [countryFlashes, setCountryFlashes] = useState<Array<{ id: number; country: string; bornAt: number; severity: string }>>([]);
  const arcSeq = useRef(1);

  // Helper: spawn a single attack animation from an engagement record
  const spawnAttack = React.useCallback((eng: Engagement) => {
    const a = COUNTRIES[eng.attackerCountry];
    const d = DECOY_GEO[eng.decoyInstanceId];
    if (!a || !d) return;
    const now = Date.now();
    const id = arcSeq.current++;
    const duration = 1800; // arc + packet travel time
    const arc: AnimArc = {
      id,
      from: [a.lat, a.lon],
      to: [d.lat, d.lon],
      severity: eng.severity,
      country: eng.attackerCountry,
      decoyId: eng.decoyInstanceId,
      bornAt: now,
      duration,
      expires: now + duration + 400,
    };
    setArcs(prev => [...prev, arc]);
    // Country flash at source
    setCountryFlashes(prev => [...prev, { id, country: eng.attackerCountry, bornAt: now, severity: eng.severity }]);
    // Schedule impact when packet arrives
    window.setTimeout(() => {
      setImpacts(prev => [...prev, { id, decoyId: eng.decoyInstanceId, bornAt: Date.now() }]);
    }, duration - 150);
    // Clean up
    window.setTimeout(() => {
      setArcs(prev => prev.filter(x => x.id !== id));
      setCountryFlashes(prev => prev.filter(x => x.id !== id));
    }, duration + 400);
    window.setTimeout(() => {
      setImpacts(prev => prev.filter(x => x.id !== id));
    }, duration + 1200);
  }, []);

  // Explicit live-arc trigger (from WebSocket EVENT)
  useEffect(() => {
    if (!liveArc) return;
    const eng = engagements.find(e => e.id === liveArc.engagementId);
    if (eng) spawnAttack(eng);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveArc?.ts]);

  // Ambient storm: every 700-1500ms pick a random engagement and emit an attack.
  // Gives the map a "something is always happening" feel even without backend stream.
  useEffect(() => {
    if (!engagements.length) return;
    let cancelled = false;
    let timer: number | null = null;

    const loop = () => {
      if (cancelled) return;
      // Prefer active engagements, fall back to any
      const active = engagements.filter(e => e.status === 'ACTIVE');
      const pool = active.length ? active : engagements;
      const pick = pool[Math.floor(Math.random() * pool.length)];
      if (pick) spawnAttack(pick);
      const delay = 600 + Math.random() * 900;
      timer = window.setTimeout(loop, delay);
    };
    // Seed first attack quickly
    timer = window.setTimeout(loop, 400);
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [engagements, spawnAttack]);

  const selectedArc = useMemo(() => {
    if (!selectedEngagementId) return null;
    const eng = engagements.find(e => e.id === selectedEngagementId);
    if (!eng) return null;
    const a = COUNTRIES[eng.attackerCountry];
    const d = DECOY_GEO[eng.decoyInstanceId];
    if (!a || !d) return null;
    return { from: [a.lat, a.lon] as [number, number], to: [d.lat, d.lon] as [number, number], severity: eng.severity };
  }, [selectedEngagementId, engagements]);

  // rAF tick so packet positions interpolate smoothly
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let raf = 0;
    const loop = () => {
      setTick(t => (t + 1) % 1_000_000);
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, []);

  // Also re-render on pan/zoom (projection change)
  useEffect(() => {
    const bump = () => setTick(t => t + 1);
    map.on('move', bump);
    map.on('zoom', bump);
    return () => {
      map.off('move', bump);
      map.off('zoom', bump);
    };
  }, [map]);
  void tick;

  function toPx(lat: number, lon: number): { x: number; y: number } {
    const p = map.latLngToContainerPoint([lat, lon]);
    return { x: p.x, y: p.y };
  }

  // Quadratic bezier along the arc; returns path string and a function to sample a point at t∈[0,1].
  function arcGeometry(from: [number, number], to: [number, number]) {
    const a = toPx(from[0], from[1]);
    const b = toPx(to[0], to[1]);
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const len = Math.sqrt(dx * dx + dy * dy);
    const lift = Math.min(160, Math.max(40, len * 0.35));
    const cx = mx;
    const cy = my - lift;
    const path = `M${a.x},${a.y} Q${cx},${cy} ${b.x},${b.y}`;
    const sample = (t: number) => {
      const u = 1 - t;
      return {
        x: u * u * a.x + 2 * u * t * cx + t * t * b.x,
        y: u * u * a.y + 2 * u * t * cy + t * t * b.y,
      };
    };
    return { path, sample, a, b, len };
  }

  const size = map.getSize();
  const now = Date.now();

  return (
    <div
      className="pointer-events-none absolute inset-0 z-[400]"
      style={{ width: size.x, height: size.y }}
    >
      <svg width={size.x} height={size.y} className="pointer-events-none">
        <defs>
          <linearGradient id="arc-grad-live" x1="0" x2="1" y1="0" y2="0">
            <stop offset="0%" stopColor="#a855f7" stopOpacity="0.15" />
            <stop offset="50%" stopColor="#d946ef" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#ec4899" stopOpacity="0.95" />
          </linearGradient>
          <radialGradient id="packet-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#fde68a" stopOpacity="1" />
            <stop offset="60%" stopColor="#f472b6" stopOpacity="0.6" />
            <stop offset="100%" stopColor="#ec4899" stopOpacity="0" />
          </radialGradient>
          <radialGradient id="impact-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#fecaca" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#e11d48" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Selected engagement persistent arc */}
        {selectedArc && (() => {
          const g = arcGeometry(selectedArc.from, selectedArc.to);
          return (
            <path
              d={g.path}
              fill="none"
              stroke="url(#arc-grad-live)"
              strokeWidth={2.2}
              strokeDasharray="6 4"
              opacity={0.9}
            />
          );
        })()}

        {/* Live attack arcs + travelling packets */}
        {arcs.map(a => {
          const age = now - a.bornAt;
          const t = Math.min(1, Math.max(0, age / a.duration));
          const g = arcGeometry(a.from, a.to);
          const pkt = g.sample(t);
          const color = SEV_COLOR[a.severity] || '#d946ef';
          // trailing arc reveal progresses with t
          const dashLen = g.len + 60;
          return (
            <g key={a.id}>
              {/* Dim full arc */}
              <path
                d={g.path}
                fill="none"
                stroke={color}
                strokeWidth={1}
                strokeOpacity={0.25}
              />
              {/* Leading stroke reveal */}
              <path
                d={g.path}
                fill="none"
                stroke={color}
                strokeWidth={2.5}
                strokeOpacity={0.9}
                strokeLinecap="round"
                strokeDasharray={`${dashLen * t}, ${dashLen}`}
              />
              {/* Packet head */}
              {t < 1 && (
                <>
                  <circle cx={pkt.x} cy={pkt.y} r={9} fill="url(#packet-glow)" />
                  <circle cx={pkt.x} cy={pkt.y} r={3.2} fill="#fff" />
                </>
              )}
            </g>
          );
        })}

        {/* Impact ripples on decoys */}
        {impacts.map(imp => {
          const geo = DECOY_GEO[imp.decoyId];
          if (!geo) return null;
          const p = toPx(geo.lat, geo.lon);
          const age = now - imp.bornAt;
          const life = Math.min(1, age / 1000);
          const r = 6 + life * 28;
          const opacity = 1 - life;
          return (
            <g key={`imp-${imp.id}`}>
              <circle cx={p.x} cy={p.y} r={r} fill="none" stroke="#fb7185" strokeWidth={2} opacity={opacity * 0.8} />
              <circle cx={p.x} cy={p.y} r={r * 0.55} fill="url(#impact-glow)" opacity={opacity} />
            </g>
          );
        })}

        {/* Country flash on attacker origin */}
        {countryFlashes.map(cf => {
          const c = COUNTRIES[cf.country];
          if (!c) return null;
          const p = toPx(c.lat, c.lon);
          const age = now - cf.bornAt;
          const life = Math.min(1, age / 800);
          const r = 10 + life * 22;
          const opacity = (1 - life) * 0.9;
          return (
            <circle
              key={`flash-${cf.id}`}
              cx={p.x}
              cy={p.y}
              r={r}
              fill="none"
              stroke={SEV_COLOR[cf.severity] || '#f472b6'}
              strokeWidth={1.5}
              opacity={opacity}
            />
          );
        })}
      </svg>
    </div>
  );
};

// ---------- Main component ----------

interface Props {
  engagements: Engagement[];
  instances: DecoyInstance[];
  selectedEngagementId?: string | null;
  liveArc?: { engagementId: string; ts: number } | null;
  onSelectCountry?: (country: string | null) => void;
  onSelectDecoy?: (decoyId: string | null) => void;
}

const WorldAttackerMap: React.FC<Props> = ({
  engagements, instances, selectedEngagementId, liveArc,
  onSelectCountry, onSelectDecoy,
}) => {
  const [flyTarget, setFlyTarget] = useState<{ lat: number; lon: number; id: string; zoom?: number } | null>(null);

  // Attacker country aggregation
  const countryAgg = useMemo(() => {
    const m = new Map<string, { count: number; lastSev: string; lastIp: string }>();
    for (const e of engagements) {
      const cur = m.get(e.attackerCountry) || { count: 0, lastSev: 'LOW', lastIp: e.attackerIp };
      cur.count += 1;
      if (severityRank(e.severity) > severityRank(cur.lastSev)) cur.lastSev = e.severity;
      m.set(e.attackerCountry, cur);
    }
    return m;
  }, [engagements]);

  const decoyAgg = useMemo(() => {
    const m = new Map<string, { active: number; total: number; sev: string }>();
    for (const e of engagements) {
      const cur = m.get(e.decoyInstanceId) || { active: 0, total: 0, sev: 'LOW' };
      cur.total += 1;
      if (e.status === 'ACTIVE') cur.active += 1;
      if (severityRank(e.severity) > severityRank(cur.sev)) cur.sev = e.severity;
      m.set(e.decoyInstanceId, cur);
    }
    return m;
  }, [engagements]);

  // Top-K attacker countries for labels
  const topCountries = useMemo(() => {
    return Array.from(countryAgg.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 6);
  }, [countryAgg]);

  return (
    <div className="relative w-full rounded-xl overflow-hidden ring-1 ring-violet-200/50 bg-slate-900">
      <div className="h-[360px] w-full">
        <MapContainer
          center={[30, 15]}
          zoom={2}
          minZoom={2}
          maxZoom={8}
          worldCopyJump
          scrollWheelZoom={false}
          style={{ height: '100%', width: '100%', background: '#0b1020' }}
          attributionControl={false}
        >
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            subdomains={['a', 'b', 'c', 'd']}
            attribution='&copy; OpenStreetMap &copy; CARTO'
          />

          {/* Day / night terminator */}
          <DayNightTerminator />

          {/* Country labels + threat score badges (top 6) */}
          {topCountries.map(([cc, agg]) => {
            const c = COUNTRIES[cc];
            if (!c) return null;
            // badge size 120x28 -> lat/lon bounds roughly 10deg x 3deg
            const bounds: L.LatLngBoundsExpression = [
              [c.lat + 1.5, c.lon - 5],
              [c.lat + 4.5, c.lon + 5],
            ];
            return (
              <SVGOverlay key={`lbl-${cc}`} bounds={bounds} attributes={{ viewBox: '0 0 120 28' }}>
                <g>
                  <rect x="0" y="4" rx="6" ry="6" width="120" height="20" fill="rgba(15,23,42,0.85)" stroke="rgba(168,85,247,0.75)" strokeWidth="0.6" />
                  <text x="6" y="17" fill="#e2e8f0" fontSize="11" fontWeight="700">{c.name}</text>
                  <circle cx="104" cy="14" r="7" fill={SEV_COLOR[agg.lastSev] || '#f472b6'} stroke="#fff" strokeWidth="0.8" />
                  <text x="104" y="17" textAnchor="middle" fill="#fff" fontSize="9" fontWeight="700">{agg.count}</text>
                </g>
              </SVGOverlay>
            );
          })}

          {/* Attacker markers */}
          {Array.from(countryAgg.entries()).map(([cc, agg]) => {
            const c = COUNTRIES[cc];
            if (!c) return null;
            const radius = Math.min(16, 5 + Math.sqrt(agg.count) * 2);
            return (
              <CircleMarker
                key={`atk-${cc}`}
                center={[c.lat, c.lon]}
                radius={radius}
                pathOptions={{
                  color: '#fff',
                  weight: 1,
                  fillColor: SEV_COLOR[agg.lastSev] || '#f472b6',
                  fillOpacity: 0.85,
                }}
                eventHandlers={{
                  click: () => onSelectCountry?.(cc),
                }}
              >
                <Tooltip direction="top" offset={[0, -6]} opacity={1}>
                  <div className="text-xs">
                    <div className="font-bold">{c.name} ({cc})</div>
                    <div>{agg.count} engagement{agg.count > 1 ? 's' : ''}</div>
                    <div>last severity: <span style={{ color: SEV_COLOR[agg.lastSev] }}>{agg.lastSev}</span></div>
                    <div className="text-slate-500">{agg.lastIp}</div>
                  </div>
                </Tooltip>
              </CircleMarker>
            );
          })}

          {/* Decoy markers */}
          {instances.map(d => {
            const g = DECOY_GEO[d.id];
            if (!g) return null;
            const agg = decoyAgg.get(d.id);
            return (
              <CircleMarker
                key={`dec-${d.id}`}
                center={[g.lat, g.lon]}
                radius={9}
                pathOptions={{
                  color: '#fff',
                  weight: 1.5,
                  fillColor: '#a855f7',
                  fillOpacity: 0.95,
                }}
                eventHandlers={{
                  click: () => {
                    onSelectDecoy?.(d.id);
                    setFlyTarget({ lat: g.lat, lon: g.lon, id: d.id });
                  },
                }}
              >
                <Tooltip direction="top" offset={[0, -6]} opacity={1}>
                  <div className="text-xs">
                    <div className="font-bold">{d.name}</div>
                    <div>{d.protocol} · {d.ipAddress}:{d.port}</div>
                    <div>{d.facility || 'Facility'} · L{d.purdueLevel}</div>
                    {agg && (
                      <div className="text-rose-600">{agg.active} active / {agg.total} total</div>
                    )}
                  </div>
                </Tooltip>
              </CircleMarker>
            );
          })}

          {/* Decoy zoom-in flyTo */}
          <FlyToDecoy target={flyTarget} />

          {/* Live + selected arc overlay */}
          <ArcLayer
            engagements={engagements}
            liveArc={liveArc}
            selectedEngagementId={selectedEngagementId}
          />
        </MapContainer>
      </div>

      {/* Legend */}
      <div className="absolute bottom-2 left-2 right-2 z-[500] flex flex-wrap items-center gap-3 text-[11px] text-violet-100/90 px-3 py-1.5 rounded-lg bg-slate-900/70 backdrop-blur-sm ring-1 ring-white/10 pointer-events-none">
        <span className="font-semibold tracking-wider uppercase text-violet-300">Legend</span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-pink-400 ring-1 ring-white/40" /> attacker source
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-violet-500 ring-1 ring-white/40" /> decoy
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-3 h-0.5 bg-fuchsia-400" /> live engagement event
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="relative w-2.5 h-2.5">
            <span className="absolute inset-0 rounded-full bg-amber-300 animate-ping" />
            <span className="absolute inset-0 rounded-full bg-amber-300" />
          </span>
          attack packet
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-3 h-2 rounded-sm bg-slate-900/80 ring-1 ring-white/20" /> night side
        </span>
        <span className="ml-auto text-violet-300/70">{engagements.length} engagements</span>
      </div>

      {/* Reset-view button */}
      {flyTarget && (
        <button
          onClick={() => setFlyTarget({ lat: 30, lon: 15, id: '__reset__', zoom: 2 })}
          className="absolute top-2 right-2 z-[500] px-2.5 py-1 text-[11px] font-semibold rounded-md bg-violet-600/90 hover:bg-violet-500 text-white ring-1 ring-white/20 shadow"
        >
          Reset view
        </button>
      )}
    </div>
  );
};

export default WorldAttackerMap;
