import React, { useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  decoyService,
  subscribeDecoyStream,
  DecoyInstance,
  Engagement,
  EngagementEvent,
  DecoyStats,
  DecoyProtocol,
  EngagementStatus,
} from '../services/decoyService';
import { Icon, PageHero, Panel, severityStyle } from './theme';
import PayloadInspector from './decoy/PayloadInspector';
import EngagementMitreChain from './decoy/EngagementMitreChain';
import ResponseActionBar from './decoy/ResponseActionBar';
import WorldAttackerMap from './decoy/WorldAttackerMap';
import FacilityTopologyMap from './decoy/FacilityTopologyMap';
import FakeHmisTab from './decoy/hmi/FakeHmisTab';

/**
 * Decoy Layer
 * ============================================================
 * Three-zone layout focused on attacker engagement flow:
 *
 *   Top  : Hero (rolling stats - active engagements, attackers 24h, decoys up)
 *   Left : Live Engagement Feed (filterable by protocol, glows on new event)
 *   Right: Engagement Detail (attacker profile, event timeline, deep payload,
 *          response actions)
 *   Bottom: Decoy Instances Strip (industrial protocol decoys, status + counters)
 */

const PROTOCOL_LABEL: Record<DecoyProtocol, string> = {
  MODBUS: 'Modbus',
  S7: 'Siemens S7',
  DNP3: 'DNP3',
  ETHERNET_IP: 'EtherNet/IP',
  OPC_UA: 'OPC UA',
};

const PROTOCOL_PILL: Record<DecoyProtocol, string> = {
  MODBUS: 'bg-violet-50 text-violet-700 ring-violet-200',
  S7: 'bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-200',
  DNP3: 'bg-pink-50 text-pink-700 ring-pink-200',
  ETHERNET_IP: 'bg-rose-50 text-rose-700 ring-rose-200',
  OPC_UA: 'bg-amber-50 text-amber-700 ring-amber-200',
};

const STATUS_DOT: Record<string, string> = {
  RUNNING: 'bg-emerald-500',
  STOPPED: 'bg-slate-400',
  DEGRADED: 'bg-amber-500',
  STARTING: 'bg-violet-400',
  STOPPING: 'bg-violet-400',
};

const Decoy: React.FC = () => {
  const [instances, setInstances] = useState<DecoyInstance[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [stats, setStats] = useState<DecoyStats | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Engagement | null>(null);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [protocolFilter, setProtocolFilter] = useState<'ALL' | DecoyProtocol>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | EngagementStatus>('ALL');
  const [decoyFilter, setDecoyFilter] = useState<string | null>(null);
  const [countryFilter, setCountryFilter] = useState<string | null>(null);
  const [glowIds, setGlowIds] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [streamConnected, setStreamConnected] = useState(false);
  const [liveArc, setLiveArc] = useState<{ engagementId: string; ts: number } | null>(null);
  const [topTab, setTopTab] = useState<'engagements' | 'fakeHmis'>('engagements');

  const streamCloseRef = useRef<(() => void) | null>(null);

  // ---- Initial load ----
  const loadAll = async () => {
    try {
      const [inst, engs, st] = await Promise.all([
        decoyService.listInstances(),
        decoyService.listEngagements({ size: 80 }),
        decoyService.stats(),
      ]);
      setInstances(inst);
      setEngagements(engs);
      setStats(st);
      if (!selectedId && engs.length) {
        setSelectedId(engs[0].id);
      }
      setError(null);
    } catch (e: any) {
      setError(e?.message || 'Failed to load decoy data');
    }
  };

  useEffect(() => {
    loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---- Detail load when selection changes ----
  useEffect(() => {
    if (!selectedId) { setSelected(null); setSelectedEventId(null); return; }
    let cancelled = false;
    decoyService.getEngagement(selectedId).then(e => {
      if (cancelled) return;
      setSelected(e);
      setSelectedEventId(e.events && e.events.length ? e.events[e.events.length - 1].id : null);
    }).catch(() => { if (!cancelled) setSelected(null); });
    return () => { cancelled = true; };
  }, [selectedId]);

  // ---- WebSocket live stream ----
  useEffect(() => {
    const close = subscribeDecoyStream(
      (msg) => {
        if (msg.kind === 'CONNECTED') setStreamConnected(true);
        if (msg.kind === 'EVENT') {
          // trigger an animated arc on the world map
          setLiveArc({ engagementId: msg.engagementId, ts: Date.now() });
          // glow the engagement card in the feed
          setGlowIds(prev => {
            const next = new Set(prev);
            next.add(msg.engagementId);
            window.setTimeout(() => {
              setGlowIds(p => {
                const c = new Set(p);
                c.delete(msg.engagementId);
                return c;
              });
            }, 1800);
            return next;
          });
          // bump engagement to top with new lastActivity / event count
          setEngagements(prev => {
            const idx = prev.findIndex(e => e.id === msg.engagementId);
            if (idx === -1) return prev;
            const u: Engagement = { ...prev[idx], lastActivityAt: msg.event.ts, eventCount: (prev[idx].eventCount || 0) + 1 };
            const rest = prev.filter(e => e.id !== msg.engagementId);
            return [u, ...rest];
          });
          // if the open engagement, append the event live
          setSelected(prev => {
            if (!prev || prev.id !== msg.engagementId) return prev;
            const events = [...(prev.events || []), msg.event];
            return { ...prev, events, eventCount: events.length, lastActivityAt: msg.event.ts };
          });
        }
        if (msg.kind === 'INSTANCE_STATUS') {
          setInstances(prev => prev.map(d => d.id === msg.instanceId ? { ...d, status: msg.status } : d));
        }
      },
      () => setStreamConnected(false),
    );
    streamCloseRef.current = close;
    return () => { close(); };
  }, []);

  // ---- Filtered feed ----
  const feed = useMemo(() => {
    return engagements.filter(e => {
      if (protocolFilter !== 'ALL' && e.protocol !== protocolFilter) return false;
      if (statusFilter !== 'ALL' && e.status !== statusFilter) return false;
      if (decoyFilter && e.decoyInstanceId !== decoyFilter) return false;
      if (countryFilter && e.attackerCountry !== countryFilter) return false;
      return true;
    });
  }, [engagements, protocolFilter, statusFilter, decoyFilter, countryFilter]);

  const selectedEvent: EngagementEvent | null = useMemo(() => {
    if (!selected || !selected.events) return null;
    return selected.events.find(ev => ev.id === selectedEventId) || selected.events[selected.events.length - 1] || null;
  }, [selected, selectedEventId]);

  return (
    <div className="space-y-6">
      <PageHero
        eyebrow="DECEPTION FABRIC"
        icon={<Icon.Eye className="w-3.5 h-3.5" />}
        title="Decoy Layer"
        subtitle="Live attacker engagement flow across the industrial-protocol deception fabric. Inspect deep payloads down to the register / DB / node level and respond from one place."
        stats={stats ? [
          { label: 'Active engagements', value: stats.activeEngagements, sub: `${stats.engagementsLast24h} in last 24h` },
          { label: 'Unique attackers 24h', value: stats.uniqueAttackersLast24h, sub: `${Object.keys(stats.engagementsByProtocol).length} protocols hit` },
          { label: 'Decoys running', value: `${stats.decoysRunning}/${stats.decoysTotal}`, sub: streamConnected ? 'Stream connected' : 'Stream offline' },
        ] : []}
        actions={
          <button
            onClick={loadAll}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-white bg-white/10 hover:bg-white/20 ring-1 ring-white/20 backdrop-blur-sm"
          >
            <Icon.Refresh className="w-4 h-4" /> Refresh
          </button>
        }
      />

      {error && (
        <div className="p-4 rounded-2xl bg-rose-50 ring-1 ring-rose-200 text-rose-700 text-sm">
          {error}
        </div>
      )}

      {/* Top tab bar */}
      <div className="flex items-center gap-2 border-b border-slate-200">
        {[
          { key: 'engagements', label: 'Live Engagements', icon: <Icon.Activity className="w-4 h-4" /> },
          { key: 'fakeHmis',    label: 'Fake HMIs',        icon: <Icon.Eye className="w-4 h-4" /> },
        ].map(t => (
          <button
            key={t.key}
            onClick={() => setTopTab(t.key as 'engagements' | 'fakeHmis')}
            className={`inline-flex items-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-t-xl transition-all ${
              topTab === t.key
                ? 'bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white shadow-lg -mb-px'
                : 'text-slate-500 hover:text-slate-800 hover:bg-slate-100'
            }`}
          >
            {t.icon}
            {t.label}
          </button>
        ))}
      </div>

      {topTab === 'fakeHmis' && <FakeHmisTab />}

      {topTab === 'engagements' && <>

      {/* Hybrid map: world (top) + facility topology (bottom) */}
      <Panel
        title="Engagement geography"
        subtitle="Attacker source countries & decoy fabric. Click any node to filter the live feed."
        icon={<Icon.Network />}
        actions={
          (countryFilter || decoyFilter) ? (
            <button
              onClick={() => { setCountryFilter(null); setDecoyFilter(null); }}
              className="text-xs font-semibold text-violet-700 hover:text-violet-900"
            >
              Clear map filters
            </button>
          ) : null
        }
      >
        <div className="space-y-4">
          <WorldAttackerMap
            engagements={engagements}
            instances={instances}
            selectedEngagementId={selectedId}
            liveArc={liveArc}
            onSelectCountry={(cc) => setCountryFilter(prev => prev === cc ? null : cc)}
            onSelectDecoy={(id) => setDecoyFilter(prev => prev === id ? null : id)}
          />
          <FacilityTopologyMap
            instances={instances}
            engagements={engagements}
            selectedDecoyId={decoyFilter}
            onSelectDecoy={(id) => setDecoyFilter(prev => prev === id ? null : id)}
            onSelectFacility={(facility) => {
              // Toggling a facility: pick first engagement that matches and select it,
              // also filter the feed by clearing decoy filter so all decoys in the facility show.
              setDecoyFilter(null);
              if (facility) {
                const facilityIds = instances.filter(i => i.facility === facility).map(i => i.id);
                const first = engagements.find(e => facilityIds.includes(e.decoyInstanceId));
                if (first) setSelectedId(first.id);
              }
            }}
          />
          {(countryFilter || decoyFilter) && (
            <div className="text-[11px] text-slate-500">
              Map filter active:
              {countryFilter && <span className="ml-1 px-2 py-0.5 rounded bg-violet-50 text-violet-700 ring-1 ring-violet-200">country = {countryFilter}</span>}
              {decoyFilter && <span className="ml-1 px-2 py-0.5 rounded bg-violet-50 text-violet-700 ring-1 ring-violet-200">decoy = {instances.find(i => i.id === decoyFilter)?.name || decoyFilter}</span>}
            </div>
          )}
        </div>
      </Panel>

      {/* Live feed + Engagement detail */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        {/* LEFT: Feed */}
        <div className="xl:col-span-4">
          <Panel
            title="Live Engagement Feed"
            subtitle={feed.length + ' / ' + engagements.length + ' shown'}
            icon={<Icon.Activity />}
          >
            <FeedFilters
              protocolFilter={protocolFilter}
              setProtocolFilter={setProtocolFilter}
              statusFilter={statusFilter}
              setStatusFilter={setStatusFilter}
              decoyFilter={decoyFilter}
              setDecoyFilter={setDecoyFilter}
              instances={instances}
            />
            <div className="mt-4 space-y-2 max-h-[60vh] overflow-y-auto pr-1 -mr-1">
              <AnimatePresence initial={false}>
                {feed.map(e => (
                  <motion.div
                    key={e.id}
                    layout
                    initial={{ opacity: 0, y: -6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.18 }}
                  >
                    <EngagementCard
                      eng={e}
                      glow={glowIds.has(e.id)}
                      selected={e.id === selectedId}
                      onClick={() => setSelectedId(e.id)}
                    />
                  </motion.div>
                ))}
              </AnimatePresence>
              {feed.length === 0 && (
                <div className="text-center py-10 text-sm text-slate-500">No engagements match the current filters.</div>
              )}
            </div>
          </Panel>
        </div>

        {/* RIGHT: Detail */}
        <div className="xl:col-span-8 space-y-6">
          {selected ? (
            <>
              <AttackerHeader engagement={selected} />
              <Panel title="Response actions" subtitle="Apply playbooks against the current engagement" icon={<Icon.Shield />}>
                <ResponseActionBar
                  engagement={selected}
                  onActionApplied={() => loadAll()}
                />
              </Panel>
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-5">
                  <Panel title="Event timeline" subtitle={`${selected.eventCount} messages`} icon={<Icon.Clock />}>
                    <EventTimeline
                      events={selected.events || []}
                      selectedId={selectedEventId}
                      onSelect={setSelectedEventId}
                    />
                  </Panel>
                </div>
                <div className="lg:col-span-7">
                  <Panel title="Payload inspector" subtitle={selectedEvent?.payload?.protocolOp || '-'} icon={<Icon.Search />}>
                    <PayloadInspector event={selectedEvent} />
                  </Panel>
                </div>
              </div>
              <Panel
                title="MITRE ATT&CK chain"
                subtitle={`Behavioral fingerprint & TTPs for ${selected.attackerIp}`}
                icon={<Icon.Target />}
              >
                <EngagementMitreChain
                  engagement={selected}
                  onSelectEvent={setSelectedEventId}
                />
              </Panel>
            </>
          ) : (
            <Panel>
              <div className="text-center py-16 text-sm text-slate-500">
                Select an engagement on the left to inspect attacker activity.
              </div>
            </Panel>
          )}
        </div>
      </div>

      {/* BOTTOM: Decoy Instances Strip */}
      <Panel
        title="Decoy fabric"
        subtitle="Industrial-protocol decoys deployed across plants"
        icon={<Icon.Layers />}
        actions={
          decoyFilter ? (
            <button
              onClick={() => setDecoyFilter(null)}
              className="text-xs font-semibold text-violet-700 hover:text-violet-900"
            >
              Clear decoy filter
            </button>
          ) : null
        }
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
          {instances.map(d => (
            <DecoyChip
              key={d.id}
              decoy={d}
              selected={decoyFilter === d.id}
              onClick={() => setDecoyFilter(prev => prev === d.id ? null : d.id)}
            />
          ))}
        </div>
      </Panel>
      </>}
    </div>
  );
};

/* ============================================================
 *  Sub-components
 * ============================================================ */

const FeedFilters: React.FC<{
  protocolFilter: 'ALL' | DecoyProtocol;
  setProtocolFilter: (p: 'ALL' | DecoyProtocol) => void;
  statusFilter: 'ALL' | EngagementStatus;
  setStatusFilter: (s: 'ALL' | EngagementStatus) => void;
  decoyFilter: string | null;
  setDecoyFilter: (d: string | null) => void;
  instances: DecoyInstance[];
}> = ({ protocolFilter, setProtocolFilter, statusFilter, setStatusFilter, decoyFilter, instances }) => {
  const protos: ('ALL' | DecoyProtocol)[] = ['ALL', 'MODBUS', 'S7', 'DNP3', 'ETHERNET_IP', 'OPC_UA'];
  const statuses: ('ALL' | EngagementStatus)[] = ['ALL', 'ACTIVE', 'IDLE', 'CLOSED'];
  const activeDecoy = decoyFilter ? instances.find(d => d.id === decoyFilter) : null;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1.5">
        {protos.map(p => (
          <button
            key={p}
            onClick={() => setProtocolFilter(p)}
            className={`px-2.5 py-1 rounded-full text-[11px] font-semibold ring-1 transition ${
              protocolFilter === p
                ? 'bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white ring-transparent'
                : 'bg-white text-slate-600 ring-slate-200 hover:bg-slate-50'
            }`}
          >
            {p === 'ALL' ? 'All protocols' : PROTOCOL_LABEL[p]}
          </button>
        ))}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {statuses.map(s => (
          <button
            key={s}
            onClick={() => setStatusFilter(s)}
            className={`px-2.5 py-1 rounded-full text-[11px] font-semibold ring-1 transition ${
              statusFilter === s
                ? 'bg-violet-100 text-violet-800 ring-violet-200'
                : 'bg-white text-slate-600 ring-slate-200 hover:bg-slate-50'
            }`}
          >
            {s === 'ALL' ? 'Any status' : s.charAt(0) + s.slice(1).toLowerCase()}
          </button>
        ))}
      </div>
      {activeDecoy && (
        <div className="text-[11px] text-slate-500">
          Filtering decoy: <span className="font-semibold text-slate-700">{activeDecoy.name}</span>
        </div>
      )}
    </div>
  );
};

const EngagementCard: React.FC<{
  eng: Engagement;
  glow: boolean;
  selected: boolean;
  onClick: () => void;
}> = ({ eng, glow, selected, onClick }) => {
  const sev = severityStyle(eng.severity);
  const since = relativeTime(eng.lastActivityAt);
  return (
    <button
      onClick={onClick}
      className={`w-full text-left p-3 rounded-xl ring-1 transition relative ${
        selected
          ? 'bg-violet-50 ring-violet-300 shadow-sm'
          : 'bg-white ring-slate-200 hover:ring-slate-300'
      } ${glow ? 'shadow-[0_0_0_3px_rgba(217,70,239,0.35)]' : ''}`}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className={`w-2 h-2 rounded-full ${sev.dot}`} />
          <span className="font-mono text-xs text-slate-800 truncate">{eng.attackerIp}</span>
          <span className="text-[10px] text-slate-400">{eng.attackerCountry}</span>
        </div>
        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ring-1 ${PROTOCOL_PILL[eng.protocol]}`}>
          {PROTOCOL_LABEL[eng.protocol]}
        </span>
      </div>
      <div className="mt-1.5 text-xs text-slate-700 truncate">{eng.decoyName}</div>
      <div className="mt-1 flex items-center justify-between text-[11px] text-slate-500">
        <span>{eng.eventCount} events · {eng.status.toLowerCase()}</span>
        <span>{since}</span>
      </div>
    </button>
  );
};

const AttackerHeader: React.FC<{ engagement: Engagement }> = ({ engagement }) => {
  const a = engagement.attackerProfile;
  const sev = severityStyle(engagement.severity);
  return (
    <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-5">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="flex items-center gap-4 min-w-0">
          <div className={`w-12 h-12 rounded-xl flex items-center justify-center text-white bg-gradient-to-br from-violet-500 to-fuchsia-500`}>
            <Icon.Target />
          </div>
          <div className="min-w-0">
            <div className="text-[11px] uppercase tracking-wider text-slate-500">Attacker</div>
            <div className="font-mono text-xl font-bold text-slate-900">{engagement.attackerIp}</div>
            {a && (
              <div className="mt-0.5 text-xs text-slate-500 truncate">
                {a.countryName} · {a.asn} {a.asnName} · first seen {relativeTime(a.firstSeen)}
              </div>
            )}
          </div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 min-w-[280px]">
          <Stat label="Severity">
            <span className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ring-1 ${sev.badge}`}>{engagement.severity}</span>
          </Stat>
          <Stat label="Threat score" value={String(engagement.threatScore)} />
          <Stat label="Decoys hit" value={a ? String(a.distinctDecoysHit) : '-'} />
          <Stat label="Engagements" value={a ? String(a.engagementCount) : '-'} />
        </div>
      </div>
      {a && a.tags && a.tags.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {a.tags.map(t => (
            <span key={t} className="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-slate-50 text-slate-700 ring-1 ring-slate-200">
              {t.replaceAll('_', ' ')}
            </span>
          ))}
          {a.blocked && (
            <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-50 text-rose-700 ring-1 ring-rose-200">
              BLOCKED
            </span>
          )}
          {a.quarantined && (
            <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-amber-50 text-amber-700 ring-1 ring-amber-200">
              QUARANTINED
            </span>
          )}
        </div>
      )}
    </div>
  );
};

const Stat: React.FC<{ label: string; value?: string; children?: React.ReactNode }> = ({ label, value, children }) => (
  <div>
    <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
    <div className="mt-0.5 text-sm font-semibold text-slate-900">{value || children}</div>
  </div>
);

const EventTimeline: React.FC<{
  events: EngagementEvent[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}> = ({ events, selectedId, onSelect }) => {
  if (!events.length) return <div className="text-sm text-slate-500 italic py-3">No events yet.</div>;
  return (
    <div className="relative pl-4 max-h-[55vh] overflow-y-auto">
      <div className="absolute left-1.5 top-0 bottom-0 w-px bg-gradient-to-b from-violet-300 via-fuchsia-300 to-pink-300" />
      <div className="space-y-2">
        {events.map(ev => {
          const sev = severityStyle(ev.severity);
          const sel = ev.id === selectedId;
          return (
            <button
              key={ev.id}
              onClick={() => onSelect(ev.id)}
              className={`relative w-full text-left pl-4 pr-2 py-2 rounded-lg transition ${
                sel ? 'bg-violet-50 ring-1 ring-violet-200' : 'hover:bg-slate-50'
              }`}
            >
              <span className={`absolute -left-0.5 top-3 w-2.5 h-2.5 rounded-full ring-2 ring-white ${sev.dot}`} />
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-slate-800 truncate">
                  {ev.payload?.protocolOp || ev.summary}
                </span>
                <span className="text-[10px] text-slate-500 flex-shrink-0">{new Date(ev.ts).toLocaleTimeString()}</span>
              </div>
              {ev.payload?.addressRange && (
                <div className="mt-0.5 text-[11px] font-mono text-slate-500 truncate">{ev.payload.addressRange}</div>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
};

const DecoyChip: React.FC<{ decoy: DecoyInstance; selected: boolean; onClick: () => void }> = ({ decoy, selected, onClick }) => (
  <button
    onClick={onClick}
    className={`text-left p-3 rounded-xl ring-1 transition ${
      selected ? 'bg-violet-50 ring-violet-300' : 'bg-white ring-slate-200 hover:ring-slate-300'
    }`}
  >
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2 min-w-0">
        <span className={`w-2 h-2 rounded-full ${STATUS_DOT[decoy.status] || 'bg-slate-300'}`} />
        <span className="text-xs font-semibold text-slate-800 truncate">{decoy.name}</span>
      </div>
      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ring-1 ${PROTOCOL_PILL[decoy.protocol]}`}>
        {PROTOCOL_LABEL[decoy.protocol]}
      </span>
    </div>
    <div className="mt-1 text-[11px] text-slate-500 truncate">{decoy.vendor} · {decoy.model}</div>
    <div className="mt-1 text-[11px] font-mono text-slate-400">{decoy.ipAddress}:{decoy.port}</div>
    <div className="mt-2 flex items-center justify-between text-[11px] text-slate-600">
      <span>{decoy.activeEngagements} active · {decoy.totalEngagements} total</span>
      <span>L{decoy.purdueLevel}</span>
    </div>
  </button>
);

/* ---------- Helpers ---------- */
function relativeTime(iso: string | null | undefined): string {
  if (!iso) return '-';
  const d = new Date(iso).getTime();
  const diff = Date.now() - d;
  if (diff < 60_000) return Math.max(1, Math.floor(diff / 1000)) + 's ago';
  if (diff < 3_600_000) return Math.floor(diff / 60_000) + 'm ago';
  if (diff < 86_400_000) return Math.floor(diff / 3_600_000) + 'h ago';
  return Math.floor(diff / 86_400_000) + 'd ago';
}

export default Decoy;
