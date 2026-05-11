import React, { useEffect, useState } from 'react';

interface TripwireEvent {
  id: number;
  timestamp: string | null;
  sourceIp: string | null;
  protocol: string | null;
  attackType: string | null;
  severity: string | null;
  description: string | null;
  decoySource: string | null;
  siteTag: string | null;
}

interface DashboardStats {
  recentEvents: TripwireEvent[];
  decoySourceBreakdown?: Record<string, number>;
  internalDecoySiteBreakdown?: Record<string, number>;
}

const formatRelative = (iso: string | null): string => {
  if (!iso) return 'just now';
  const t = new Date(iso).getTime();
  if (isNaN(t)) return 'just now';
  const diff = Math.max(0, Date.now() - t);
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
};

/**
 * Tripwire alarms banner - shown above the Fake HMI grid.
 * Sources real internal-decoy events from the OTShield backend (the
 * docker-compose tripwire fleet under /decoys/), tagged with
 * `decoySource = "internal-decoy"`. These are CRITICAL by definition:
 * no legitimate user has any reason to talk to a tripwire HMI, so a
 * single hit means lateral movement is in progress.
 */
const TripwireAlarmsBanner: React.FC = () => {
  const [tripwireEvents, setTripwireEvents] = useState<TripwireEvent[]>([]);
  const [siteBreakdown, setSiteBreakdown] = useState<Record<string, number>>({});
  const [internalCount, setInternalCount] = useState<number>(0);
  const [externalCount, setExternalCount] = useState<number>(0);

  useEffect(() => {
    const load = async () => {
      try {
        const r = await fetch('http://localhost:8080/api/honeypot/stats');
        if (!r.ok) return;
        const d: DashboardStats = await r.json();
        const tripwire = (d.recentEvents || []).filter(
          (e) => (e.decoySource || '').toLowerCase() === 'internal-decoy',
        );
        setTripwireEvents(tripwire.slice(0, 5));
        setSiteBreakdown(d.internalDecoySiteBreakdown || {});
        if (d.decoySourceBreakdown) {
          setInternalCount(d.decoySourceBreakdown['internal-decoy'] || 0);
          setExternalCount(d.decoySourceBreakdown['external'] || 0);
        }
      } catch {
        /* backend unreachable - banner just stays empty */
      }
    };
    load();
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, []);

  const hasAlarms = internalCount > 0 || tripwireEvents.length > 0;

  if (!hasAlarms) {
    return (
      <div className="rounded-2xl ring-1 ring-emerald-200/70 bg-gradient-to-br from-emerald-50 to-white p-5 mb-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500 text-white flex items-center justify-center shadow-md shadow-emerald-500/30">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div className="flex-1">
            <p className="text-sm font-semibold text-slate-900">No tripwire alarms</p>
            <p className="text-xs text-slate-500">All internal decoys are quiet. Lateral-movement detection is active.</p>
          </div>
          <span className="text-[11px] font-semibold uppercase tracking-wider text-emerald-700 bg-emerald-100/70 px-2 py-1 rounded-full">
            Healthy
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-2xl ring-1 ring-rose-300/70 bg-gradient-to-br from-rose-50 via-orange-50 to-white p-5 mb-5 shadow-sm">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <div className="relative">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-rose-500 to-orange-500 text-white flex items-center justify-center shadow-lg shadow-rose-500/30">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
          </div>
          <span className="absolute -top-1 -right-1 flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-3 w-3 bg-rose-500" />
          </span>
        </div>
        <div className="flex-1">
          <p className="text-sm font-semibold text-slate-900">
            Tripwire alarms active <span className="text-rose-600">· lateral movement detected</span>
          </p>
          <p className="text-xs text-slate-600">
            <strong className="text-rose-700">{internalCount.toLocaleString()}</strong> internal-decoy event(s)
            {externalCount > 0 && (
              <>
                {' '}vs <strong className="text-slate-700">{externalCount.toLocaleString()}</strong> perimeter event(s)
              </>
            )}
          </p>
        </div>
        <span className="text-[11px] font-semibold uppercase tracking-wider text-rose-700 bg-rose-100/80 ring-1 ring-rose-200 px-2 py-1 rounded-full animate-pulse">
          Critical
        </span>
      </div>

      {/* Recent tripwire feed */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1.5">
            Last hits
          </p>
          <div className="space-y-1">
            {tripwireEvents.length === 0 && (
              <p className="text-xs text-slate-400">No recent tripwire events in the last 30-event window.</p>
            )}
            {tripwireEvents.map((e) => (
              <div key={e.id} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/70 ring-1 ring-rose-200/50">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse flex-shrink-0" />
                <span className="text-[10px] font-semibold uppercase tracking-wider text-rose-700 bg-rose-50 ring-1 ring-rose-200 px-1.5 py-0.5 rounded">
                  {e.protocol || 'TCP'}
                </span>
                <span className="text-xs font-mono text-slate-700 truncate">{e.sourceIp || '?'}</span>
                {e.siteTag && (
                  <span className="text-[10px] text-slate-500 truncate">{e.siteTag}</span>
                )}
                <span className="ml-auto text-[10px] text-slate-400 flex-shrink-0">{formatRelative(e.timestamp)}</span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1.5">
            Sites under fire
          </p>
          <div className="space-y-1">
            {Object.keys(siteBreakdown).length === 0 && (
              <p className="text-xs text-slate-400">Site tags will appear once a tripwire fires.</p>
            )}
            {Object.entries(siteBreakdown).slice(0, 5).map(([site, count]) => {
              const max = Math.max(1, ...Object.values(siteBreakdown));
              const pct = Math.round((count / max) * 100);
              return (
                <div key={site} className="px-3 py-2 rounded-lg bg-white/70 ring-1 ring-rose-200/50">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono font-semibold text-slate-700 truncate">{site}</span>
                    <span className="text-xs font-bold text-rose-600 tabular-nums">{count}</span>
                  </div>
                  <div className="h-1 bg-rose-100 rounded-full overflow-hidden">
                    <div className="h-full bg-gradient-to-r from-rose-500 to-orange-500 rounded-full" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default TripwireAlarmsBanner;
