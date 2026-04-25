import React, { useEffect, useMemo, useState } from 'react';
import dpiService, { DpiEvent, FunctionCodeStat } from '../services/dpiService';

/**
 * Detail modal for a Deep-Packet-Inspection context - opened from either a
 * topology edge (src↔dst pair), a topology node (single IP), or the Dashboard
 * DPI widget (global). Shows a function-code histogram, the last N events,
 * and - when an event is selected - the full {@code dpiFieldsJson} as a
 * two-column table.
 *
 * The modal self-fetches from {@code /api/dpi/*} based on the scope the caller
 * passes in, so callers only need to open/close it.
 */
export type DpiModalScope =
  | { kind: 'edge'; sourceIp: string; destinationIp: string; title?: string }
  | { kind: 'node'; ip: string; title?: string }
  | { kind: 'global'; title?: string };

interface Props {
  open: boolean;
  scope: DpiModalScope | null;
  onClose: () => void;
}

const RARE_PCT = 2; // histogram entries below this % are flagged "rare"
const RARE_MIN_TOTAL = 20; // … but only once we have enough samples

const DpiEventModal: React.FC<Props> = ({ open, scope, onClose }) => {
  const [events, setEvents] = useState<DpiEvent[]>([]);
  const [stats, setStats] = useState<FunctionCodeStat[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<DpiEvent | null>(null);
  const [selectedFields, setSelectedFields] = useState<Record<string, string> | null>(null);

  // ---- Data fetch -----------------------------------------------------------
  useEffect(() => {
    if (!open || !scope) {
      setEvents([]);
      setStats([]);
      setSelected(null);
      setSelectedFields(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);

    const eventsPromise: Promise<DpiEvent[]> =
      scope.kind === 'edge'
        ? dpiService.recentForEdge(scope.sourceIp, scope.destinationIp, 25)
        : scope.kind === 'node'
        ? dpiService.recentForNode(scope.ip, 25)
        : dpiService.search({ size: 25 }).then((p) => p.content);

    const statsPromise: Promise<FunctionCodeStat[]> =
      scope.kind === 'edge'
        ? dpiService.functionStats({ sourceIp: scope.sourceIp, destinationIp: scope.destinationIp })
        : scope.kind === 'node'
        ? dpiService.nodeStats(scope.ip)
        : dpiService.functionStats({});

    Promise.all([eventsPromise.catch(() => []), statsPromise.catch(() => [])])
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
  }, [open, scope]);

  // ---- Esc key closes the modal --------------------------------------------
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  // ---- Selected event → fetch full fields ----------------------------------
  useEffect(() => {
    if (!selected) {
      setSelectedFields(null);
      return;
    }
    // If the row already carries JSON (e.g. came straight from /events/{id}),
    // parse it locally; otherwise fetch the detail endpoint.
    if (selected.dpiFieldsJson) {
      try {
        setSelectedFields(JSON.parse(selected.dpiFieldsJson));
        return;
      } catch {
        /* fall through to fetch */
      }
    }
    let cancelled = false;
    dpiService
      .getById(selected.id)
      .then((full) => {
        if (cancelled) return;
        if (full.dpiFieldsJson) {
          try {
            setSelectedFields(JSON.parse(full.dpiFieldsJson));
          } catch {
            setSelectedFields(null);
          }
        } else {
          setSelectedFields({});
        }
      })
      .catch(() => {
        if (!cancelled) setSelectedFields(null);
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  const total = useMemo(() => stats.reduce((s, r) => s + (r.count || 0), 0), [stats]);
  const title = useMemo(() => {
    if (!scope) return 'DPI Events';
    if (scope.title) return scope.title;
    if (scope.kind === 'edge') return `DPI · ${scope.sourceIp} ↔ ${scope.destinationIp}`;
    if (scope.kind === 'node') return `DPI · ${scope.ip}`;
    return 'DPI · Global';
  }, [scope]);

  if (!open || !scope) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      onClick={onClose}
    >
      <div
        className="bg-white rounded-lg shadow-xl w-full max-w-4xl max-h-[85vh] overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200">
          <div>
            <div className="text-[11px] uppercase tracking-wide text-gray-500">
              Deep Packet Inspection
            </div>
            <div className="text-base font-semibold text-gray-900">{title}</div>
          </div>
          <button
            type="button"
            className="text-gray-400 hover:text-gray-600 text-xl leading-none px-2"
            onClick={onClose}
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto">
          {loading && <div className="p-4 text-sm text-gray-500">Loading DPI data…</div>}
          {error && <div className="p-4 text-sm text-red-600">{error}</div>}

          {!loading && !error && (
            <div className="p-4 space-y-4">
              <FunctionStatsBar stats={stats} total={total} />
              <EventList
                events={events}
                selectedId={selected?.id || null}
                onSelect={setSelected}
              />
              {selected && (
                <EventDetail event={selected} fields={selectedFields} onClear={() => setSelected(null)} />
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 border-t border-gray-200 text-[11px] text-gray-400 bg-gray-50">
          Events are persisted as {`'dpi_events'`} after each .pcap upload. Rare codes are flagged
          below {RARE_PCT}% of {RARE_MIN_TOTAL}+ samples.
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Subcomponents
// ---------------------------------------------------------------------------

const FunctionStatsBar: React.FC<{ stats: FunctionCodeStat[]; total: number }> = ({
  stats,
  total,
}) => {
  if (stats.length === 0) {
    return (
      <div className="text-xs text-gray-500 italic">
        No function-code aggregation for this scope yet.
      </div>
    );
  }
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wide text-gray-500 mb-2">
        Function-code histogram · {total.toLocaleString()} PDU
      </div>
      <div className="space-y-1">
        {stats.map((s, idx) => {
          const pct = total > 0 ? (s.count / total) * 100 : 0;
          const isRare = total >= RARE_MIN_TOTAL && pct < RARE_PCT;
          return (
            <div key={`${s.protocol}-${s.functionCode}-${idx}`} className="flex items-center gap-2 text-xs">
              <div className="w-14 text-gray-500 uppercase text-[10px] tabular-nums">
                {s.protocol}
              </div>
              <div className="w-14 font-mono text-gray-700">{s.functionCode}</div>
              <div className="flex-1 min-w-0 truncate text-gray-800">
                {s.functionName || '-'}
              </div>
              <div className="w-40 bg-gray-100 rounded h-2 overflow-hidden">
                <div
                  className={`h-full ${isRare ? 'bg-fuchsia-500' : 'bg-blue-500'}`}
                  style={{ width: `${Math.max(2, pct)}%` }}
                />
              </div>
              <div className="w-16 text-right tabular-nums text-gray-500">{s.count}</div>
              <div className="w-10 text-right tabular-nums text-gray-400">{pct.toFixed(1)}%</div>
              {isRare && (
                <span className="text-[10px] uppercase font-semibold text-fuchsia-700">rare</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

const EventList: React.FC<{
  events: DpiEvent[];
  selectedId: string | null;
  onSelect: (e: DpiEvent) => void;
}> = ({ events, selectedId, onSelect }) => {
  if (events.length === 0) {
    return (
      <div className="text-xs text-gray-500 italic">
        No events in this scope. Upload a .pcap with Modbus or S7 traffic to populate.
      </div>
    );
  }
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wide text-gray-500 mb-2">
        Recent events · last {events.length}
      </div>
      <div className="overflow-x-auto border border-gray-100 rounded">
        <table className="min-w-full text-xs">
          <thead className="bg-gray-50 text-gray-600">
            <tr>
              <th className="text-left px-2 py-1">Time</th>
              <th className="text-left px-2 py-1">Proto</th>
              <th className="text-left px-2 py-1">Source</th>
              <th className="text-left px-2 py-1">Destination</th>
              <th className="text-left px-2 py-1">Function</th>
              <th className="text-left px-2 py-1">Address</th>
              <th className="text-left px-2 py-1">Value</th>
              <th className="text-left px-2 py-1"></th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => {
              const isSel = e.id === selectedId;
              return (
                <tr
                  key={e.id}
                  onClick={() => onSelect(e)}
                  className={`cursor-pointer ${
                    isSel ? 'bg-blue-50' : 'hover:bg-gray-50'
                  }`}
                >
                  <td className="px-2 py-1 text-gray-600 tabular-nums whitespace-nowrap">
                    {formatTs(e.eventTime)}
                  </td>
                  <td className="px-2 py-1 text-gray-700">{e.protocol}</td>
                  <td className="px-2 py-1 text-gray-800 truncate max-w-[140px]">{e.sourceIp}</td>
                  <td className="px-2 py-1 text-gray-800 truncate max-w-[140px]">{e.destinationIp}</td>
                  <td className="px-2 py-1 text-gray-800 truncate max-w-[180px]">
                    <span className="font-mono mr-1">{e.functionCode || ''}</span>
                    {e.functionName || ''}
                  </td>
                  <td className="px-2 py-1 text-gray-700">{e.registerAddress || ''}</td>
                  <td className="px-2 py-1 text-gray-700 truncate max-w-[100px]">
                    {e.value || ''}
                  </td>
                  <td className="px-2 py-1 whitespace-nowrap">
                    {e.isWrite && (
                      <span className="text-[10px] uppercase font-semibold text-amber-700 mr-1">
                        write
                      </span>
                    )}
                    {e.isException && (
                      <span className="text-[10px] uppercase font-semibold text-red-700">
                        exc
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const EventDetail: React.FC<{
  event: DpiEvent;
  fields: Record<string, string> | null;
  onClear: () => void;
}> = ({ event, fields, onClear }) => {
  return (
    <div className="border border-gray-200 rounded p-3 bg-gray-50">
      <div className="flex items-start justify-between mb-2">
        <div>
          <div className="text-[11px] uppercase tracking-wide text-gray-500">Event detail</div>
          <div className="text-sm font-mono text-gray-800 break-all">{event.id}</div>
        </div>
        <button
          type="button"
          className="text-xs text-gray-500 hover:text-gray-700"
          onClick={onClear}
        >
          clear
        </button>
      </div>

      {event.summary && (
        <div className="text-xs text-gray-700 mb-2">
          <span className="uppercase text-[10px] text-gray-400 mr-1">Summary:</span>
          <span className="font-mono break-all">{event.summary}</span>
        </div>
      )}

      {fields === null ? (
        <div className="text-xs text-gray-400 italic">Loading fields…</div>
      ) : Object.keys(fields).length === 0 ? (
        <div className="text-xs text-gray-400 italic">No detailed fields for this event.</div>
      ) : (
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
          {Object.entries(fields).map(([k, v]) => (
            <React.Fragment key={k}>
              <div className="text-gray-500 uppercase text-[10px] tabular-nums">{k}</div>
              <div className="text-gray-800 font-mono break-all">{String(v)}</div>
            </React.Fragment>
          ))}
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const formatTs = (iso: string): string => {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};

export default DpiEventModal;
