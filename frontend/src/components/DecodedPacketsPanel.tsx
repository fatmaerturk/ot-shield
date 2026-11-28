import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import dpiService, { DpiEvent, FunctionCodeStat } from '../services/dpiService';
import { Panel, Icon } from './theme';

/**
 * Wireshark-style inspector for the decoded packets the DPI pipeline produced
 * from ingested traffic. Left: the "packet list" (one row per dissected PDU,
 * newest first). Right: the "detail pane" - a layered protocol tree showing the
 * full decoded field set for the selected packet (PDU / Function / Data /
 * Integrity), plus a function-code histogram for that src-dst pair.
 *
 * Every row is a real {@code /api/dpi/events} record written by the dissectors
 * during PCAP analysis - nothing here is synthesized. Raw Ethernet/IP/TCP bytes
 * are not retained by the pipeline, so this shows the decoded protocol fields
 * (what an OT analyst acts on); where the dissector captured a value's bytes it
 * is shown as {@code value_hex}.
 */

// ---- helpers ---------------------------------------------------------------
function fmtTime(iso?: string): string {
  if (!iso) return '-';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
const endpoint = (ip?: string, port?: number | null) => `${ip || '?'}${port ? `:${port}` : ''}`;
const label = (k: string) => k.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
const truthy = (v: string) => v === 'true' || v === '1' || v === 'yes';
const fmtHex = (h: string) => {
  const s = h.replace(/^0x/i, '').replace(/\s+/g, '');
  if (!/^[0-9a-fA-F]+$/.test(s) || s.length < 2) return h;
  return (s.match(/.{1,2}/g) || []).join(' ').toUpperCase();
};

const protoColor: Record<string, string> = {
  MODBUS: 'bg-violet-50 text-violet-700 ring-violet-200',
  S7COMM: 'bg-sky-50 text-sky-700 ring-sky-200',
  IEC104: 'bg-amber-50 text-amber-700 ring-amber-200',
  DNP3: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
};
const protoChip = (p?: string) => protoColor[(p || '').toUpperCase()] || 'bg-slate-100 text-slate-600 ring-slate-200';

// Group decoded keys into Wireshark-like layers. Keys not listed fall into
// "Other" so nothing the dissector produced is ever hidden.
const SECTIONS: { title: string; keys: string[] }[] = [
  { title: 'PDU / session', keys: ['apci_type', 'pdu_kind', 'pdu_ref', 'direction', 'transaction_id', 'unit_id', 'send_seq', 'recv_seq', 'u_function', 'common_address', 'originator', 'cot', 'cot_name', 'num_objects', 'sq', 'test', 'negative', 'apdu_length', 'rosctr', 'rosctr_name', 'cotp_pdu_type', 'mei_type', 'is_setup'] },
  { title: 'Function', keys: ['function_code', 'function_name', 'type_id', 'is_command', 'is_write', 'is_exception', 'exception_code', 'exception_name', 'exception_status', 'has_error', 'error_class', 'error_code', 'is_plc_control', 'plc_action', 'is_block_transfer'] },
  { title: 'Data', keys: ['area', 'db_number', 'address', 'register_address', 'read_address', 'write_address', 'ioa', 'quantity', 'read_quantity', 'write_quantity', 'item_count', 'byte_count', 'length', 'data_length', 'param_length', 'transport_size', 'bit_offset', 'and_mask', 'or_mask', 'value', 'values', 'value_hex'] },
  { title: 'Integrity', keys: ['mbap_length_mismatch', 'tpkt_length_mismatch', 'apdu_length_mismatch'] },
];
const FLAG_KEYS = new Set(['mbap_length_mismatch', 'tpkt_length_mismatch', 'apdu_length_mismatch', 'has_error', 'is_exception']);

// ---- decoded-field layer tree ---------------------------------------------
const FieldRow: React.FC<{ k: string; v: string }> = ({ k, v }) => {
  const isFlag = FLAG_KEYS.has(k);
  const bad = isFlag && truthy(v);
  if (k === 'value_hex') {
    return (
      <tr className="odd:bg-white even:bg-slate-50/60">
        <td className="py-1.5 px-3 text-slate-500 align-top whitespace-nowrap w-[38%]">{label(k)}</td>
        <td className="py-1.5 px-3"><code className="text-[11px] font-mono text-slate-800 break-all bg-slate-900/90 text-slate-100 rounded px-1.5 py-0.5">{fmtHex(v)}</code></td>
      </tr>
    );
  }
  return (
    <tr className="odd:bg-white even:bg-slate-50/60">
      <td className="py-1.5 px-3 text-slate-500 align-top whitespace-nowrap w-[38%]">{label(k)}</td>
      <td className={`py-1.5 px-3 font-mono break-all ${bad ? 'text-rose-600 font-semibold' : 'text-slate-800'}`}>
        {String(v)}{bad ? ' ⚠' : ''}
      </td>
    </tr>
  );
};

const LayerTree: React.FC<{ fields: Record<string, string> }> = ({ fields }) => {
  const present = Object.keys(fields);
  if (present.length === 0) return <p className="text-xs text-slate-400">No decoded fields on this packet.</p>;
  const used = new Set<string>();
  const sections = SECTIONS.map((s) => {
    const rows = s.keys.filter((k) => fields[k] !== undefined);
    rows.forEach((k) => used.add(k));
    return { title: s.title, rows };
  }).filter((s) => s.rows.length > 0);
  const other = present.filter((k) => !used.has(k));
  if (other.length) sections.push({ title: 'Other', rows: other });

  return (
    <div className="space-y-2">
      {sections.map((s) => (
        <details key={s.title} open className="rounded-lg ring-1 ring-slate-200 overflow-hidden">
          <summary className="cursor-pointer select-none bg-slate-50 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
            {s.title} <span className="text-slate-300">({s.rows.length})</span>
          </summary>
          <table className="min-w-full text-xs">
            <tbody className="divide-y divide-slate-100">
              {s.rows.map((k) => <FieldRow key={k} k={k} v={fields[k]} />)}
            </tbody>
          </table>
        </details>
      ))}
    </div>
  );
};

// ---- function-code histogram (edge) ---------------------------------------
const FuncHistogram: React.FC<{ stats: FunctionCodeStat[] }> = ({ stats }) => {
  const total = stats.reduce((a, s) => a + s.count, 0);
  if (!total) return null;
  const top = [...stats].sort((a, b) => b.count - a.count).slice(0, 6);
  const max = Math.max(...top.map((s) => s.count));
  return (
    <div className="space-y-1.5">
      {top.map((s) => {
        const pct = (s.count / total) * 100;
        const rare = total >= 20 && pct < 2;
        return (
          <div key={`${s.protocol}-${s.functionCode}`} className="flex items-center gap-2 text-[11px]">
            <span className="w-28 truncate text-slate-600" title={s.functionName || s.functionCode}>{s.functionName || s.functionCode}</span>
            <span className="flex-1 h-2 rounded bg-slate-100 overflow-hidden">
              <span className="block h-full rounded bg-violet-400" style={{ width: `${(s.count / max) * 100}%` }} />
            </span>
            <span className="tabular-nums text-slate-500 w-10 text-right">{s.count}</span>
            {rare && <span className="text-[9px] font-bold text-amber-600">RARE</span>}
          </div>
        );
      })}
    </div>
  );
};

// ---- main ------------------------------------------------------------------
const DecodedPacketsPanel: React.FC = () => {
  const [events, setEvents] = useState<DpiEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [protocol, setProtocol] = useState<string>('ALL');
  const [kind, setKind] = useState<'all' | 'read' | 'write'>('all');
  const [query, setQuery] = useState<string>('');
  const [selected, setSelected] = useState<DpiEvent | null>(null);
  const [fields, setFields] = useState<Record<string, string> | null>(null);
  const [fieldsLoading, setFieldsLoading] = useState(false);
  const [edgeStats, setEdgeStats] = useState<FunctionCodeStat[]>([]);
  const [copied, setCopied] = useState(false);
  const timer = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    try {
      const page = await dpiService.search({ size: 120, protocol: protocol === 'ALL' ? undefined : protocol });
      setEvents(page.content);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load decoded packets');
    } finally {
      setLoading(false);
    }
  }, [protocol]);

  useEffect(() => {
    setLoading(true);
    void refresh();
    timer.current = window.setInterval(() => { void refresh(); }, 5000);
    return () => { if (timer.current) window.clearInterval(timer.current); };
  }, [refresh]);

  // Selected packet -> full decoded fields + edge histogram.
  useEffect(() => {
    if (!selected) { setFields(null); setEdgeStats([]); return; }
    let cancelled = false;
    setFieldsLoading(true);
    const loadFields = selected.dpiFieldsJson
      ? Promise.resolve(selected)
      : dpiService.getById(selected.id);
    loadFields
      .then((full) => { if (!cancelled) { try { setFields(full.dpiFieldsJson ? JSON.parse(full.dpiFieldsJson) : {}); } catch { setFields({}); } } })
      .catch(() => { if (!cancelled) setFields({}); })
      .finally(() => { if (!cancelled) setFieldsLoading(false); });
    dpiService.functionStats({ sourceIp: selected.sourceIp, destinationIp: selected.destinationIp })
      .then((s) => { if (!cancelled) setEdgeStats(s); })
      .catch(() => { if (!cancelled) setEdgeStats([]); });
    return () => { cancelled = true; };
  }, [selected]);

  const protocols = useMemo(() => {
    const set = new Set<string>();
    events.forEach((e) => e.protocol && set.add(e.protocol.toUpperCase()));
    return ['ALL', ...Array.from(set).sort()];
  }, [events]);

  // Client-side kind + IP filtering over the loaded window (instant, no refetch).
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return events.filter((e) => {
      if (kind === 'write' && !e.isWrite) return false;
      if (kind === 'read' && (e.isWrite || e.pduKind === 'write')) return false;
      if (q && !(`${e.sourceIp} ${e.destinationIp}`.toLowerCase().includes(q))) return false;
      return true;
    });
  }, [events, kind, query]);

  const stats = useMemo(() => {
    const endpoints = new Set<string>();
    let writes = 0, exceptions = 0;
    shown.forEach((e) => { endpoints.add(e.sourceIp); endpoints.add(e.destinationIp); if (e.isWrite) writes++; if (e.isException) exceptions++; });
    return { pdus: shown.length, endpoints: endpoints.size, writes, exceptions };
  }, [shown]);

  const copyJson = async () => {
    if (!selected) return;
    const payload = { ...selected, decoded: fields };
    try { await navigator.clipboard.writeText(JSON.stringify(payload, null, 2)); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* ignore */ }
  };

  const Stat: React.FC<{ label: string; value: React.ReactNode; tone?: string }> = ({ label: l, value, tone }) => (
    <div className="rounded-lg ring-1 ring-slate-200 bg-white px-3 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-slate-400">{l}</div>
      <div className={`text-base font-bold tabular-nums ${tone || 'text-slate-800'}`}>{value}</div>
    </div>
  );

  return (
    <Panel
      title="Decoded packets (deep inspection)"
      subtitle="Live dissected PDUs from ingested traffic. Select a packet for its full protocol tree - the OT analyst's view, not a raw byte dump."
      icon={<Icon.Search className="w-4 h-4" />}
    >
      {/* Stats strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
        <Stat label="PDUs shown" value={loading ? '-' : stats.pdus.toLocaleString()} />
        <Stat label="Endpoints" value={loading ? '-' : stats.endpoints.toLocaleString()} />
        <Stat label="Writes" value={loading ? '-' : stats.writes.toLocaleString()} tone="text-amber-600" />
        <Stat label="Exceptions" value={loading ? '-' : stats.exceptions.toLocaleString()} tone={stats.exceptions ? 'text-rose-600' : 'text-slate-800'} />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-1.5 mb-3">
        {protocols.map((p) => (
          <button key={p} onClick={() => { setProtocol(p); setSelected(null); }}
            className={`px-2.5 py-1 rounded-full text-[11px] font-semibold ring-1 transition ${protocol === p ? 'bg-slate-900 text-white ring-slate-900' : 'bg-white text-slate-600 ring-slate-200 hover:ring-slate-300'}`}>
            {p === 'ALL' ? 'All protocols' : p}
          </button>
        ))}
        <span className="mx-1 h-4 w-px bg-slate-200" />
        {(['all', 'read', 'write'] as const).map((k) => (
          <button key={k} onClick={() => setKind(k)}
            className={`px-2.5 py-1 rounded-full text-[11px] font-semibold ring-1 transition capitalize ${kind === k ? 'bg-violet-600 text-white ring-violet-600' : 'bg-white text-slate-600 ring-slate-200 hover:ring-slate-300'}`}>
            {k}
          </button>
        ))}
        <div className="flex items-center gap-1 ml-auto rounded-full ring-1 ring-slate-200 bg-white px-2.5 py-1">
          <Icon.Search className="w-3 h-3 text-slate-400" />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by IP"
            className="text-[11px] outline-none bg-transparent w-28 placeholder:text-slate-400" />
          {query && <button onClick={() => setQuery('')} className="text-slate-400 hover:text-slate-600 text-[11px]">✕</button>}
        </div>
        {error && <span className="text-[11px] text-amber-600 w-full">{error}</span>}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Packet list */}
        <div className="overflow-auto max-h-[56vh] rounded-lg ring-1 ring-slate-100">
          <table className="min-w-full text-xs">
            <thead className="sticky top-0 z-10 bg-white">
              <tr className="text-left text-[10px] uppercase tracking-wide text-slate-400 border-b border-slate-200">
                <th className="py-2 pr-3 pl-3">Time</th>
                <th className="py-2 pr-3">Source</th>
                <th className="py-2 pr-3">Destination</th>
                <th className="py-2 pr-3">Proto</th>
                <th className="py-2 pr-3">Function</th>
                <th className="py-2 pr-3">Info</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                Array.from({ length: 9 }).map((_, i) => (
                  <tr key={`pk-skel-${i}`}>
                    {Array.from({ length: 6 }).map((__, c) => (
                      <td key={c} className={`py-2 pr-3 ${c === 0 ? 'pl-3' : ''}`}>
                        <div className="h-3 w-full max-w-[90px] rounded bg-slate-200 animate-pulse" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : shown.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-xs text-slate-400 px-4">
                    {events.length === 0
                      ? 'No decoded packets yet. Ingest OT traffic (e.g. Modbus on the SPAN port) and dissected packets appear here.'
                      : 'No packets match the current filters.'}
                  </td>
                </tr>
              ) : (
                shown.map((e) => {
                  const isSel = selected?.id === e.id;
                  return (
                    <tr key={e.id} onClick={() => setSelected(e)}
                      className={`cursor-pointer ${isSel ? 'bg-violet-50' : e.isException ? 'bg-rose-50/40 hover:bg-rose-50' : 'hover:bg-slate-50'}`}>
                      <td className="py-2 pr-3 pl-3 text-slate-500 whitespace-nowrap font-mono">{fmtTime(e.eventTime)}</td>
                      <td className="py-2 pr-3 text-slate-700 font-mono whitespace-nowrap">{endpoint(e.sourceIp, e.sourcePort)}</td>
                      <td className="py-2 pr-3 text-slate-700 font-mono whitespace-nowrap">{endpoint(e.destinationIp, e.destinationPort)}</td>
                      <td className="py-2 pr-3">
                        <span className={`inline-flex px-1.5 py-0.5 rounded ring-1 text-[10px] font-semibold ${protoChip(e.protocol)}`}>{(e.protocol || '?').toUpperCase()}</span>
                      </td>
                      <td className="py-2 pr-3 text-slate-600 whitespace-nowrap">
                        {e.functionName || e.functionCode || '-'}
                        {e.isWrite ? <span className="ml-1 text-[9px] font-bold text-amber-600">WR</span> : null}
                        {e.isException ? <span className="ml-1 text-[9px] font-bold text-rose-600">EXC</span> : null}
                      </td>
                      <td className="py-2 pr-3 text-slate-500 truncate max-w-[200px]">{e.summary || '-'}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Detail pane - protocol tree */}
        <div className="rounded-lg ring-1 ring-slate-100 p-4 min-h-[220px]">
          {!selected ? (
            <div className="h-full flex items-center justify-center text-center text-xs text-slate-400 px-4">
              Select a packet on the left to inspect its protocol tree and decoded fields.
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`inline-flex px-2 py-0.5 rounded ring-1 text-[11px] font-semibold ${protoChip(selected.protocol)}`}>{(selected.protocol || '?').toUpperCase()}</span>
                <span className="text-sm font-semibold text-slate-800">{selected.functionName || selected.functionCode || 'PDU'}</span>
                {selected.isWrite ? <span className="px-1.5 py-0.5 rounded bg-amber-50 text-amber-700 ring-1 ring-amber-200 text-[10px] font-semibold">WRITE</span> : null}
                {selected.isException ? <span className="px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 ring-1 ring-rose-200 text-[10px] font-semibold">EXCEPTION</span> : null}
                <div className="ml-auto flex items-center gap-2">
                  <button onClick={copyJson} className="text-[11px] text-violet-700 font-semibold hover:text-violet-900">{copied ? 'Copied' : 'Copy JSON'}</button>
                  <button onClick={() => setSelected(null)} className="text-[11px] text-slate-400 hover:text-slate-600">Clear</button>
                </div>
              </div>

              {/* Connection header */}
              <div className="grid grid-cols-[1fr_auto_1fr] items-center gap-2 text-xs">
                <div className="rounded-lg bg-slate-50 ring-1 ring-slate-100 px-3 py-2 text-center">
                  <div className="text-[10px] uppercase tracking-wide text-slate-400">Source</div>
                  <div className="font-mono text-slate-700">{endpoint(selected.sourceIp, selected.sourcePort)}</div>
                </div>
                <span className="text-slate-300 font-bold text-sm" aria-hidden="true">&rarr;</span>
                <div className="rounded-lg bg-slate-50 ring-1 ring-slate-100 px-3 py-2 text-center">
                  <div className="text-[10px] uppercase tracking-wide text-slate-400">Destination</div>
                  <div className="font-mono text-slate-700">{endpoint(selected.destinationIp, selected.destinationPort)}</div>
                </div>
              </div>

              {selected.summary && (
                <div className="text-xs text-slate-600 bg-white ring-1 ring-slate-100 rounded-lg px-3 py-2">{selected.summary}</div>
              )}

              {/* Layered decoded fields */}
              <div>
                <div className="text-[10px] uppercase tracking-wide text-slate-400 mb-1.5">Protocol tree</div>
                {fieldsLoading ? (
                  <div className="h-28 w-full rounded-lg bg-slate-100 animate-pulse" />
                ) : fields ? (
                  <LayerTree fields={fields} />
                ) : (
                  <p className="text-xs text-slate-400">No decoded fields.</p>
                )}
              </div>

              {/* Edge function histogram */}
              {edgeStats.length > 0 && (
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-slate-400 mb-1.5">
                    Commands on {selected.sourceIp} to {selected.destinationIp}
                  </div>
                  <FuncHistogram stats={edgeStats} />
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
};

export default DecodedPacketsPanel;
