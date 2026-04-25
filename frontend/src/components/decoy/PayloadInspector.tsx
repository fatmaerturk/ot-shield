import React, { useState } from 'react';
import { PayloadDeep, PayloadField, EngagementEvent } from '../../services/decoyService';
import { severityStyle } from '../theme';

/**
 * Deep payload inspector for one EngagementEvent.
 *
 * Renders three tabs:
 *   1. Decoded   - structured semantic field table (per-protocol breakdown)
 *   2. Raw       - dual hex / ASCII view
 *   3. Anomaly   - flags + reasons + MITRE technique attached to the event
 *
 * Designed for industrial protocols (Modbus / S7 / DNP3 / EtherNet-IP / OPC UA)
 * where the SOC needs to see the exact register / DB / node / object that
 * the attacker touched, not just a textual summary.
 */

type Tab = 'decoded' | 'raw' | 'anomaly';

const PayloadInspector: React.FC<{ event: EngagementEvent | null }> = ({ event }) => {
  const [tab, setTab] = useState<Tab>('decoded');

  if (!event) {
    return (
      <div className="p-8 text-center text-sm text-slate-500">
        Select an event from the timeline to inspect its payload.
      </div>
    );
  }

  const p: PayloadDeep | null = event.payload || null;
  const sev = severityStyle(event.severity);

  return (
    <div>
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ring-1 ${sev.badge}`}>
              {event.severity}
            </span>
            <span className="px-2 py-0.5 rounded-full text-[11px] font-mono bg-slate-100 text-slate-700 ring-1 ring-slate-200">
              {event.direction === 'INBOUND' ? '→ DECOY' : '← ATTACKER'}
            </span>
            {p?.functionCodeHex && (
              <span className="px-2 py-0.5 rounded-full text-[11px] font-mono bg-violet-50 text-violet-700 ring-1 ring-violet-200">
                {p.functionCodeHex} {p.functionCodeName ? `· ${p.functionCodeName}` : ''}
              </span>
            )}
          </div>
          <h4 className="mt-2 text-base font-semibold text-slate-900 truncate" title={event.summary}>
            {p?.protocolOp || event.summary}
          </h4>
          <div className="mt-1 text-xs text-slate-500 flex items-center gap-3 flex-wrap">
            <span>{new Date(event.ts).toLocaleString()}</span>
            {p?.transactionId != null && <span>txn #{p.transactionId}</span>}
            {p?.unitId != null && <span>unit {p.unitId}</span>}
            {p?.addressRange && <span className="font-mono">{p.addressRange}</span>}
            {p?.byteCount != null && <span>{p.byteCount} B</span>}
          </div>
        </div>
      </div>

      {/* Tab strip */}
      <div className="mt-4 inline-flex p-1 bg-slate-100 rounded-xl ring-1 ring-slate-200">
        {([
          ['decoded', 'Decoded'],
          ['raw', 'Raw bytes'],
          ['anomaly', 'Anomaly · MITRE'],
        ] as [Tab, string][]).map(([k, label]) => (
          <button
            key={k}
            onClick={() => setTab(k)}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition ${
              tab === k ? 'bg-white text-violet-700 shadow-sm' : 'text-slate-500 hover:text-slate-700'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="mt-4">
        {tab === 'decoded' && <DecodedTable fields={p?.fields || []} />}
        {tab === 'raw' && <RawDual hex={p?.rawHex || ''} ascii={p?.rawAscii || ''} />}
        {tab === 'anomaly' && <AnomalyView event={event} />}
      </div>
    </div>
  );
};

const DecodedTable: React.FC<{ fields: PayloadField[] }> = ({ fields }) => {
  if (!fields.length) {
    return <div className="text-sm text-slate-500 italic">No structured fields parsed for this message.</div>;
  }
  return (
    <div className="overflow-x-auto rounded-xl ring-1 ring-slate-200">
      <table className="min-w-full text-sm">
        <thead className="bg-slate-50 text-[11px] uppercase tracking-wider text-slate-500">
          <tr>
            <th className="text-left px-3 py-2 font-semibold">Address / Node</th>
            <th className="text-left px-3 py-2 font-semibold">Type</th>
            <th className="text-left px-3 py-2 font-semibold">Value</th>
            <th className="text-left px-3 py-2 font-semibold">Hex</th>
            <th className="text-left px-3 py-2 font-semibold">Unit</th>
            <th className="text-left px-3 py-2 font-semibold">Flag</th>
          </tr>
        </thead>
        <tbody>
          {fields.map((f, i) => (
            <tr
              key={i}
              className={f.flagged ? 'bg-rose-50/60' : i % 2 ? 'bg-white' : 'bg-slate-50/40'}
            >
              <td className="px-3 py-2 font-mono text-xs text-slate-800">{f.name}</td>
              <td className="px-3 py-2 text-xs text-slate-500">{f.type}</td>
              <td className="px-3 py-2 font-mono text-slate-900">{f.value}</td>
              <td className="px-3 py-2 font-mono text-xs text-slate-500">{f.rawHex || '-'}</td>
              <td className="px-3 py-2 text-xs text-slate-500">{f.unit || '-'}</td>
              <td className="px-3 py-2">
                {f.flagged ? (
                  <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-rose-100 text-rose-700 ring-1 ring-rose-200">
                    flagged
                  </span>
                ) : (
                  <span className="text-[11px] text-slate-400">-</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {fields.some(f => f.flagged && f.anomalyReason) && (
        <div className="px-3 py-2 bg-rose-50 border-t border-rose-200 text-xs text-rose-800">
          <span className="font-semibold">Why flagged:</span>{' '}
          {fields.filter(f => f.flagged && f.anomalyReason).map(f => f.anomalyReason).join(' · ')}
        </div>
      )}
    </div>
  );
};

const RawDual: React.FC<{ hex: string; ascii: string }> = ({ hex, ascii }) => (
  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <div className="rounded-xl ring-1 ring-slate-200 bg-slate-900 text-slate-100 p-3">
      <div className="text-[11px] uppercase tracking-wider text-slate-400 mb-2">Hex</div>
      <pre className="text-xs font-mono whitespace-pre-wrap break-all leading-relaxed">{hex || '-'}</pre>
    </div>
    <div className="rounded-xl ring-1 ring-slate-200 bg-slate-50 p-3">
      <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-2">ASCII</div>
      <pre className="text-xs font-mono whitespace-pre-wrap break-all leading-relaxed text-slate-700">
        {ascii || '-'}
      </pre>
    </div>
  </div>
);

const AnomalyView: React.FC<{ event: EngagementEvent }> = ({ event }) => {
  const flags = event.payload?.anomalyFlags || [];
  const m = event.mitre;
  return (
    <div className="space-y-4">
      <div>
        <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-2">Anomaly flags</div>
        {flags.length ? (
          <div className="flex flex-wrap gap-2">
            {flags.map(f => (
              <span
                key={f}
                className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-rose-50 text-rose-700 ring-1 ring-rose-200"
              >
                {f.replaceAll('_', ' ')}
              </span>
            ))}
          </div>
        ) : (
          <div className="text-sm text-slate-500 italic">No anomalies detected on this message.</div>
        )}
      </div>

      <div>
        <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-2">MITRE ATT&amp;CK for ICS</div>
        {m ? (
          <div className="p-3 rounded-xl bg-violet-50 ring-1 ring-violet-200">
            <div className="text-xs text-violet-600 font-semibold tracking-wider uppercase">{m.tactic}</div>
            <div className="mt-1 text-sm font-semibold text-violet-900">
              {m.techniqueId} · {m.techniqueName}
            </div>
            <div className="mt-2 text-xs text-violet-700">Confidence: {m.confidence}%</div>
          </div>
        ) : (
          <div className="text-sm text-slate-500 italic">No technique mapped to this event.</div>
        )}
      </div>
    </div>
  );
};

export default PayloadInspector;
