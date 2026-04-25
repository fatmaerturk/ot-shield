import React, { useState } from 'react';
import {
  threatIntelService,
  IocExportFormat,
  IntelPushTarget,
  IocExportResult,
  IntelPushResult,
} from '../../services/threatIntelService';

interface Props {
  open: boolean;
  onClose: () => void;
  ips: string[]; // IPs to include; empty = all
}

const FORMATS: { value: IocExportFormat; label: string; hint: string }[] = [
  { value: 'STIX', label: 'STIX 2.1', hint: 'Structured Threat Information Expression bundle' },
  { value: 'CSV', label: 'CSV', hint: 'Spreadsheet-friendly row per attacker' },
  { value: 'PLAIN', label: 'Plain IP list', hint: 'One IP per line (firewall drop-in)' },
];

const TARGETS: { value: IntelPushTarget; label: string; hint: string }[] = [
  { value: 'SIEM', label: 'SIEM', hint: 'Send indicators to SIEM correlation engine' },
  { value: 'TAXII', label: 'TAXII', hint: 'Push as STIX bundle to a TAXII 2.1 collection' },
  { value: 'MISP', label: 'MISP', hint: 'Create a MISP event with attributes' },
];

const IocExportDrawer: React.FC<Props> = ({ open, onClose, ips }) => {
  const [format, setFormat] = useState<IocExportFormat>('STIX');
  const [target, setTarget] = useState<IntelPushTarget>('SIEM');
  const [reason, setReason] = useState('Routine intel push from OTShield decoy layer');
  const [endpoint, setEndpoint] = useState('https://siem.internal/api/ingest');
  const [busy, setBusy] = useState(false);
  const [exportResult, setExportResult] = useState<IocExportResult | null>(null);
  const [pushResult, setPushResult] = useState<IntelPushResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!open) return null;

  const runExport = async () => {
    setBusy(true); setError(null); setExportResult(null);
    try {
      const r = await threatIntelService.export({ format, attackerIps: ips, includeCampaigns: true, includeTtps: true });
      setExportResult(r);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  const runPush = async () => {
    setBusy(true); setError(null); setPushResult(null);
    try {
      const r = await threatIntelService.push({ target, endpoint, attackerIps: ips, reason });
      setPushResult(r);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  const downloadExport = () => {
    if (!exportResult) return;
    const blob = new Blob([exportResult.content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = exportResult.filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-stretch justify-end bg-black/40 backdrop-blur-sm">
      <div className="bg-white w-full max-w-md h-full shadow-2xl ring-1 ring-violet-200 flex flex-col">
        <div className="p-4 bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-[10px] uppercase tracking-wider text-white/80">Intel delivery</div>
              <div className="text-base font-bold">Export &amp; push IOCs</div>
            </div>
            <button onClick={onClose} className="text-white/80 hover:text-white text-xl leading-none">×</button>
          </div>
          <div className="mt-2 text-[11px] text-white/80">
            {ips.length === 0
              ? 'Scope: all known attackers'
              : `Scope: ${ips.length} selected attacker(s)`}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-5">
          {/* EXPORT */}
          <section>
            <h3 className="text-xs uppercase tracking-wider text-slate-500 font-semibold mb-2">Export bundle</h3>
            <div className="space-y-1.5">
              {FORMATS.map(f => (
                <label key={f.value} className={`flex items-start gap-2 p-2 rounded-lg ring-1 cursor-pointer ${format === f.value ? 'bg-violet-50 ring-violet-400' : 'ring-slate-200 hover:bg-slate-50'}`}>
                  <input
                    type="radio"
                    name="fmt"
                    checked={format === f.value}
                    onChange={() => setFormat(f.value)}
                    className="mt-1 accent-violet-600"
                  />
                  <div>
                    <div className="text-[13px] font-semibold text-slate-900">{f.label}</div>
                    <div className="text-[11px] text-slate-500">{f.hint}</div>
                  </div>
                </label>
              ))}
            </div>
            <button
              onClick={runExport}
              disabled={busy}
              className="mt-3 w-full px-3 py-2 rounded-lg bg-violet-600 hover:bg-violet-700 disabled:bg-slate-300 text-white font-semibold text-sm transition"
            >
              {busy ? 'Generating…' : 'Generate export'}
            </button>
            {exportResult && (
              <div className="mt-2 rounded-lg bg-emerald-50 ring-1 ring-emerald-200 p-2">
                <div className="flex items-center justify-between">
                  <div className="text-[12px] text-emerald-800">
                    {exportResult.iocCount} IOCs · {exportResult.filename}
                  </div>
                  <button onClick={downloadExport} className="text-[11px] font-semibold text-emerald-700 hover:text-emerald-900">
                    Download ↓
                  </button>
                </div>
                <pre className="mt-1.5 text-[10px] bg-slate-900 text-slate-100 rounded p-2 max-h-40 overflow-auto font-mono">
                  {exportResult.content.slice(0, 1200)}{exportResult.content.length > 1200 ? '\n...' : ''}
                </pre>
              </div>
            )}
          </section>

          {/* PUSH */}
          <section>
            <h3 className="text-xs uppercase tracking-wider text-slate-500 font-semibold mb-2">Push to external</h3>
            <div className="space-y-1.5">
              {TARGETS.map(t => (
                <label key={t.value} className={`flex items-start gap-2 p-2 rounded-lg ring-1 cursor-pointer ${target === t.value ? 'bg-fuchsia-50 ring-fuchsia-400' : 'ring-slate-200 hover:bg-slate-50'}`}>
                  <input
                    type="radio"
                    name="tgt"
                    checked={target === t.value}
                    onChange={() => setTarget(t.value)}
                    className="mt-1 accent-fuchsia-600"
                  />
                  <div>
                    <div className="text-[13px] font-semibold text-slate-900">{t.label}</div>
                    <div className="text-[11px] text-slate-500">{t.hint}</div>
                  </div>
                </label>
              ))}
            </div>
            <label className="block mt-3">
              <span className="text-[11px] text-slate-600 font-semibold">Endpoint</span>
              <input
                value={endpoint}
                onChange={e => setEndpoint(e.target.value)}
                className="mt-0.5 w-full rounded border border-slate-300 px-2 py-1 text-[12px] font-mono"
              />
            </label>
            <label className="block mt-2">
              <span className="text-[11px] text-slate-600 font-semibold">Justification</span>
              <textarea
                value={reason}
                onChange={e => setReason(e.target.value)}
                rows={2}
                className="mt-0.5 w-full rounded border border-slate-300 px-2 py-1 text-[12px]"
              />
            </label>
            <button
              onClick={runPush}
              disabled={busy}
              className="mt-3 w-full px-3 py-2 rounded-lg bg-fuchsia-600 hover:bg-fuchsia-700 disabled:bg-slate-300 text-white font-semibold text-sm transition"
            >
              {busy ? 'Pushing…' : `Push to ${target}`}
            </button>
            {pushResult && (
              <div className="mt-2 rounded-lg bg-emerald-50 ring-1 ring-emerald-200 p-2">
                <div className="text-[12px] text-emerald-800 font-semibold">
                  ✓ {pushResult.pushedIocs} IOC(s) accepted by {pushResult.target}
                </div>
                <div className="text-[11px] text-emerald-700 mt-0.5">Ref: {pushResult.externalRef}</div>
                <div className="text-[10.5px] text-slate-500 mt-0.5">{pushResult.message}</div>
              </div>
            )}
          </section>

          {error && (
            <div className="rounded-lg bg-rose-50 ring-1 ring-rose-200 p-2 text-[12px] text-rose-700">{error}</div>
          )}
        </div>
      </div>
    </div>
  );
};

export default IocExportDrawer;
