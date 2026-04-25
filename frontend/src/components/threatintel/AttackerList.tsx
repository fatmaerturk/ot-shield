import React from 'react';
import { AttackerIntelSummary } from '../../services/threatIntelService';

interface Props {
  items: AttackerIntelSummary[];
  selectedIp?: string | null;
  onSelect: (ip: string) => void;
}

const scoreClass = (s: number) => {
  if (s >= 80) return 'bg-rose-100 text-rose-700 ring-rose-200';
  if (s >= 60) return 'bg-orange-100 text-orange-700 ring-orange-200';
  if (s >= 40) return 'bg-amber-100 text-amber-700 ring-amber-200';
  return 'bg-emerald-100 text-emerald-700 ring-emerald-200';
};

const countryFlag = (cc: string): string => {
  if (!cc || cc.length !== 2) return '🌐';
  const base = 127397;
  return String.fromCodePoint(...Array.from(cc.toUpperCase()).map(c => base + c.charCodeAt(0)));
};

const Sparkline: React.FC<{ values: number[] }> = ({ values }) => {
  const max = Math.max(1, ...values);
  const w = 80;
  const h = 18;
  const step = w / Math.max(1, values.length - 1);
  const pts = values.map((v, i) => {
    const x = i * step;
    const y = h - (v / max) * h;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width={w} height={h} className="overflow-visible">
      <polyline fill="none" stroke="#a855f7" strokeWidth={1.5} points={pts} strokeLinecap="round" strokeLinejoin="round" />
      {values.map((v, i) => v > 0 && (
        <circle key={i} cx={i * step} cy={h - (v / max) * h} r={1.4} fill="#d946ef" />
      ))}
    </svg>
  );
};

const AttackerList: React.FC<Props> = ({ items, selectedIp, onSelect }) => {
  if (!items.length) {
    return <div className="text-center py-10 text-sm text-slate-500">No attackers match the current filters.</div>;
  }
  return (
    <div className="space-y-2">
      {items.map(a => {
        const sel = a.ip === selectedIp;
        return (
          <button
            key={a.ip}
            onClick={() => onSelect(a.ip)}
            className={`w-full text-left rounded-lg p-3 ring-1 transition ${sel
              ? 'bg-gradient-to-br from-violet-50 to-fuchsia-50 ring-violet-400 shadow-sm'
              : 'bg-white ring-violet-100 hover:ring-violet-300 hover:bg-violet-50/40'}`}
          >
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <span className="text-lg leading-none">{countryFlag(a.country)}</span>
                <div className="min-w-0">
                  <div className="font-mono text-[12.5px] text-slate-900 font-bold truncate">{a.ip}</div>
                  <div className="text-[10.5px] text-slate-500 truncate">
                    {a.asn || 'ASN?'} · {a.asnName || a.countryName}
                  </div>
                </div>
              </div>
              <span className={`px-2 py-0.5 rounded-full text-[11px] font-bold ring-1 ${scoreClass(a.threatScore || 0)}`}>
                {a.threatScore || 0}
              </span>
            </div>

            <div className="mt-1.5 flex items-center justify-between gap-2">
              <div className="flex flex-wrap gap-1">
                {(a.tags || []).slice(0, 3).map(t => (
                  <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-violet-100 text-violet-700">
                    {t}
                  </span>
                ))}
                {a.blocked && <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-600 text-white">BLOCKED</span>}
                {a.quarantined && <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500 text-white">QUAR</span>}
              </div>
              <Sparkline values={a.activitySparkline || []} />
            </div>

            <div className="mt-1 flex items-center justify-between text-[10.5px] text-slate-500">
              <span>
                {a.engagementCount} engagements · {a.distinctDecoysHit} decoys
              </span>
              <span className="truncate ml-2">
                {a.dominantTactic || '-'} · {a.distinctTechniques || 0} tech
              </span>
            </div>
          </button>
        );
      })}
    </div>
  );
};

export default AttackerList;
