import React from 'react';
import { CampaignCluster } from '../../services/threatIntelService';

interface Props {
  campaigns: CampaignCluster[];
  relatedIps: string[];
  onSelectRelated?: (ip: string) => void;
}

const CampaignPanel: React.FC<Props> = ({ campaigns, relatedIps, onSelectRelated }) => {
  if (!campaigns.length && !relatedIps.length) {
    return (
      <div className="text-center text-sm text-slate-500 py-8">
        No campaign membership detected yet for this attacker.
      </div>
    );
  }
  return (
    <div className="space-y-3">
      {campaigns.map(c => (
        <div key={c.id} className="rounded-lg bg-gradient-to-br from-violet-50 to-fuchsia-50 ring-1 ring-violet-200 p-3">
          <div className="flex items-start justify-between gap-2">
            <div>
              <div className="text-[10px] uppercase tracking-wider text-violet-600 font-semibold">Campaign</div>
              <div className="text-sm font-bold text-slate-900">{c.name}</div>
            </div>
            <div className="text-right">
              <div className="text-[10px] text-slate-500">Severity</div>
              <div className="text-sm font-bold text-rose-600">{c.severityScore}</div>
            </div>
          </div>
          <p className="mt-1.5 text-[11.5px] text-slate-600 leading-relaxed">{c.summary}</p>
          <div className="mt-2 flex flex-wrap gap-1">
            {c.topTechniques.map(t => (
              <span key={t} className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-violet-600 text-white">{t}</span>
            ))}
          </div>
          <div className="mt-2 flex items-center justify-between text-[10.5px] text-slate-500">
            <span>{c.memberCount} IPs · ASNs {c.sharedAsns.join(', ') || 'mixed'}</span>
            <span className="font-mono text-violet-700">{c.fingerprintHash}</span>
          </div>
        </div>
      ))}

      {relatedIps.length > 0 && (
        <div className="rounded-lg bg-white ring-1 ring-slate-200 p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1.5">Related IPs</div>
          <div className="flex flex-wrap gap-1.5">
            {relatedIps.map(ip => (
              <button
                key={ip}
                onClick={() => onSelectRelated?.(ip)}
                className="font-mono text-[11px] px-2 py-0.5 rounded bg-slate-100 hover:bg-violet-100 hover:text-violet-700 text-slate-700 transition"
              >
                {ip}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default CampaignPanel;
