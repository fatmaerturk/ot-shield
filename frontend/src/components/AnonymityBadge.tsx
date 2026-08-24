import React from 'react';
import { AttackerIntelSummary } from '../services/threatIntelService';

type Cat = NonNullable<AttackerIntelSummary['anonymityCategory']>;

const STYLE: Record<Cat, { cls: string; icon: string }> = {
  TOR_EXIT:           { cls: 'bg-purple-50 text-purple-700 ring-purple-200', icon: '🧅' },
  VPN_PROVIDER:       { cls: 'bg-rose-50 text-rose-700 ring-rose-200', icon: '🛡' },
  HOSTING_DATACENTER: { cls: 'bg-amber-50 text-amber-700 ring-amber-200', icon: '🖥' },
  RESIDENTIAL_ISP:    { cls: 'bg-emerald-50 text-emerald-700 ring-emerald-200', icon: '🏠' },
  INTERNAL:           { cls: 'bg-slate-100 text-slate-500 ring-slate-200', icon: '🔒' },
  NOT_ASSESSED:       { cls: 'bg-slate-50 text-slate-400 ring-slate-200', icon: '—' },
};

/**
 * Renders the attacker's connection-nature classification as a compact badge.
 * The full honest caveat (from the backend) is exposed via the native tooltip.
 */
const AnonymityBadge: React.FC<{ a: Pick<AttackerIntelSummary, 'anonymityCategory' | 'anonymityLabel' | 'anonymityConfidence' | 'anonymityNote'>; }> = ({ a }) => {
  const cat = (a.anonymityCategory || 'NOT_ASSESSED') as Cat;
  const st = STYLE[cat] || STYLE.NOT_ASSESSED;
  const label = a.anonymityLabel || 'Not assessed';
  const conf = a.anonymityConfidence && a.anonymityConfidence !== 'NONE' ? a.anonymityConfidence.toLowerCase() : '';
  const title = [label, conf && `confidence: ${conf}`, a.anonymityNote].filter(Boolean).join('\n');
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold ring-1 whitespace-nowrap ${st.cls}`}
    >
      <span aria-hidden>{st.icon}</span>
      {label}
    </span>
  );
};

export default AnonymityBadge;
