import React from 'react';
import { TtpMatrix, TtpTechnique } from '../../services/threatIntelService';

interface Props {
  matrix: TtpMatrix | null;
  emptyMessage?: string;
}

function heatBg(observationCount: number, confidence: number): string {
  if (!observationCount) return 'bg-slate-50 ring-slate-200 text-slate-500';
  const intensity = Math.min(1, (observationCount * 0.25) + (confidence / 200));
  if (intensity > 0.8) return 'bg-gradient-to-br from-rose-500 to-fuchsia-600 text-white ring-rose-400';
  if (intensity > 0.55) return 'bg-gradient-to-br from-fuchsia-500 to-violet-600 text-white ring-fuchsia-300';
  if (intensity > 0.3) return 'bg-gradient-to-br from-violet-400 to-violet-600 text-white ring-violet-300';
  return 'bg-violet-100 text-violet-800 ring-violet-200';
}

const TechniqueCell: React.FC<{ t: TtpTechnique }> = ({ t }) => {
  const hit = (t.observationCount || 0) > 0;
  return (
    <div
      className={`rounded-md p-2 ring-1 transition ${heatBg(t.observationCount || 0, t.confidence || 0)} ${hit ? 'shadow' : ''}`}
      title={hit ? `${t.id} · ${t.name} · ${t.observationCount} obs · conf ${t.confidence}%` : `${t.id} · not observed`}
    >
      <div className="flex items-start justify-between gap-1">
        <div className="min-w-0">
          <div className={`font-mono text-[10px] ${hit ? 'text-white/90' : 'text-slate-500'}`}>{t.id}</div>
          <div className={`text-[11px] font-semibold truncate ${hit ? 'text-white' : 'text-slate-700'}`}>{t.name}</div>
        </div>
        {hit && (
          <span className="text-[10px] font-bold rounded bg-white/20 px-1.5 py-0.5">
            {t.observationCount}×
          </span>
        )}
      </div>
      {hit && (
        <div className="mt-1 h-1 rounded-full bg-white/30 overflow-hidden">
          <div className="h-full bg-white/80" style={{ width: `${Math.max(8, t.confidence)}%` }} />
        </div>
      )}
    </div>
  );
};

const TtpMatrixCanvas: React.FC<Props> = ({ matrix, emptyMessage }) => {
  if (!matrix || !matrix.tactics || matrix.tactics.length === 0) {
    return (
      <div className="text-center py-10 text-sm text-slate-500">
        {emptyMessage || 'Select an attacker to view their ATT&CK coverage.'}
      </div>
    );
  }
  return (
    <div className="overflow-x-auto">
      <div className="flex gap-3 min-w-max pb-2">
        {matrix.tactics
          .slice()
          .sort((a, b) => a.order - b.order)
          .map(tac => {
            const observed = tac.techniques.filter(t => (t.observationCount || 0) > 0).length;
            const total = tac.techniques.length;
            return (
              <div key={tac.id} className="w-[180px] flex-shrink-0">
                <div className="flex items-baseline justify-between mb-2">
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-violet-600 font-semibold">#{tac.order}</div>
                    <div className="text-[12.5px] font-bold text-slate-900 leading-tight">{tac.name}</div>
                  </div>
                  <span className={`text-[10.5px] px-1.5 py-0.5 rounded font-semibold ring-1 ${observed > 0
                    ? 'bg-violet-600 text-white ring-violet-400'
                    : 'bg-slate-100 text-slate-500 ring-slate-200'}`}>
                    {observed}/{total}
                  </span>
                </div>
                <div className="space-y-1.5">
                  {tac.techniques.map(t => <TechniqueCell key={t.id} t={t} />)}
                </div>
              </div>
            );
          })}
      </div>
    </div>
  );
};

export default TtpMatrixCanvas;
