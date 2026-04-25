import React, { useEffect, useMemo, useState } from 'react';
import { Engagement } from '../../services/decoyService';
import {
  threatIntelService,
  AttackerIntelDetail,
  BehavioralFingerprint,
} from '../../services/threatIntelService';

/**
 * EngagementMitreChain
 * --------------------------------------------------------------
 * For a given engagement, fetches the attacker's intel detail and renders:
 *   - A compact behavioral fingerprint header (pattern, rep/night/burst scores,
 *     dominant protocols, anomalies).
 *   - The ATT&CK for ICS kill chain timeline restricted to the techniques
 *     actually observed for THIS attacker, ordered by tactic.order.
 *   - For each observed technique: technique id+name, observation count,
 *     confidence bar, evidence event ids (clickable to focus them).
 *
 * The matrix call returns the FULL matrix filled for this attacker; we then
 * filter to techniques with observationCount > 0 before rendering - so the
 * timeline stays tight and readable even when coverage is broad.
 */

interface Props {
  engagement: Engagement;
  onSelectEvent?: (eventId: string) => void;
}

const EngagementMitreChain: React.FC<Props> = ({ engagement, onSelectEvent }) => {
  const [detail, setDetail] = useState<AttackerIntelDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    threatIntelService.getAttacker(engagement.attackerIp)
      .then(d => { if (!cancelled) setDetail(d); })
      .catch(e => { if (!cancelled) setError(String(e?.message || e)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [engagement.attackerIp]);

  // engagement-specific event ids (so we can highlight which evidence came from THIS engagement)
  const ownEventIds = useMemo(
    () => new Set((engagement.events || []).map(ev => ev.id)),
    [engagement.events],
  );

  if (loading) {
    return <div className="text-sm text-slate-500 py-6 text-center">Correlating TTPs for {engagement.attackerIp}…</div>;
  }
  if (error) {
    return <div className="text-sm text-rose-600 py-6 text-center">Intel lookup failed: {error}</div>;
  }
  if (!detail) {
    return <div className="text-sm text-slate-500 py-6 text-center">No intel yet for this attacker.</div>;
  }

  const tactics = detail.ttpMatrix.tactics
    .slice()
    .sort((a, b) => a.order - b.order)
    .map(t => ({
      ...t,
      observed: t.techniques.filter(tc => (tc.observationCount || 0) > 0),
    }))
    .filter(t => t.observed.length > 0);

  return (
    <div className="space-y-4">
      <FingerprintHeader fp={detail.fingerprint} summary={detail.summary.dominantTactic || ''} />

      {tactics.length === 0 ? (
        <div className="text-center text-sm text-slate-500 py-6">
          No MITRE ATT&amp;CK techniques have been correlated for this attacker yet.
        </div>
      ) : (
        <ol className="relative border-l-2 border-violet-200 pl-5 space-y-4">
          {tactics.map(tac => (
            <li key={tac.id} className="relative">
              <span className="absolute -left-[27px] top-1 w-4 h-4 rounded-full bg-gradient-to-br from-violet-500 to-fuchsia-500 ring-4 ring-white shadow" />
              <div className="flex items-baseline gap-2">
                <span className="text-[10px] uppercase tracking-wider text-violet-500 font-semibold">Tactic #{tac.order}</span>
                <span className="text-sm font-bold text-slate-900">{tac.name}</span>
                <span className="text-[11px] text-slate-400">({tac.id})</span>
              </div>
              <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-2">
                {tac.observed.map(tech => (
                  <TechniqueCard
                    key={tech.id}
                    tech={tech}
                    engagementOwnedIds={ownEventIds}
                    onSelectEvent={onSelectEvent}
                  />
                ))}
              </div>
            </li>
          ))}
        </ol>
      )}

      {detail.iocHighlights && detail.iocHighlights.length > 0 && (
        <div className="mt-4 rounded-lg bg-gradient-to-br from-violet-50 to-fuchsia-50 ring-1 ring-violet-200 p-3">
          <div className="text-[10px] uppercase tracking-wider text-violet-600 font-semibold mb-1.5">IOC highlights</div>
          <ul className="space-y-1">
            {detail.iocHighlights.map((h, i) => (
              <li key={i} className="text-[12px] text-slate-700 flex items-start gap-2">
                <span className="mt-1 w-1.5 h-1.5 rounded-full bg-fuchsia-500 shrink-0" />
                <span>{h}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

const FingerprintHeader: React.FC<{ fp: BehavioralFingerprint; summary: string }> = ({ fp, summary }) => {
  const topProtocols = Object.entries(fp.protocolMix || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3);
  return (
    <div className="rounded-lg bg-gradient-to-br from-violet-600 to-fuchsia-600 text-white p-3 ring-1 ring-white/20 shadow">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-white/80 font-semibold">Behavioral fingerprint</div>
          <div className="text-sm font-bold">{fp.pattern || 'Unclassified'}</div>
        </div>
        <div className="text-right">
          <div className="text-[10px] uppercase tracking-wider text-white/70">Hash</div>
          <div className="font-mono text-xs bg-white/20 rounded px-2 py-0.5">{fp.hash}</div>
        </div>
      </div>

      <div className="mt-2 grid grid-cols-3 gap-2">
        <ScoreBar label="Repetition" value={fp.repetitionScore} />
        <ScoreBar label="Nocturnal" value={fp.nightRatio} />
        <ScoreBar label="Burstiness" value={fp.burstiness} />
      </div>

      <div className="mt-2 flex flex-wrap gap-1.5 text-[11px]">
        {topProtocols.map(([p, c]) => (
          <span key={p} className="bg-white/20 rounded-full px-2 py-0.5">
            {p} · {c}
          </span>
        ))}
        {summary && (
          <span className="ml-auto bg-white/25 rounded-full px-2 py-0.5">dominant: {summary}</span>
        )}
      </div>

      {fp.notableAnomalies && fp.notableAnomalies.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1 text-[10.5px]">
          {fp.notableAnomalies.slice(0, 4).map(a => (
            <span key={a} className="bg-rose-500/30 ring-1 ring-rose-200/40 rounded px-1.5 py-0.5">
              ⚠ {a}
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

const ScoreBar: React.FC<{ label: string; value: number }> = ({ label, value }) => {
  const v = Math.max(0, Math.min(100, value || 0));
  return (
    <div className="bg-white/10 rounded-md px-2 py-1">
      <div className="flex items-center justify-between text-[10px] text-white/80">
        <span>{label}</span>
        <span className="font-bold">{v}</span>
      </div>
      <div className="mt-0.5 h-1.5 rounded-full bg-white/15 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-amber-200 to-rose-300"
          style={{ width: `${v}%` }}
        />
      </div>
    </div>
  );
};

const TechniqueCard: React.FC<{
  tech: { id: string; name: string; observationCount: number; confidence: number; evidenceEventIds: string[] };
  engagementOwnedIds: Set<string>;
  onSelectEvent?: (id: string) => void;
}> = ({ tech, engagementOwnedIds, onSelectEvent }) => {
  const own = tech.evidenceEventIds.filter(id => engagementOwnedIds.has(id));
  return (
    <div className="rounded-md bg-white ring-1 ring-violet-100 hover:ring-violet-300 p-2.5 transition">
      <div className="flex items-center justify-between">
        <div className="flex items-baseline gap-1.5">
          <span className="font-mono text-[10.5px] text-violet-700 font-bold">{tech.id}</span>
          <span className="text-[12.5px] text-slate-900 font-semibold truncate">{tech.name}</span>
        </div>
        <span className="text-[10px] text-slate-500">{tech.observationCount}×</span>
      </div>
      <div className="mt-1.5 h-1 rounded-full bg-slate-100 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-violet-500 to-fuchsia-500"
          style={{ width: `${Math.max(6, tech.confidence)}%` }}
        />
      </div>
      <div className="mt-1 flex items-center justify-between text-[10px]">
        <span className="text-slate-500">conf {tech.confidence}%</span>
        {own.length > 0 && onSelectEvent ? (
          <button
            onClick={() => onSelectEvent(own[0])}
            className="text-violet-600 hover:text-violet-800 font-semibold"
          >
            focus in this engagement →
          </button>
        ) : (
          <span className="text-slate-400">cross-engagement evidence</span>
        )}
      </div>
    </div>
  );
};

export default EngagementMitreChain;
