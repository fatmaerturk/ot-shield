import React, { useEffect, useMemo, useState } from 'react';
import { Icon, PageHero } from './theme';
import { engageService, EngageMatrix, EngageActivity } from '../services/engageService';

/**
 * MITRE Engage Coverage
 * ============================================================
 * The defender-side complement to ATT&CK for ICS. ATT&CK maps what the
 * adversary does; Engage maps the deception and adversary-engagement techniques
 * we apply against them. Each activity is marked ACTIVE or AVAILABLE from live
 * state - decoys running, honeytokens planted and tripped, telemetry collected,
 * responses taken, cases opened - so the matrix is proof, not aspiration.
 */

const GOAL_META: Record<string, { blurb: string; accent: string; head: string; dot: string }> = {
  Prepare: {
    blurb: 'Plan & set up the engagement',
    accent: 'ring-sky-200',
    head: 'from-sky-500 to-cyan-500',
    dot: 'bg-sky-500',
  },
  Expose: {
    blurb: 'Reveal the adversary',
    accent: 'ring-violet-200',
    head: 'from-violet-500 to-fuchsia-500',
    dot: 'bg-violet-500',
  },
  Elicit: {
    blurb: 'Learn their TTPs',
    accent: 'ring-fuchsia-200',
    head: 'from-fuchsia-500 to-pink-500',
    dot: 'bg-fuchsia-500',
  },
  Affect: {
    blurb: 'Change their course',
    accent: 'ring-rose-200',
    head: 'from-rose-500 to-orange-500',
    dot: 'bg-rose-500',
  },
  Understand: {
    blurb: 'Threat-informed decisions',
    accent: 'ring-emerald-200',
    head: 'from-emerald-500 to-teal-500',
    dot: 'bg-emerald-500',
  },
};

const Engage: React.FC = () => {
  const [data, setData] = useState<EngageMatrix | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      setData(await engageService.matrix());
      setError(null);
    } catch {
      setError('Could not load the Engage matrix. Is the backend running?');
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);

  const byGoal = useMemo(() => {
    const m: Record<string, EngageActivity[]> = {};
    (data?.activities ?? []).forEach((a) => {
      (m[a.goal] = m[a.goal] || []).push(a);
    });
    return m;
  }, [data]);

  const goals = data?.goals ?? [];

  return (
    <div className="space-y-6">
      <PageHero
        eyebrow="DEFENSIVE DECEPTION · MITRE ENGAGE"
        icon={<Icon.Shield className="w-3.5 h-3.5" />}
        title="MITRE Engage Coverage"
        subtitle="The defender-side complement to ATT&CK for ICS. Which deception and adversary-engagement techniques OTShield is actually exercising, proven with live first-party evidence."
        stats={data ? [
          { label: 'Engage coverage', value: `${data.summary.coveragePct}%`, sub: `${data.summary.activeActivities}/${data.summary.totalActivities} activities active` },
          { label: 'Goals engaged', value: goals.filter((g) => (data.summary.byGoal[g]?.active ?? 0) > 0).length, sub: `of ${goals.length} strategic goals` },
          { label: 'Framework', value: 'Engage', sub: 'mapped from live state' },
        ] : []}
        actions={
          <button
            onClick={load}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-white bg-white/10 hover:bg-white/20 ring-1 ring-white/20 backdrop-blur-sm"
          >
            <Icon.Refresh className="w-4 h-4" /> Refresh
          </button>
        }
      />

      {error && (
        <div className="p-4 rounded-2xl bg-rose-50 ring-1 ring-rose-200 text-rose-700 text-sm">{error}</div>
      )}

      {/* Engage matrix: one column per strategic goal */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
        {goals.map((goal) => {
          const meta = GOAL_META[goal] ?? GOAL_META.Expose;
          const gs = data?.summary.byGoal[goal];
          const acts = byGoal[goal] ?? [];
          return (
            <div key={goal} className={`rounded-2xl bg-white ring-1 ${meta.accent} shadow-sm overflow-hidden flex flex-col`}>
              <div className={`px-4 py-3 bg-gradient-to-r ${meta.head} text-white`}>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold tracking-tight">{goal}</span>
                  {gs && (
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-white/20">
                      {gs.active}/{gs.total}
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-white/85 mt-0.5">{meta.blurb}</div>
              </div>

              <div className="p-2.5 space-y-2 flex-1">
                {acts.map((a) => {
                  const active = a.status === 'ACTIVE';
                  return (
                    <div
                      key={a.activity}
                      className={`rounded-xl p-2.5 ring-1 transition ${
                        active ? 'bg-slate-50 ring-slate-200' : 'bg-white ring-slate-200 opacity-60'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <span className="text-[13px] font-semibold text-slate-900 leading-tight">{a.activity}</span>
                        <span
                          className={`mt-0.5 flex-shrink-0 w-2 h-2 rounded-full ${
                            active ? meta.dot : 'bg-slate-300'
                          }`}
                          title={a.status}
                        />
                      </div>
                      <div className="text-[11px] text-slate-500 mt-0.5 leading-snug">{a.otShieldFeature}</div>
                      <div
                        className={`mt-1.5 text-[10px] font-semibold px-2 py-0.5 rounded-md inline-block ${
                          active ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-100 text-slate-400'
                        }`}
                        title={a.description}
                      >
                        {active ? a.evidence : 'awaiting activity'}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {!data && !error && (
        <div className="text-sm text-slate-500 py-10 text-center">Loading Engage matrix…</div>
      )}
    </div>
  );
};

export default Engage;
