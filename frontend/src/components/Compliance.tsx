import React, { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence, Variants } from 'framer-motion';

// =====================================================================
// NIS2 Directive (EU 2022/2555) Compliance Page
// Real, working compliance posture driven by /api/compliance/nis2/posture.
// Four tabs:
//   1. Article 21 Measures - status board for the 10 mandatory measures
//   2. Incident Reporting - Article 23 24h/72h/1m clock per alert
//   3. Evidence Library - telemetry artifacts cross-referenced to articles
//   4. Self-Assessment - interactive questionnaire with gap analysis
// =====================================================================

interface OrgProfile {
  name: string; sector: string; entityType: string;
  country: string; nis2CompliantSince: string;
}
interface PostureScore {
  score: number; trendDelta: number; classification: string;
}
interface Kpis {
  openFindings: number; criticalFindings: number;
  reportableIncidents: number; reportableOverdue: number;
  daysToNextSelfAudit: number; evidenceArtifacts: number;
}
interface Article21Measure {
  id: string; title: string; description: string;
  score: number; status: string; evidenceIds: string[];
  currentState: string; nextAction: string;
}
interface ReportableIncident {
  alertId: string; title: string; severity: string;
  sourceIp: string | null; protocol: string | null;
  detectedAt: string | null;
  earlyWarningDeadline: string | null; earlyWarningStatus: string;
  incidentReportDeadline: string | null; incidentReportStatus: string;
  finalReportDeadline: string | null;
  status: string; recommendedAction: string;
}
interface EvidenceArtifact {
  id: string; type: string; article: string;
  description: string; timestamp: string | null;
}
interface EvidenceLibrary {
  byArticle: Record<string, number>;
  totalArtifacts: number; retentionMonths: number;
  oldestArtifact: string | null;
  recentArtifacts: EvidenceArtifact[];
}
interface SelfAssessmentSection {
  id: string; title: string;
  questions: Array<{ id: string; question: string; weight: number }>;
}
interface RetentionPolicy {
  requiredMonths: number; currentRetention: number; status: string;
}
interface PostureResponse {
  organization: OrgProfile;
  postureScore: PostureScore;
  kpis: Kpis;
  article21Measures: Article21Measure[];
  reportableIncidents: ReportableIncident[];
  evidenceLibrary: EvidenceLibrary;
  selfAssessment: SelfAssessmentSection[];
  retentionPolicy: RetentionPolicy;
}

const containerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.06, delayChildren: 0.04 } },
};
const cardVariants: Variants = {
  hidden: { opacity: 0, y: 16 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 120, damping: 16 } },
};

const statusBadge = (status: string) => {
  switch (status) {
    case 'COMPLIANT': return 'bg-emerald-50 text-emerald-700 ring-emerald-200';
    case 'PARTIAL': return 'bg-amber-50 text-amber-700 ring-amber-200';
    case 'NON_COMPLIANT': return 'bg-rose-50 text-rose-700 ring-rose-200';
    default: return 'bg-slate-50 text-slate-600 ring-slate-200';
  }
};

const scoreColor = (score: number) => {
  if (score >= 85) return 'from-emerald-500 to-teal-500';
  if (score >= 70) return 'from-violet-500 to-fuchsia-500';
  if (score >= 50) return 'from-amber-500 to-orange-500';
  return 'from-rose-500 to-fuchsia-500';
};

const formatDateShort = (iso: string | null): string => {
  if (!iso) return '-';
  return iso.replace('T', ' ').slice(0, 16);
};

const formatTimeRemaining = (deadline: string | null): string => {
  if (!deadline) return '-';
  const t = new Date(deadline).getTime();
  const diff = t - Date.now();
  if (diff < 0) {
    const h = Math.abs(Math.floor(diff / 3600000));
    return `${h}h overdue`;
  }
  const h = Math.floor(diff / 3600000);
  if (h < 24) return `${h}h left`;
  const d = Math.floor(h / 24);
  return `${d}d left`;
};

const AnimatedNumber: React.FC<{ value: number; suffix?: string; duration?: number }> = ({
  value, suffix = '', duration = 900,
}) => {
  const [d, setD] = useState(0);
  useEffect(() => {
    let raf = 0; let start: number | null = null;
    const tick = (now: number) => {
      if (start === null) start = now;
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setD(Math.round(value * eased));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value, duration]);
  return <>{d.toLocaleString()}{suffix}</>;
};

const Compliance: React.FC = () => {
  const [data, setData] = useState<PostureResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'measures' | 'incidents' | 'evidence' | 'assessment'>('measures');
  const [expandedMeasure, setExpandedMeasure] = useState<string | null>(null);
  const [earlyWarning, setEarlyWarning] = useState<any>(null);
  const [answers, setAnswers] = useState<Record<string, 'YES' | 'NO' | 'PARTIAL' | null>>({});

  useEffect(() => {
    let cancel = false;
    const load = async () => {
      try {
        const r = await fetch('http://localhost:8080/api/compliance/nis2/posture');
        if (!r.ok) {
          if (!cancel) { setError(`Backend HTTP ${r.status}`); setLoading(false); }
          return;
        }
        const d = (await r.json()) as PostureResponse;
        if (!cancel) { setData(d); setLoading(false); }
      } catch (e: any) {
        if (!cancel) { setError(e?.message ?? 'Network error'); setLoading(false); }
      }
    };
    load();
    const t = window.setInterval(load, 60000);
    return () => { cancel = true; window.clearInterval(t); };
  }, []);

  const assessmentScore = useMemo(() => {
    if (!data) return { answered: 0, total: 0, score: 0 };
    let total = 0, yes = 0, partial = 0, answered = 0;
    data.selfAssessment.forEach((s) => s.questions.forEach((q) => {
      total++;
      const a = answers[q.id];
      if (a) answered++;
      if (a === 'YES') yes++;
      else if (a === 'PARTIAL') partial++;
    }));
    const score = total > 0 ? Math.round(((yes + partial * 0.5) / total) * 100) : 0;
    return { answered, total, score };
  }, [data, answers]);

  const generateEarlyWarning = async (alertId: string) => {
    try {
      const r = await fetch(`http://localhost:8080/api/compliance/nis2/early-warning/${alertId}`);
      if (r.ok) setEarlyWarning(await r.json());
    } catch { /* noop */ }
  };

  if (loading) {
    return (
      <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-10 text-center">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1.2, repeat: Infinity, ease: 'linear' }}
          className="w-12 h-12 mx-auto mb-3 rounded-full border-4 border-violet-200 border-t-violet-600"
        />
        <p className="text-sm text-slate-500">Loading NIS2 compliance posture…</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="bg-rose-50 rounded-2xl ring-1 ring-rose-200 p-6">
        <p className="text-sm text-rose-800 font-semibold">Failed to load compliance data</p>
        <p className="text-xs text-rose-700 mt-1">{error}</p>
      </div>
    );
  }

  return (
    <motion.div className="space-y-6" variants={containerVariants} initial="hidden" animate="visible">
      {/* Hero */}
      <motion.div
        variants={cardVariants}
        className="relative overflow-hidden rounded-2xl p-8 md:p-10 text-white"
        style={{ background: 'linear-gradient(135deg, #1e1b4b 0%, #4c1d95 45%, #7c3aed 100%)' }}
      >
        <div className="absolute -top-20 -right-20 w-72 h-72 rounded-full bg-fuchsia-500/20 blur-3xl" />
        <div className="absolute -bottom-10 -left-10 w-60 h-60 rounded-full bg-violet-400/10 blur-3xl" />
        <div className="relative flex flex-col lg:flex-row lg:items-end lg:justify-between gap-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 ring-1 ring-white/20 text-xs font-semibold tracking-wider backdrop-blur-sm mb-4">
              EU 2022/2555 · NIS2 DIRECTIVE
            </div>
            <h1 className="text-3xl md:text-4xl font-bold leading-tight">
              NIS2 Compliance Posture
              <span className="block text-violet-100/90 font-medium text-lg md:text-xl mt-2">
                {data.organization.name} · {data.organization.sector} · {data.organization.country}
              </span>
              <span className="block mt-3 text-sm text-violet-100/70">
                Live posture computed from honeypot telemetry, alerts, and incident timelines.
                NIS2 deadline: <strong>October 17, 2024</strong> (in force).
              </span>
            </h1>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-right">
              <p className="text-xs uppercase tracking-wider text-violet-100/70 font-semibold">Posture</p>
              <p className="text-5xl font-bold tabular-nums">
                <AnimatedNumber value={data.postureScore.score} suffix="%" />
              </p>
              <p className="text-xs text-violet-100/80 mt-0.5">
                {data.postureScore.classification}
                {data.postureScore.trendDelta !== 0 && (
                  <span className={`ml-2 ${data.postureScore.trendDelta < 0 ? 'text-rose-300' : 'text-emerald-300'}`}>
                    {data.postureScore.trendDelta > 0 ? '▲' : '▼'} {Math.abs(data.postureScore.trendDelta)}%
                  </span>
                )}
              </p>
            </div>
          </div>
        </div>
      </motion.div>

      {/* KPI strip */}
      <motion.div variants={cardVariants} className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'Open findings', value: data.kpis.openFindings, sub: `${data.kpis.criticalFindings} critical`, color: 'from-violet-500 to-fuchsia-500' },
          { label: 'Reportable incidents', value: data.kpis.reportableIncidents, sub: data.kpis.reportableOverdue > 0 ? `${data.kpis.reportableOverdue} overdue!` : 'on schedule', color: data.kpis.reportableOverdue > 0 ? 'from-rose-500 to-fuchsia-600' : 'from-emerald-500 to-teal-500' },
          { label: 'Evidence artifacts', value: data.kpis.evidenceArtifacts, sub: `${data.evidenceLibrary.retentionMonths}-month retention`, color: 'from-amber-500 to-orange-500' },
          { label: 'Days to next audit', value: data.kpis.daysToNextSelfAudit, sub: 'on schedule', color: 'from-emerald-500 to-teal-500' },
          { label: 'Article 21 measures', value: 10, sub: `${data.article21Measures.filter((m) => m.status === 'COMPLIANT').length} compliant`, color: 'from-violet-500 to-fuchsia-500' },
          { label: 'Self-assessment', value: assessmentScore.answered, sub: `${assessmentScore.total} total`, color: 'from-fuchsia-500 to-pink-500' },
        ].map((k, i) => (
          <motion.div
            key={i}
            variants={cardVariants}
            whileHover={{ y: -2, scale: 1.02 }}
            className="relative bg-white rounded-xl ring-1 ring-slate-200/70 shadow-sm p-3 overflow-hidden"
          >
            <div className={`absolute inset-x-0 top-0 h-1 bg-gradient-to-r ${k.color}`} />
            <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">{k.label}</p>
            <p className="mt-0.5 text-2xl font-bold text-slate-900 tabular-nums"><AnimatedNumber value={k.value} /></p>
            <p className="text-[10px] text-slate-400 mt-0.5">{k.sub}</p>
          </motion.div>
        ))}
      </motion.div>

      {/* Tabs */}
      <motion.div variants={cardVariants} className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm overflow-hidden">
        <div className="flex border-b border-slate-200/70 overflow-x-auto">
          {([
            { id: 'measures', label: 'Article 21 Measures', count: data.article21Measures.length },
            { id: 'incidents', label: 'Incident Reporting', count: data.reportableIncidents.length },
            { id: 'evidence', label: 'Evidence Library', count: data.evidenceLibrary.totalArtifacts },
            { id: 'assessment', label: 'Self-Assessment', count: assessmentScore.total },
          ] as const).map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id as any)}
              className={`flex items-center gap-2 px-5 py-3 text-sm font-semibold transition whitespace-nowrap border-b-2 ${
                tab === t.id ? 'border-violet-500 text-violet-700 bg-violet-50/40' : 'border-transparent text-slate-500 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              {t.label}
              <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-bold ${tab === t.id ? 'bg-violet-100 text-violet-700' : 'bg-slate-100 text-slate-600'}`}>
                {t.count}
              </span>
            </button>
          ))}
        </div>

        <div className="p-6">
          {/* TAB 1: Article 21 Measures */}
          {tab === 'measures' && (
            <div className="space-y-3">
              {data.article21Measures.map((m, i) => {
                const isExpanded = expandedMeasure === m.id;
                return (
                  <motion.div
                    key={m.id}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.04 }}
                    layout
                    className="border border-slate-200 rounded-xl overflow-hidden bg-white"
                  >
                    <div
                      className="flex items-center gap-4 p-4 cursor-pointer hover:bg-slate-50/60"
                      onClick={() => setExpandedMeasure(isExpanded ? null : m.id)}
                    >
                      <div className="flex-shrink-0 w-16 text-center">
                        <p className="text-[10px] uppercase font-bold tracking-wider text-slate-400">{m.id}</p>
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold text-slate-900">{m.title}</p>
                        <p className="text-xs text-slate-500 mt-0.5">{m.description}</p>
                      </div>
                      <div className="flex-shrink-0 w-32">
                        <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${m.score}%` }}
                            transition={{ duration: 0.8, delay: 0.2 + i * 0.04 }}
                            className={`h-full bg-gradient-to-r ${scoreColor(m.score)} rounded-full`}
                          />
                        </div>
                        <p className="text-xs text-slate-600 mt-1 text-right tabular-nums">{m.score}%</p>
                      </div>
                      <div className="flex-shrink-0">
                        <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded-full ring-1 ${statusBadge(m.status)}`}>
                          {m.status.replace('_', ' ')}
                        </span>
                      </div>
                      <div className="flex-shrink-0 text-violet-600 text-xs font-semibold">{isExpanded ? '▲' : '▼'}</div>
                    </div>
                    <AnimatePresence>
                      {isExpanded && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.25 }}
                          className="border-t border-slate-200 bg-slate-50/40 overflow-hidden"
                        >
                          <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div>
                              <p className="text-[10px] uppercase font-bold tracking-wider text-slate-500 mb-1">Current state</p>
                              <p className="text-xs text-slate-700">{m.currentState}</p>
                            </div>
                            <div>
                              <p className="text-[10px] uppercase font-bold tracking-wider text-slate-500 mb-1">Next action</p>
                              <p className="text-xs text-slate-700">{m.nextAction}</p>
                            </div>
                            <div>
                              <p className="text-[10px] uppercase font-bold tracking-wider text-slate-500 mb-1">Linked evidence</p>
                              <p className="text-xs text-slate-700">{m.evidenceIds.length} artifact{m.evidenceIds.length === 1 ? '' : 's'} attached</p>
                              <div className="mt-1 space-y-0.5">
                                {m.evidenceIds.slice(0, 3).map((id) => (
                                  <code key={id} className="block text-[10px] text-violet-700 bg-violet-50 px-1.5 py-0.5 rounded">{id}</code>
                                ))}
                              </div>
                            </div>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                );
              })}
            </div>
          )}

          {/* TAB 2: Incident Reporting */}
          {tab === 'incidents' && (
            <div className="space-y-4">
              <div className="bg-violet-50/60 border border-violet-200 rounded-xl p-4">
                <p className="text-xs text-violet-900 leading-relaxed">
                  <strong>NIS2 Article 23</strong> requires reportable incidents to be sent to the CSIRT (USOM in Türkiye) within{' '}
                  <strong>24h (early warning)</strong>, <strong>72h (incident report)</strong>, and <strong>1 month (final report)</strong>.
                  An incident is reportable when it has substantial operational impact.
                </p>
              </div>
              {data.reportableIncidents.length === 0 ? (
                <p className="text-xs text-slate-500 text-center py-8">No reportable incidents at the moment. ✓</p>
              ) : (
                <div className="space-y-2">
                  {data.reportableIncidents.map((inc, i) => (
                    <motion.div
                      key={inc.alertId}
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.04 }}
                      className={`border rounded-xl p-4 transition ${
                        inc.earlyWarningStatus === 'OVERDUE' ? 'border-rose-300 bg-rose-50/40' : 'border-slate-200 hover:bg-slate-50'
                      }`}
                    >
                      <div className="flex items-center gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ring-1 ${
                              inc.severity === 'CRITICAL' ? 'bg-rose-50 text-rose-700 ring-rose-200' : 'bg-amber-50 text-amber-700 ring-amber-200'
                            }`}>{inc.severity}</span>
                            {inc.protocol && (
                              <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-slate-100 text-slate-700">{inc.protocol}</span>
                            )}
                            <span className="text-[10px] text-slate-500">detected {formatDateShort(inc.detectedAt)}</span>
                          </div>
                          <p className="text-sm font-semibold text-slate-900 mt-1 truncate">{inc.title}</p>
                        </div>
                        <div className="flex-shrink-0 text-right">
                          <p className="text-[10px] uppercase font-bold tracking-wider text-slate-500">24h Early warning</p>
                          <p className={`text-sm font-bold ${inc.earlyWarningStatus === 'OVERDUE' ? 'text-rose-600' : 'text-slate-900'}`}>
                            {formatTimeRemaining(inc.earlyWarningDeadline)}
                          </p>
                        </div>
                        <button
                          onClick={() => generateEarlyWarning(inc.alertId)}
                          className="flex-shrink-0 px-3 py-1.5 rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white text-xs font-semibold hover:shadow-lg hover:shadow-violet-500/30 transition"
                        >
                          Generate report
                        </button>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}

              <AnimatePresence>
                {earlyWarning && (
                  <motion.div
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 12 }}
                    className="border border-violet-200 bg-violet-50/40 rounded-xl p-5"
                  >
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="text-sm font-bold text-slate-900">ENISA Article 23.4(a) Early Warning Report</h4>
                      <button onClick={() => setEarlyWarning(null)} className="text-xs text-slate-500 hover:text-slate-900">Close</button>
                    </div>
                    <pre className="text-[11px] font-mono bg-white p-3 rounded-lg max-h-[400px] overflow-auto whitespace-pre-wrap">
                      {JSON.stringify(earlyWarning, null, 2)}
                    </pre>
                    <div className="mt-3 flex gap-2">
                      <button
                        onClick={() => {
                          const blob = new Blob([JSON.stringify(earlyWarning, null, 2)], { type: 'application/json' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = `nis2-early-warning-${earlyWarning?.incident?.alertId ?? 'report'}.json`;
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                        className="px-3 py-1.5 rounded-lg bg-violet-600 text-white text-xs font-semibold hover:bg-violet-700 transition"
                      >
                        Download JSON
                      </button>
                      <button
                        className="px-3 py-1.5 rounded-lg bg-white text-slate-700 text-xs font-semibold ring-1 ring-slate-300 hover:bg-slate-50 transition"
                        onClick={() => alert('Submission to USOM CSIRT is mocked in this demo.')}
                      >
                        Submit to USOM
                      </button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}

          {/* TAB 3: Evidence Library */}
          {tab === 'evidence' && (
            <div className="space-y-5">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="bg-violet-50 border border-violet-200 rounded-xl p-4">
                  <p className="text-[10px] uppercase font-bold tracking-wider text-violet-700">Total artifacts</p>
                  <p className="text-3xl font-bold text-violet-900 tabular-nums mt-1">
                    <AnimatedNumber value={data.evidenceLibrary.totalArtifacts} />
                  </p>
                  <p className="text-xs text-violet-700/80">Logs · Alerts · Policies · Reviews</p>
                </div>
                <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-4">
                  <p className="text-[10px] uppercase font-bold tracking-wider text-emerald-700">Retention compliance</p>
                  <p className="text-3xl font-bold text-emerald-900 tabular-nums mt-1">
                    <AnimatedNumber value={data.retentionPolicy.currentRetention} suffix="mo" />
                  </p>
                  <p className="text-xs text-emerald-700/80">NIS2 minimum: {data.retentionPolicy.requiredMonths} months</p>
                </div>
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
                  <p className="text-[10px] uppercase font-bold tracking-wider text-amber-700">Oldest evidence</p>
                  <p className="text-base font-bold text-amber-900 mt-1">{formatDateShort(data.evidenceLibrary.oldestArtifact)}</p>
                  <p className="text-xs text-amber-700/80">First captured artifact</p>
                </div>
              </div>

              <div className="bg-white rounded-xl border border-slate-200">
                <div className="px-4 py-3 border-b border-slate-200">
                  <p className="text-sm font-semibold text-slate-900">Artifacts by Article</p>
                  <p className="text-xs text-slate-500">Telemetry cross-referenced to NIS2 Article 21 measures</p>
                </div>
                <div className="p-4 space-y-2">
                  {Object.entries(data.evidenceLibrary.byArticle).map(([article, count], i) => {
                    const max = Math.max(...Object.values(data.evidenceLibrary.byArticle));
                    const pct = Math.round((count / max) * 100);
                    return (
                      <motion.div
                        key={article}
                        initial={{ opacity: 0, x: -8 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.03 }}
                        className="grid grid-cols-12 items-center gap-3 py-1.5"
                      >
                        <div className="col-span-2 text-xs font-semibold text-slate-700">{article}</div>
                        <div className="col-span-8">
                          <div className="h-5 bg-slate-100 rounded-md overflow-hidden">
                            <motion.div
                              initial={{ width: 0 }}
                              animate={{ width: `${pct}%` }}
                              transition={{ duration: 0.8, delay: 0.2 + i * 0.03 }}
                              className="h-full bg-gradient-to-r from-violet-500 to-fuchsia-500 rounded-md"
                            />
                          </div>
                        </div>
                        <div className="col-span-2 text-right text-sm tabular-nums font-bold text-slate-900">
                          {count.toLocaleString()}
                        </div>
                      </motion.div>
                    );
                  })}
                </div>
              </div>

              {data.evidenceLibrary.recentArtifacts.length > 0 && (
                <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
                    <p className="text-sm font-semibold text-slate-900">Recent artifacts</p>
                    <button
                      className="text-xs font-semibold text-violet-700 hover:text-violet-900"
                      onClick={() => {
                        const csv = [
                          'id,type,article,description,timestamp',
                          ...data.evidenceLibrary.recentArtifacts.map(
                            (a) => `"${a.id}","${a.type}","${a.article}","${a.description.replace(/"/g, '""')}","${a.timestamp ?? ''}"`,
                          ),
                        ].join('\n');
                        const blob = new Blob([csv], { type: 'text/csv' });
                        const url = URL.createObjectURL(blob);
                        const aEl = document.createElement('a');
                        aEl.href = url;
                        aEl.download = 'nis2-evidence-export.csv';
                        aEl.click();
                        URL.revokeObjectURL(url);
                      }}
                    >
                      Export CSV ↓
                    </button>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-slate-50 text-[11px] uppercase tracking-wider text-slate-500">
                        <tr>
                          <th className="text-left px-4 py-2 font-semibold">Artifact ID</th>
                          <th className="text-left px-4 py-2 font-semibold">Type</th>
                          <th className="text-left px-4 py-2 font-semibold">Article</th>
                          <th className="text-left px-4 py-2 font-semibold">Description</th>
                          <th className="text-left px-4 py-2 font-semibold">Timestamp</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.evidenceLibrary.recentArtifacts.map((a, i) => (
                          <motion.tr
                            key={a.id}
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            transition={{ delay: i * 0.03 }}
                            className="border-t border-slate-100 hover:bg-slate-50"
                          >
                            <td className="px-4 py-2 font-mono text-xs text-slate-700">{a.id}</td>
                            <td className="px-4 py-2 text-xs">{a.type}</td>
                            <td className="px-4 py-2">
                              <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-violet-50 text-violet-700 ring-1 ring-violet-200">
                                {a.article}
                              </span>
                            </td>
                            <td className="px-4 py-2 text-xs text-slate-700">{a.description}</td>
                            <td className="px-4 py-2 text-xs text-slate-500 tabular-nums">{formatDateShort(a.timestamp)}</td>
                          </motion.tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: Self-Assessment */}
          {tab === 'assessment' && (
            <div className="space-y-5">
              <div className="bg-gradient-to-br from-violet-50 to-fuchsia-50 border border-violet-200 rounded-xl p-5 flex items-center gap-6">
                <div className="flex-1">
                  <p className="text-xs uppercase font-bold tracking-wider text-violet-700">Self-Assessment Score</p>
                  <p className="text-4xl font-bold text-slate-900 tabular-nums mt-1">
                    <AnimatedNumber value={assessmentScore.score} suffix="%" />
                  </p>
                  <p className="text-xs text-slate-600 mt-1">
                    {assessmentScore.answered}/{assessmentScore.total} questions answered
                  </p>
                </div>
                <div className="flex-1">
                  <div className="h-3 bg-white rounded-full overflow-hidden ring-1 ring-violet-200">
                    <motion.div
                      animate={{ width: `${assessmentScore.score}%` }}
                      transition={{ duration: 0.6 }}
                      className="h-full bg-gradient-to-r from-violet-500 to-fuchsia-500 rounded-full"
                    />
                  </div>
                  <p className="text-[10px] text-slate-500 mt-2">YES = full credit · PARTIAL = half credit · NO = no credit</p>
                </div>
              </div>

              {data.selfAssessment.map((section, idx) => (
                <motion.div
                  key={section.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.04 }}
                  className="bg-white border border-slate-200 rounded-xl overflow-hidden"
                >
                  <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
                    <p className="text-sm font-semibold text-slate-900">{section.id} · {section.title}</p>
                  </div>
                  <div className="p-4 space-y-3">
                    {section.questions.map((q) => {
                      const ans = answers[q.id];
                      return (
                        <div key={q.id} className="flex items-start gap-3 py-2 border-b border-slate-100 last:border-0">
                          <p className="flex-1 text-xs text-slate-700">{q.question}</p>
                          <div className="flex gap-1">
                            {(['YES', 'PARTIAL', 'NO'] as const).map((opt) => (
                              <button
                                key={opt}
                                onClick={() => setAnswers((s) => ({ ...s, [q.id]: ans === opt ? null : opt }))}
                                className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider ring-1 transition ${
                                  ans === opt
                                    ? opt === 'YES'
                                      ? 'bg-emerald-500 text-white ring-emerald-500'
                                      : opt === 'PARTIAL'
                                      ? 'bg-amber-500 text-white ring-amber-500'
                                      : 'bg-rose-500 text-white ring-rose-500'
                                    : 'bg-white text-slate-600 ring-slate-300 hover:bg-slate-50'
                                }`}
                              >
                                {opt}
                              </button>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </motion.div>
              ))}

              {assessmentScore.answered > 0 && (
                <div className="bg-white border border-slate-200 rounded-xl p-5">
                  <h4 className="text-sm font-bold text-slate-900 mb-3">Gap Analysis</h4>
                  <div className="space-y-2">
                    {data.selfAssessment.map((section) => {
                      const gaps = section.questions.filter((q) => answers[q.id] === 'NO');
                      const partial = section.questions.filter((q) => answers[q.id] === 'PARTIAL');
                      if (gaps.length === 0 && partial.length === 0) return null;
                      return (
                        <div key={section.id} className="border-l-4 border-rose-400 pl-3 py-1">
                          <p className="text-xs font-semibold text-slate-900">{section.id} · {section.title}</p>
                          <p className="text-[11px] text-slate-600">
                            {gaps.length} gap{gaps.length === 1 ? '' : 's'}, {partial.length} partial coverage
                          </p>
                        </div>
                      );
                    })}
                    {data.selfAssessment.every((s) =>
                      s.questions.every((q) => answers[q.id] !== 'NO' && answers[q.id] !== 'PARTIAL'),
                    ) && (
                      <p className="text-xs text-emerald-700">✓ No gaps identified in answered questions</p>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
};

export default Compliance;
