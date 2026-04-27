import React, { useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence, Variants } from 'framer-motion';

// =====================================================================
// Attacker TTPs & Behavioral Intelligence tab — animated edition
// Renders /api/honeypot/ttp-analysis as 7 widgets with staggered fade-ins,
// growing bars, animated counters, and timeline reveal animations.
// =====================================================================

interface AttackerProfile {
  sourceIp: string;
  country: string | null;
  totalEvents: number;
  uniqueProtocols: number;
  protocols: string[];
  attackTypes: string[];
  credentialAttempts: number;
  highSeverityCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
  activeMinutes: number;
  sophistication: 'SCRIPT_KIDDIE' | 'INTERMEDIATE' | 'ADVANCED' | string;
  suspectedTool: string;
}

interface MitreTactic {
  tactic: string;
  eventCount: number;
  techniques: string[];
  uniqueAttackers: number;
}

interface ToolRow {
  tool: string;
  eventCount: number;
  uniqueAttackers: number;
  description: string;
}

interface ToolFingerprint {
  toolBreakdown: ToolRow[];
  topUserAgents: Record<string, number>;
}

interface KillChainStep {
  timestamp: string | null;
  tactic: string;
  technique: string;
  protocol: string | null;
  attackType: string | null;
}

interface KillChain {
  sourceIp: string;
  totalEvents: number;
  steps: KillChainStep[];
}

interface GeoRow {
  country: string;
  eventCount: number;
  uniqueAttackers: number;
}

interface CredPair {
  username: string;
  password: string;
  attempts: number;
  uniqueAttackers: number;
  family: string;
}

interface CredentialIntel {
  topCredentialPairs: CredPair[];
  miraiFamilyHits: number;
  miraiAttackers: number;
  icsDefaultHits: number;
  icsAttackers: number;
}

interface BehavioralRow {
  sourceIp: string;
  eventsPerMinute?: number;
  activeMinutes?: number;
  protocols?: string[];
  totalEvents: number;
  note: string;
}

interface BehavioralAnomalies {
  burstAttackers: BehavioralRow[];
  slowLowAttackers: BehavioralRow[];
  multiProtocolPivots: BehavioralRow[];
}

interface TTPReport {
  totalEvents: number;
  uniqueAttackers: number;
  attackerProfiles: AttackerProfile[];
  mitreTactics: MitreTactic[];
  toolFingerprints: ToolFingerprint[];
  killChains: KillChain[];
  geoDistribution: GeoRow[];
  credentialIntelligence: CredentialIntel;
  behavioralAnomalies: BehavioralAnomalies;
}

const EMPTY_REPORT: TTPReport = {
  totalEvents: 0,
  uniqueAttackers: 0,
  attackerProfiles: [],
  mitreTactics: [],
  toolFingerprints: [{ toolBreakdown: [], topUserAgents: {} }],
  killChains: [],
  geoDistribution: [],
  credentialIntelligence: {
    topCredentialPairs: [],
    miraiFamilyHits: 0,
    miraiAttackers: 0,
    icsDefaultHits: 0,
    icsAttackers: 0,
  },
  behavioralAnomalies: {
    burstAttackers: [],
    slowLowAttackers: [],
    multiProtocolPivots: [],
  },
};

const tierStyle = (tier: string) => {
  switch (tier) {
    case 'ADVANCED':
      return 'bg-rose-50 text-rose-700 ring-rose-200';
    case 'INTERMEDIATE':
      return 'bg-amber-50 text-amber-700 ring-amber-200';
    default:
      return 'bg-slate-50 text-slate-700 ring-slate-200';
  }
};

// ─── animated number — counts up from 0 to target on mount ──────────────
const AnimatedNumber: React.FC<{ value: number; duration?: number }> = ({
  value,
  duration = 900,
}) => {
  const [display, setDisplay] = useState(0);
  const startRef = useRef<number | null>(null);
  const fromRef = useRef(0);

  useEffect(() => {
    fromRef.current = display;
    startRef.current = null;
    let raf = 0;
    const tick = (now: number) => {
      if (startRef.current === null) startRef.current = now;
      const t = Math.min(1, (now - startRef.current) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(Math.round(fromRef.current + (value - fromRef.current) * eased));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  return <>{display.toLocaleString()}</>;
};

// ─── animation variants ─────────────────────────────────────────────────
const containerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.08, delayChildren: 0.05 },
  },
};

const cardVariants: Variants = {
  hidden: { opacity: 0, y: 18 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { type: 'spring', stiffness: 110, damping: 16 },
  },
};

const itemVariants: Variants = {
  hidden: { opacity: 0, x: -12 },
  visible: { opacity: 1, x: 0, transition: { duration: 0.35 } },
};

const TTPIntelTab: React.FC = () => {
  const [report, setReport] = useState<TTPReport>(EMPTY_REPORT);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedChainIp, setSelectedChainIp] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const r = await fetch('http://localhost:8080/api/honeypot/ttp-analysis');
        if (!r.ok) {
          if (!cancelled) {
            setError(`Backend returned HTTP ${r.status}`);
            setLoading(false);
          }
          return;
        }
        const d = (await r.json()) as TTPReport;
        if (!cancelled) {
          setReport({ ...EMPTY_REPORT, ...d });
          setLoading(false);
        }
      } catch (e: any) {
        if (!cancelled) {
          setError(e?.message ?? 'Network error');
          setLoading(false);
        }
      }
    };
    load();
    const id = window.setInterval(load, 30000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  const sophCounts = useMemo(() => {
    const c = { SCRIPT_KIDDIE: 0, INTERMEDIATE: 0, ADVANCED: 0 };
    report.attackerProfiles.forEach((p) => {
      if (p.sophistication in c) (c as any)[p.sophistication]++;
    });
    return c;
  }, [report.attackerProfiles]);

  const totalProfiles = report.attackerProfiles.length;
  const maxTactic = useMemo(
    () =>
      Math.max(
        1,
        ...report.mitreTactics.map((t) => t.eventCount as number),
      ),
    [report.mitreTactics],
  );

  const tools = report.toolFingerprints?.[0]?.toolBreakdown ?? [];
  const userAgents = report.toolFingerprints?.[0]?.topUserAgents ?? {};

  const selectedChain = useMemo(
    () =>
      report.killChains.find((k) => k.sourceIp === selectedChainIp) ??
      report.killChains[0] ??
      null,
    [report.killChains, selectedChainIp],
  );

  if (loading) {
    return (
      <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-10 text-center overflow-hidden">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1.2, repeat: Infinity, ease: 'linear' }}
          className="w-12 h-12 mx-auto mb-3 rounded-full border-4 border-violet-200 border-t-violet-600"
        />
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: [0.4, 1, 0.4] }}
          transition={{ duration: 1.6, repeat: Infinity }}
          className="text-sm text-slate-500"
        >
          Computing TTP analysis…
        </motion.p>
      </div>
    );
  }

  if (error) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="bg-rose-50 rounded-2xl ring-1 ring-rose-200 p-6"
      >
        <p className="text-sm text-rose-800 font-semibold">Failed to load TTP report</p>
        <p className="text-xs text-rose-700 mt-1">{error}</p>
      </motion.div>
    );
  }

  return (
    <motion.div
      className="space-y-6"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* ───── Summary strip ───── */}
      <motion.div
        variants={cardVariants}
        className="grid grid-cols-2 md:grid-cols-4 gap-3"
      >
        {[
          { label: 'Total events analyzed', value: report.totalEvents },
          { label: 'Unique attackers', value: report.uniqueAttackers },
          { label: 'Profiled (≥2 events)', value: totalProfiles },
          { label: 'Advanced tier', value: sophCounts.ADVANCED },
        ].map((s, i) => (
          <motion.div
            key={i}
            whileHover={{ y: -3, scale: 1.02 }}
            transition={{ type: 'spring', stiffness: 300 }}
            className="bg-white rounded-xl ring-1 ring-slate-200/70 shadow-sm p-4 hover:shadow-md transition-shadow"
          >
            <p className="text-[11px] uppercase tracking-wider font-semibold text-slate-500">
              {s.label}
            </p>
            <p className="mt-1 text-2xl font-bold text-slate-900 tabular-nums">
              <AnimatedNumber value={s.value} />
            </p>
          </motion.div>
        ))}
      </motion.div>

      {/* ───── 1. Sophistication breakdown ───── */}
      <motion.div
        variants={cardVariants}
        className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-6"
      >
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-semibold text-slate-900">Attacker Sophistication</h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Heuristic tier from protocol breadth, write attempts, and brute-force activity.
            </p>
          </div>
          <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full bg-violet-50 text-violet-700 ring-1 ring-violet-200">
            Behavior
          </span>
        </div>
        <motion.div
          variants={containerVariants}
          className="grid grid-cols-1 md:grid-cols-3 gap-3"
        >
          {[
            {
              key: 'SCRIPT_KIDDIE',
              label: 'Script kiddie / bot',
              hint: 'Single protocol, opportunistic, default-credential noise.',
              color: 'from-slate-400 to-slate-500',
            },
            {
              key: 'INTERMEDIATE',
              label: 'Intermediate',
              hint: 'Two protocols or sustained brute-force.',
              color: 'from-amber-400 to-orange-500',
            },
            {
              key: 'ADVANCED',
              label: 'Advanced / ICS-aware',
              hint: '3+ protocols or write/control attempts on ICS.',
              color: 'from-rose-500 to-fuchsia-600',
            },
          ].map((row, idx) => {
            const v = (sophCounts as any)[row.key] as number;
            const pct = totalProfiles ? Math.round((v / totalProfiles) * 100) : 0;
            return (
              <motion.div
                key={row.key}
                variants={cardVariants}
                whileHover={{ y: -4, scale: 1.02 }}
                transition={{ type: 'spring', stiffness: 280 }}
                className="relative rounded-xl border border-slate-200/70 p-4 overflow-hidden hover:shadow-md transition-shadow"
              >
                <motion.div
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.7, delay: 0.2 + idx * 0.1, ease: 'easeOut' }}
                  style={{ originX: 0 }}
                  className={`absolute inset-x-0 top-0 h-1 bg-gradient-to-r ${row.color}`}
                />
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                  {row.label}
                </p>
                <p className="mt-1 text-3xl font-bold text-slate-900 tabular-nums">
                  <AnimatedNumber value={v} />
                </p>
                <p className="text-xs text-slate-500 mt-0.5">{pct}% of profiled attackers</p>
                <p className="text-[11px] text-slate-400 mt-2 leading-snug">{row.hint}</p>
              </motion.div>
            );
          })}
        </motion.div>
      </motion.div>

      {/* ───── 2. MITRE ATT&CK ICS Tactic Heatmap ───── */}
      <motion.div
        variants={cardVariants}
        className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-6"
      >
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-semibold text-slate-900">
              MITRE ATT&amp;CK ICS — Tactic Heatmap
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Distribution of observed tactics across the ICS Kill Chain.
            </p>
          </div>
          <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full bg-fuchsia-50 text-fuchsia-700 ring-1 ring-fuchsia-200">
            ATT&amp;CK
          </span>
        </div>
        <div className="space-y-2">
          {report.mitreTactics.map((t, idx) => {
            const pct = Math.round(((t.eventCount as number) / maxTactic) * 100);
            const empty = (t.eventCount as number) === 0;
            return (
              <motion.div
                key={t.tactic}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.35, delay: 0.15 + idx * 0.06 }}
                className="grid grid-cols-12 items-center gap-3 py-1.5"
              >
                <div className="col-span-3 text-sm font-semibold text-slate-700">{t.tactic}</div>
                <div className="col-span-7 relative">
                  <div className="h-7 rounded-md bg-slate-100 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${empty ? 0 : Math.max(4, pct)}%` }}
                      transition={{ duration: 1.0, delay: 0.3 + idx * 0.06, ease: 'easeOut' }}
                      className={`h-full rounded-md ${
                        empty
                          ? 'bg-slate-200'
                          : 'bg-gradient-to-r from-violet-500 to-fuchsia-500'
                      }`}
                    />
                  </div>
                  <div className="absolute inset-0 flex items-center px-2 text-[11px] font-semibold text-slate-700 pointer-events-none">
                    {(t.techniques ?? []).slice(0, 2).join(' · ')}
                  </div>
                </div>
                <div className="col-span-2 text-right text-sm tabular-nums text-slate-700">
                  <span className="font-bold">
                    <AnimatedNumber value={t.eventCount} />
                  </span>
                  <span className="text-xs text-slate-400 ml-1">
                    / {t.uniqueAttackers} IPs
                  </span>
                </div>
              </motion.div>
            );
          })}
        </div>
      </motion.div>

      {/* ───── 3. Tool / Wordlist Fingerprints ───── */}
      <motion.div
        variants={cardVariants}
        className="grid grid-cols-1 lg:grid-cols-2 gap-6"
      >
        <motion.div
          whileHover={{ y: -2 }}
          className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-6 transition-shadow hover:shadow-md"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-semibold text-slate-900">Tool Fingerprints</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Inferred from User-Agent and behavioral signatures.
              </p>
            </div>
            <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200">
              Recon
            </span>
          </div>
          {tools.length === 0 ? (
            <p className="text-xs text-slate-500">
              No recognizable tool signatures yet — no User-Agent strings observed.
            </p>
          ) : (
            <motion.ul
              variants={containerVariants}
              initial="hidden"
              animate="visible"
              className="divide-y divide-slate-100"
            >
              {tools.slice(0, 10).map((t) => (
                <motion.li
                  key={t.tool}
                  variants={itemVariants}
                  className="py-2.5 flex items-start justify-between gap-3 hover:bg-slate-50 rounded px-2 -mx-2 transition-colors"
                >
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold text-slate-900">{t.tool}</p>
                    <p className="text-[11px] text-slate-500 mt-0.5">{t.description}</p>
                  </div>
                  <div className="text-right shrink-0">
                    <p className="text-sm font-bold tabular-nums">
                      <AnimatedNumber value={t.eventCount} />
                    </p>
                    <p className="text-[11px] text-slate-400">{t.uniqueAttackers} IPs</p>
                  </div>
                </motion.li>
              ))}
            </motion.ul>
          )}
        </motion.div>
        <motion.div
          whileHover={{ y: -2 }}
          className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-6 transition-shadow hover:shadow-md"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold text-slate-900">Top User-Agents</h3>
            <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full bg-slate-50 text-slate-600 ring-1 ring-slate-200">
              Raw
            </span>
          </div>
          {Object.keys(userAgents).length === 0 ? (
            <p className="text-xs text-slate-500">No User-Agent headers captured.</p>
          ) : (
            <motion.ul
              variants={containerVariants}
              initial="hidden"
              animate="visible"
              className="space-y-1.5"
            >
              {Object.entries(userAgents).map(([ua, n]) => (
                <motion.li
                  key={ua}
                  variants={itemVariants}
                  whileHover={{ x: 4 }}
                  className="flex items-start justify-between gap-3 p-2 rounded-lg hover:bg-slate-50 transition-colors"
                >
                  <code className="text-[11px] text-slate-700 break-all">{ua}</code>
                  <span className="shrink-0 text-xs font-semibold tabular-nums text-slate-900">
                    <AnimatedNumber value={n} />
                  </span>
                </motion.li>
              ))}
            </motion.ul>
          )}
        </motion.div>
      </motion.div>

      {/* ───── 4. Top Attacker Profiles Table ───── */}
      <motion.div
        variants={cardVariants}
        className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm overflow-hidden"
      >
        <div className="px-6 py-4 border-b border-slate-200/70 flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-slate-900">Top Attacker Profiles</h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Per-IP behavioral summary, sorted by activity volume.
            </p>
          </div>
          <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full bg-violet-50 text-violet-700 ring-1 ring-violet-200">
            Profiles
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-[11px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="text-left px-4 py-2 font-semibold">Source IP</th>
                <th className="text-left px-4 py-2 font-semibold">Country</th>
                <th className="text-left px-4 py-2 font-semibold">Tier</th>
                <th className="text-left px-4 py-2 font-semibold">Suspected Tool</th>
                <th className="text-left px-4 py-2 font-semibold">Protocols</th>
                <th className="text-right px-4 py-2 font-semibold">Events</th>
                <th className="text-right px-4 py-2 font-semibold">Cred Tries</th>
                <th className="text-right px-4 py-2 font-semibold">High Sev</th>
                <th className="text-right px-4 py-2 font-semibold">Active (min)</th>
              </tr>
            </thead>
            <tbody>
              {report.attackerProfiles.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-4 py-6 text-center text-xs text-slate-500">
                    No profiled attackers yet — at least 2 events per IP required.
                  </td>
                </tr>
              ) : (
                <AnimatePresence>
                  {report.attackerProfiles.slice(0, 20).map((p, idx) => (
                    <motion.tr
                      key={p.sourceIp}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.25, delay: 0.02 * idx }}
                      whileHover={{ backgroundColor: 'rgba(124, 58, 237, 0.05)' }}
                      className="border-t border-slate-100 cursor-pointer"
                      onClick={() => setSelectedChainIp(p.sourceIp)}
                    >
                      <td className="px-4 py-2 font-mono text-xs text-slate-900">
                        {p.sourceIp}
                      </td>
                      <td className="px-4 py-2 text-slate-700">{p.country ?? '—'}</td>
                      <td className="px-4 py-2">
                        <motion.span
                          whileHover={{ scale: 1.08 }}
                          className={`inline-block text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ring-1 ${tierStyle(
                            p.sophistication,
                          )}`}
                        >
                          {p.sophistication.replace('_', ' ')}
                        </motion.span>
                      </td>
                      <td className="px-4 py-2 text-slate-700 text-xs">{p.suspectedTool}</td>
                      <td className="px-4 py-2 text-xs text-slate-700">
                        {(p.protocols ?? []).join(', ')}
                      </td>
                      <td className="px-4 py-2 text-right tabular-nums font-semibold">
                        {p.totalEvents.toLocaleString()}
                      </td>
                      <td className="px-4 py-2 text-right tabular-nums text-slate-700">
                        {p.credentialAttempts.toLocaleString()}
                      </td>
                      <td className="px-4 py-2 text-right tabular-nums text-rose-600">
                        {p.highSeverityCount.toLocaleString()}
                      </td>
                      <td className="px-4 py-2 text-right tabular-nums text-slate-500">
                        {p.activeMinutes.toLocaleString()}
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>
              )}
            </tbody>
          </table>
        </div>
        {report.attackerProfiles.length > 0 && (
          <div className="px-6 py-2 border-t border-slate-200/70 bg-slate-50/50">
            <p className="text-[11px] text-slate-500">
              Click any row to focus its kill chain below.
            </p>
          </div>
        )}
      </motion.div>

      {/* ───── 5. Kill Chain Timeline ───── */}
      <motion.div
        variants={cardVariants}
        className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-6"
      >
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-semibold text-slate-900">Kill Chain Timeline</h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Tactic progression for the selected attacker.
            </p>
          </div>
          {report.killChains.length > 0 && (
            <select
              className="text-xs px-3 py-1.5 rounded-lg ring-1 ring-slate-200 bg-white focus:ring-2 focus:ring-violet-300 transition-all"
              value={selectedChain?.sourceIp ?? ''}
              onChange={(e) => setSelectedChainIp(e.target.value)}
            >
              {report.killChains.map((c) => (
                <option key={c.sourceIp} value={c.sourceIp}>
                  {c.sourceIp} ({c.totalEvents} events)
                </option>
              ))}
            </select>
          )}
        </div>
        {!selectedChain ? (
          <p className="text-xs text-slate-500 py-6 text-center">
            No multi-step kill chains detected yet — need ≥3 events per attacker.
          </p>
        ) : (
          <div className="relative">
            <motion.div
              initial={{ scaleY: 0 }}
              animate={{ scaleY: 1 }}
              transition={{ duration: 0.7, ease: 'easeOut' }}
              style={{ originY: 0 }}
              className="absolute left-3 top-2 bottom-2 w-0.5 bg-gradient-to-b from-violet-400 via-fuchsia-400 to-rose-400"
            />
            <ol className="space-y-3 pl-2">
              <AnimatePresence mode="wait">
                {selectedChain.steps.map((step, idx) => (
                  <motion.li
                    key={`${selectedChain.sourceIp}-${idx}`}
                    initial={{ opacity: 0, x: -16 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -16 }}
                    transition={{ duration: 0.3, delay: 0.15 + idx * 0.12 }}
                    className="relative flex items-start gap-3 pl-6"
                  >
                    <motion.span
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{
                        type: 'spring',
                        stiffness: 400,
                        damping: 12,
                        delay: 0.2 + idx * 0.12,
                      }}
                      className="absolute left-2 top-1.5 w-3 h-3 rounded-full bg-white ring-2 ring-violet-500"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-baseline justify-between gap-3">
                        <p className="text-sm font-semibold text-slate-900">{step.tactic}</p>
                        <span className="text-[11px] text-slate-400 tabular-nums">
                          {step.timestamp ? step.timestamp.replace('T', ' ').slice(0, 19) : ''}
                        </span>
                      </div>
                      <p className="text-xs text-violet-700 mt-0.5">{step.technique}</p>
                      <p className="text-[11px] text-slate-500 mt-0.5">
                        {step.protocol ?? '—'} · {step.attackType ?? '—'}
                      </p>
                    </div>
                  </motion.li>
                ))}
              </AnimatePresence>
            </ol>
          </div>
        )}
      </motion.div>

      {/* ───── 6. Geographic Distribution ───── */}
      <motion.div
        variants={cardVariants}
        className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-6"
      >
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-semibold text-slate-900">Geographic Distribution</h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Country-level breakdown via GeoIP enrichment.
            </p>
          </div>
          <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200">
            Geo
          </span>
        </div>
        {report.geoDistribution.length === 0 ? (
          <p className="text-xs text-slate-500">No geographic data available.</p>
        ) : (
          <motion.div
            variants={containerVariants}
            initial="hidden"
            animate="visible"
            className="grid grid-cols-1 md:grid-cols-2 gap-4"
          >
            {report.geoDistribution.slice(0, 12).map((g, idx) => {
              const total = report.geoDistribution.reduce(
                (s, x) => s + (x.eventCount as number),
                0,
              );
              const pct = total ? Math.round(((g.eventCount as number) / total) * 100) : 0;
              return (
                <motion.div
                  key={g.country}
                  variants={cardVariants}
                  whileHover={{ scale: 1.02, x: 2 }}
                  className="flex items-center gap-3 p-3 rounded-lg ring-1 ring-slate-200/60 hover:ring-emerald-300 hover:shadow-sm transition-all"
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-slate-900">{g.country}</p>
                    <p className="text-[11px] text-slate-500">
                      {g.uniqueAttackers} unique IP{g.uniqueAttackers === 1 ? '' : 's'}
                    </p>
                    <div className="mt-1.5 h-1.5 rounded-full bg-slate-100 overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${pct}%` }}
                        transition={{ duration: 1.0, delay: 0.2 + idx * 0.05, ease: 'easeOut' }}
                        className="h-full bg-gradient-to-r from-emerald-400 to-teal-500"
                      />
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <p className="text-sm font-bold tabular-nums">
                      <AnimatedNumber value={g.eventCount} />
                    </p>
                    <p className="text-[11px] text-slate-400">{pct}%</p>
                  </div>
                </motion.div>
              );
            })}
          </motion.div>
        )}
      </motion.div>

      {/* ───── 7a. Credential Intelligence ───── */}
      <motion.div
        variants={cardVariants}
        className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-6"
      >
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-semibold text-slate-900">Credential Intelligence</h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Wordlist family detection over observed user/password attempts.
            </p>
          </div>
          <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full bg-rose-50 text-rose-700 ring-1 ring-rose-200">
            Creds
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-5">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.15 }}
            whileHover={{ y: -3, boxShadow: '0 8px 24px -8px rgba(244, 63, 94, 0.3)' }}
            className="p-4 rounded-xl bg-rose-50 ring-1 ring-rose-200 transition-shadow"
          >
            <p className="text-xs uppercase font-semibold tracking-wider text-rose-700">
              Mirai-class IoT botnet
            </p>
            <p className="mt-1 text-2xl font-bold text-rose-900 tabular-nums">
              <AnimatedNumber value={report.credentialIntelligence.miraiFamilyHits} />
            </p>
            <p className="text-xs text-rose-700/80">
              {report.credentialIntelligence.miraiAttackers} attacker
              {report.credentialIntelligence.miraiAttackers === 1 ? '' : 's'} matched the
              IoT-default credential list (root:xc3511 etc.)
            </p>
          </motion.div>
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.25 }}
            whileHover={{ y: -3, boxShadow: '0 8px 24px -8px rgba(124, 58, 237, 0.3)' }}
            className="p-4 rounded-xl bg-violet-50 ring-1 ring-violet-200 transition-shadow"
          >
            <p className="text-xs uppercase font-semibold tracking-wider text-violet-700">
              ICS vendor defaults
            </p>
            <p className="mt-1 text-2xl font-bold text-violet-900 tabular-nums">
              <AnimatedNumber value={report.credentialIntelligence.icsDefaultHits} />
            </p>
            <p className="text-xs text-violet-700/80">
              {report.credentialIntelligence.icsAttackers} attacker
              {report.credentialIntelligence.icsAttackers === 1 ? '' : 's'} tried
              ICS-default pairs (siemens:siemens, plc:plc, etc.)
            </p>
          </motion.div>
        </div>

        {report.credentialIntelligence.topCredentialPairs.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="text-left px-4 py-2 font-semibold">Username</th>
                  <th className="text-left px-4 py-2 font-semibold">Password</th>
                  <th className="text-left px-4 py-2 font-semibold">Family</th>
                  <th className="text-right px-4 py-2 font-semibold">Attempts</th>
                  <th className="text-right px-4 py-2 font-semibold">Distinct IPs</th>
                </tr>
              </thead>
              <tbody>
                {report.credentialIntelligence.topCredentialPairs.map((p, i) => (
                  <motion.tr
                    key={i}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.25, delay: 0.04 * i }}
                    className="border-t border-slate-100 hover:bg-slate-50 transition-colors"
                  >
                    <td className="px-4 py-2 font-mono text-xs">{p.username || '—'}</td>
                    <td className="px-4 py-2 font-mono text-xs">{p.password || '—'}</td>
                    <td className="px-4 py-2 text-xs">
                      <span
                        className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ring-1 ${
                          p.family.startsWith('Mirai')
                            ? 'bg-rose-50 text-rose-700 ring-rose-200'
                            : p.family.startsWith('ICS')
                            ? 'bg-violet-50 text-violet-700 ring-violet-200'
                            : 'bg-slate-50 text-slate-600 ring-slate-200'
                        }`}
                      >
                        {p.family}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-right tabular-nums font-semibold">
                      {p.attempts.toLocaleString()}
                    </td>
                    <td className="px-4 py-2 text-right tabular-nums text-slate-500">
                      {p.uniqueAttackers}
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>

      {/* ───── 7b. Behavioral Anomalies ───── */}
      <motion.div
        variants={containerVariants}
        className="grid grid-cols-1 lg:grid-cols-3 gap-4"
      >
        {[
          {
            title: 'Burst attackers',
            hint: 'High event rate (>10/min) — automated tool / botnet.',
            rows: report.behavioralAnomalies.burstAttackers,
            metric: (r: BehavioralRow) => `${r.eventsPerMinute ?? 0}/min`,
            color: 'bg-rose-50 text-rose-700 ring-rose-200',
            shadowColor: 'rgba(244, 63, 94, 0.25)',
          },
          {
            title: 'Slow-and-low',
            hint: 'Long active window with low rate — likely manual recon.',
            rows: report.behavioralAnomalies.slowLowAttackers,
            metric: (r: BehavioralRow) => `${r.activeMinutes ?? 0} min`,
            color: 'bg-amber-50 text-amber-700 ring-amber-200',
            shadowColor: 'rgba(245, 158, 11, 0.25)',
          },
          {
            title: 'Multi-protocol pivots',
            hint: '3+ distinct protocols — ICS-aware operator.',
            rows: report.behavioralAnomalies.multiProtocolPivots,
            metric: (r: BehavioralRow) => `${(r.protocols ?? []).length} protos`,
            color: 'bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-200',
            shadowColor: 'rgba(217, 70, 239, 0.25)',
          },
        ].map((card) => (
          <motion.div
            key={card.title}
            variants={cardVariants}
            whileHover={{ y: -4, boxShadow: `0 12px 32px -12px ${card.shadowColor}` }}
            transition={{ type: 'spring', stiffness: 280 }}
            className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-6 transition-shadow"
          >
            <div className="flex items-start justify-between mb-3">
              <div>
                <h4 className="text-sm font-semibold text-slate-900">{card.title}</h4>
                <p className="text-[11px] text-slate-500 mt-0.5">{card.hint}</p>
              </div>
              <motion.span
                animate={card.rows.length > 0 ? { scale: [1, 1.15, 1] } : {}}
                transition={{ duration: 1.6, repeat: Infinity, repeatDelay: 1 }}
                className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ring-1 ${card.color}`}
              >
                {card.rows.length}
              </motion.span>
            </div>
            {card.rows.length === 0 ? (
              <p className="text-xs text-slate-400">None detected yet.</p>
            ) : (
              <motion.ul
                variants={containerVariants}
                initial="hidden"
                animate="visible"
                className="space-y-1.5"
              >
                {card.rows.slice(0, 6).map((r, i) => (
                  <motion.li
                    key={i}
                    variants={itemVariants}
                    whileHover={{ x: 3 }}
                    className="flex items-center justify-between gap-3 p-2 rounded-lg hover:bg-slate-50 transition-colors"
                  >
                    <code className="text-xs text-slate-700">{r.sourceIp}</code>
                    <span className="text-[11px] font-semibold text-slate-600 tabular-nums">
                      {card.metric(r)}
                    </span>
                  </motion.li>
                ))}
              </motion.ul>
            )}
          </motion.div>
        ))}
      </motion.div>
    </motion.div>
  );
};

export default TTPIntelTab;
