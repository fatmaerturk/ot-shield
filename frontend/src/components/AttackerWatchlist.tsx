import React, { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence, Variants } from 'framer-motion';

// =====================================================================
// Attacker Watchlist sub-tab
// Card-grid view of every profiled attacker, with filtering, search,
// and expandable detail (kill-chain steps inline). Pulls the same
// /api/honeypot/ttp-analysis payload the TTP Intel tab uses, so no
// extra backend work is required.
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

interface TTPReport {
  attackerProfiles: AttackerProfile[];
  killChains: KillChain[];
}

const containerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.05, delayChildren: 0.05 },
  },
};

const cardVariants: Variants = {
  hidden: { opacity: 0, y: 14, scale: 0.98 },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: { type: 'spring', stiffness: 130, damping: 16 },
  },
};

// Country name -> ISO 3166-1 alpha-2 (subset matching the most common
// attacker origins). Mirrors the larger table in Honeypot.tsx but kept
// local so this component is self-contained.
const COUNTRY_ISO: Record<string, string> = {
  'Türkiye': 'TR', 'Turkey': 'TR',
  'United States': 'US', 'United States of America': 'US', 'USA': 'US',
  'United Kingdom': 'GB', 'UK': 'GB', 'Great Britain': 'GB',
  'China': 'CN', 'Russia': 'RU', 'Russian Federation': 'RU',
  'Germany': 'DE', 'France': 'FR', 'Netherlands': 'NL', 'Spain': 'ES',
  'Italy': 'IT', 'Switzerland': 'CH', 'Sweden': 'SE', 'Norway': 'NO',
  'Denmark': 'DK', 'Finland': 'FI', 'Poland': 'PL', 'Romania': 'RO',
  'Ukraine': 'UA', 'Belarus': 'BY', 'Bulgaria': 'BG',
  'Brazil': 'BR', 'Argentina': 'AR', 'Mexico': 'MX', 'Canada': 'CA',
  'India': 'IN', 'Pakistan': 'PK',
  'Japan': 'JP', 'South Korea': 'KR', 'Korea, Republic of': 'KR',
  'Taiwan': 'TW', 'Hong Kong': 'HK', 'Vietnam': 'VN', 'Thailand': 'TH',
  'Singapore': 'SG', 'Indonesia': 'ID', 'Malaysia': 'MY',
  'Philippines': 'PH', 'Australia': 'AU', 'New Zealand': 'NZ',
  'Iran': 'IR', 'Israel': 'IL', 'Saudi Arabia': 'SA',
  'United Arab Emirates': 'AE', 'Egypt': 'EG', 'South Africa': 'ZA',
  'Kazakhstan': 'KZ', 'Azerbaijan': 'AZ', 'Georgia': 'GE',
  'Seychelles': 'SC', 'Cyprus': 'CY',
};

function isoFor(country: string | null | undefined): string | null {
  if (!country) return null;
  return COUNTRY_ISO[country.trim()] ?? null;
}

/** Render a country flag image from flagcdn (works on Windows too). */
const Flag: React.FC<{ country: string | null | undefined; size?: number; className?: string }> = ({
  country,
  size = 14,
  className = '',
}) => {
  const iso = isoFor(country);
  if (!iso) {
    return <span aria-hidden="true" className={className} style={{ fontSize: size }}>🌐</span>;
  }
  const w = Math.round(size * 1.4);
  return (
    <img
      src={`https://flagcdn.com/w40/${iso.toLowerCase()}.png`}
      srcSet={`https://flagcdn.com/w80/${iso.toLowerCase()}.png 2x`}
      width={w}
      height={size}
      alt={country ?? ''}
      loading="lazy"
      className={`inline-block rounded-sm shadow-sm align-middle ${className}`}
      style={{ width: w, height: size, objectFit: 'cover' }}
    />
  );
};

const tierStyle = (tier: string) => {
  switch (tier) {
    case 'ADVANCED':
      return {
        ring: 'ring-rose-200',
        bg: 'bg-rose-50',
        text: 'text-rose-700',
        gradient: 'from-rose-500 to-fuchsia-600',
        glow: 'shadow-rose-200/60',
      };
    case 'INTERMEDIATE':
      return {
        ring: 'ring-amber-200',
        bg: 'bg-amber-50',
        text: 'text-amber-700',
        gradient: 'from-amber-400 to-orange-500',
        glow: 'shadow-amber-200/60',
      };
    default:
      return {
        ring: 'ring-slate-200',
        bg: 'bg-slate-50',
        text: 'text-slate-700',
        gradient: 'from-slate-400 to-slate-500',
        glow: 'shadow-slate-200/60',
      };
  }
};

const formatTimeAgo = (iso: string | null): string => {
  if (!iso) return '-';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '-';
  const diffMs = Date.now() - t;
  const m = Math.floor(diffMs / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
};

const AttackerWatchlist: React.FC = () => {
  const [profiles, setProfiles] = useState<AttackerProfile[]>([]);
  const [killChains, setKillChains] = useState<KillChain[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedIp, setExpandedIp] = useState<string | null>(null);

  // Filters
  const [searchIp, setSearchIp] = useState('');
  const [tierFilter, setTierFilter] = useState<'ALL' | 'SCRIPT_KIDDIE' | 'INTERMEDIATE' | 'ADVANCED'>('ALL');
  const [countryFilter, setCountryFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'events' | 'recent' | 'severity'>('events');

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
          setProfiles(d.attackerProfiles ?? []);
          setKillChains(d.killChains ?? []);
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

  const countries = useMemo(() => {
    const set = new Set<string>();
    profiles.forEach((p) => {
      if (p.country) set.add(p.country);
    });
    return Array.from(set).sort();
  }, [profiles]);

  const filtered = useMemo(() => {
    let list = profiles.slice();
    if (searchIp.trim()) {
      const q = searchIp.trim().toLowerCase();
      list = list.filter((p) => p.sourceIp.toLowerCase().includes(q));
    }
    if (tierFilter !== 'ALL') {
      list = list.filter((p) => p.sophistication === tierFilter);
    }
    if (countryFilter !== 'ALL') {
      list = list.filter((p) => p.country === countryFilter);
    }
    if (sortBy === 'events') {
      list.sort((a, b) => b.totalEvents - a.totalEvents);
    } else if (sortBy === 'recent') {
      list.sort((a, b) => {
        const ta = a.lastSeen ? new Date(a.lastSeen).getTime() : 0;
        const tb = b.lastSeen ? new Date(b.lastSeen).getTime() : 0;
        return tb - ta;
      });
    } else if (sortBy === 'severity') {
      list.sort((a, b) => b.highSeverityCount - a.highSeverityCount);
    }
    return list;
  }, [profiles, searchIp, tierFilter, countryFilter, sortBy]);

  const tierCounts = useMemo(() => {
    const c = { SCRIPT_KIDDIE: 0, INTERMEDIATE: 0, ADVANCED: 0 };
    profiles.forEach((p) => {
      if (p.sophistication in c) (c as any)[p.sophistication]++;
    });
    return c;
  }, [profiles]);

  if (loading) {
    return (
      <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-10 text-center">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1.2, repeat: Infinity, ease: 'linear' }}
          className="w-12 h-12 mx-auto mb-3 rounded-full border-4 border-violet-200 border-t-violet-600"
        />
        <p className="text-sm text-slate-500">Loading attacker watchlist…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-rose-50 rounded-2xl ring-1 ring-rose-200 p-6">
        <p className="text-sm text-rose-800 font-semibold">Failed to load watchlist</p>
        <p className="text-xs text-rose-700 mt-1">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Header strip - tier counts */}
      <motion.div
        initial="hidden"
        animate="visible"
        variants={containerVariants}
        className="grid grid-cols-2 md:grid-cols-4 gap-3"
      >
        {[
          {
            label: 'Watchlist size',
            value: profiles.length,
            color: 'from-violet-500 to-fuchsia-500',
            hint: 'Profiled attackers',
          },
          {
            label: 'Advanced tier',
            value: tierCounts.ADVANCED,
            color: 'from-rose-500 to-fuchsia-600',
            hint: 'ICS-aware operators',
          },
          {
            label: 'Intermediate',
            value: tierCounts.INTERMEDIATE,
            color: 'from-amber-400 to-orange-500',
            hint: 'Brute-force / multi-proto',
          },
          {
            label: 'Script kiddie / bot',
            value: tierCounts.SCRIPT_KIDDIE,
            color: 'from-slate-400 to-slate-500',
            hint: 'Opportunistic noise',
          },
        ].map((s, i) => (
          <motion.div
            key={i}
            variants={cardVariants}
            whileHover={{ y: -2, scale: 1.02 }}
            className="relative bg-white rounded-xl ring-1 ring-slate-200/70 shadow-sm p-4 overflow-hidden"
          >
            <div className={`absolute inset-x-0 top-0 h-1 bg-gradient-to-r ${s.color}`} />
            <p className="text-[11px] uppercase tracking-wider font-semibold text-slate-500">
              {s.label}
            </p>
            <p className="mt-1 text-2xl font-bold text-slate-900 tabular-nums">
              {s.value.toLocaleString()}
            </p>
            <p className="text-[11px] text-slate-400 mt-0.5">{s.hint}</p>
          </motion.div>
        ))}
      </motion.div>

      {/* Filter bar */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15 }}
        className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-4 flex flex-wrap items-center gap-3"
      >
        <div className="flex-1 min-w-[180px]">
          <label className="block text-[10px] uppercase font-semibold tracking-wider text-slate-500 mb-1">
            Search IP
          </label>
          <input
            type="text"
            value={searchIp}
            onChange={(e) => setSearchIp(e.target.value)}
            placeholder="e.g. 178.243"
            className="w-full text-sm px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-300 outline-none transition"
          />
        </div>
        <div>
          <label className="block text-[10px] uppercase font-semibold tracking-wider text-slate-500 mb-1">
            Sophistication
          </label>
          <select
            value={tierFilter}
            onChange={(e) => setTierFilter(e.target.value as any)}
            className="text-sm px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-300 outline-none transition bg-white"
          >
            <option value="ALL">All tiers</option>
            <option value="ADVANCED">Advanced</option>
            <option value="INTERMEDIATE">Intermediate</option>
            <option value="SCRIPT_KIDDIE">Script kiddie</option>
          </select>
        </div>
        <div>
          <label className="block text-[10px] uppercase font-semibold tracking-wider text-slate-500 mb-1">
            Country
          </label>
          <select
            value={countryFilter}
            onChange={(e) => setCountryFilter(e.target.value)}
            className="text-sm px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-300 outline-none transition bg-white"
          >
            <option value="ALL">All countries</option>
            {countries.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-[10px] uppercase font-semibold tracking-wider text-slate-500 mb-1">
            Sort by
          </label>
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as any)}
            className="text-sm px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-300 outline-none transition bg-white"
          >
            <option value="events">Most events</option>
            <option value="recent">Most recent</option>
            <option value="severity">High-severity count</option>
          </select>
        </div>
        <div className="ml-auto text-xs text-slate-500 self-end pb-1">
          Showing <span className="font-bold text-slate-900">{filtered.length}</span> /{' '}
          {profiles.length}
        </div>
      </motion.div>

      {/* Card grid */}
      {filtered.length === 0 ? (
        <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-10 text-center">
          <p className="text-sm text-slate-500">No attackers match the current filters.</p>
        </div>
      ) : (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"
        >
          <AnimatePresence>
            {filtered.map((p) => {
              const ts = tierStyle(p.sophistication);
              const expanded = expandedIp === p.sourceIp;
              const chain = killChains.find((k) => k.sourceIp === p.sourceIp);

              return (
                <motion.div
                  key={p.sourceIp}
                  layout
                  variants={cardVariants}
                  whileHover={{ y: -3 }}
                  className={`relative bg-white rounded-2xl ring-1 ${ts.ring} shadow-sm overflow-hidden cursor-pointer hover:shadow-lg transition-shadow ${ts.glow}`}
                  onClick={() => setExpandedIp(expanded ? null : p.sourceIp)}
                >
                  {/* gradient top bar */}
                  <motion.div
                    initial={{ scaleX: 0 }}
                    animate={{ scaleX: 1 }}
                    transition={{ duration: 0.6, ease: 'easeOut' }}
                    style={{ originX: 0 }}
                    className={`absolute inset-x-0 top-0 h-1 bg-gradient-to-r ${ts.gradient}`}
                  />

                  <div className="p-5">
                    {/* Header row: tier + country + last seen */}
                    <div className="flex items-start justify-between gap-2 mb-3">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ring-1 ${ts.bg} ${ts.text} ${ts.ring}`}
                        >
                          {p.sophistication.replace('_', ' ')}
                        </span>
                        {p.country && (
                          <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-slate-600 px-2 py-0.5 rounded-full bg-slate-100">
                            <Flag country={p.country} size={12} />
                            {p.country}
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] font-semibold text-slate-400">
                        {formatTimeAgo(p.lastSeen)}
                      </span>
                    </div>

                    {/* IP + total events */}
                    <div className="flex items-baseline justify-between gap-3 mb-3">
                      <p className="text-base font-mono font-bold text-slate-900 truncate">
                        {p.sourceIp}
                      </p>
                      <p className="text-2xl font-bold text-slate-900 tabular-nums">
                        {p.totalEvents.toLocaleString()}
                      </p>
                    </div>

                    {/* Suspected tool */}
                    <div className="mb-3">
                      <p className="text-[10px] uppercase font-semibold tracking-wider text-slate-400">
                        Suspected tool
                      </p>
                      <p className="text-xs text-slate-700 mt-0.5 truncate">{p.suspectedTool}</p>
                    </div>

                    {/* Protocol pills */}
                    {p.protocols.length > 0 && (
                      <div className="mb-3 flex flex-wrap gap-1">
                        {p.protocols.slice(0, 6).map((proto) => (
                          <span
                            key={proto}
                            className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-violet-50 text-violet-700 ring-1 ring-violet-100"
                          >
                            {proto}
                          </span>
                        ))}
                        {p.protocols.length > 6 && (
                          <span className="text-[10px] font-semibold text-slate-400">
                            +{p.protocols.length - 6}
                          </span>
                        )}
                      </div>
                    )}

                    {/* Mini metrics */}
                    <div className="grid grid-cols-3 gap-2 pt-3 border-t border-slate-100">
                      <div>
                        <p className="text-[10px] uppercase font-semibold tracking-wider text-slate-400">
                          Cred tries
                        </p>
                        <p className="text-sm font-bold text-slate-900 tabular-nums">
                          {p.credentialAttempts.toLocaleString()}
                        </p>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase font-semibold tracking-wider text-slate-400">
                          High sev
                        </p>
                        <p className="text-sm font-bold text-rose-600 tabular-nums">
                          {p.highSeverityCount.toLocaleString()}
                        </p>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase font-semibold tracking-wider text-slate-400">
                          Active
                        </p>
                        <p className="text-sm font-bold text-slate-900 tabular-nums">
                          {p.activeMinutes >= 60
                            ? `${Math.round(p.activeMinutes / 60)}h`
                            : `${p.activeMinutes}m`}
                        </p>
                      </div>
                    </div>

                    {/* Expand affordance */}
                    <div className="mt-3 flex items-center justify-center text-[10px] uppercase font-semibold tracking-wider text-violet-600">
                      {expanded ? '▲ Hide details' : '▼ Show kill chain'}
                    </div>
                  </div>

                  {/* Expanded detail panel */}
                  <AnimatePresence>
                    {expanded && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.3 }}
                        className="border-t border-slate-100 bg-slate-50/50 overflow-hidden"
                      >
                        <div className="p-5">
                          <p className="text-[10px] uppercase font-semibold tracking-wider text-slate-500 mb-3">
                            Kill chain progression
                          </p>
                          {!chain || chain.steps.length === 0 ? (
                            <p className="text-xs text-slate-400">
                              Not enough events to reconstruct a kill chain (need ≥3 distinct
                              tactics).
                            </p>
                          ) : (
                            <div className="relative">
                              <div className="absolute left-2 top-2 bottom-2 w-0.5 bg-gradient-to-b from-violet-400 via-fuchsia-400 to-rose-400" />
                              <ol className="space-y-2.5 pl-1.5">
                                {chain.steps.slice(0, 8).map((step, idx) => (
                                  <motion.li
                                    key={idx}
                                    initial={{ opacity: 0, x: -8 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: 0.05 * idx }}
                                    className="relative flex items-start gap-3 pl-5"
                                  >
                                    <motion.span
                                      initial={{ scale: 0 }}
                                      animate={{ scale: 1 }}
                                      transition={{
                                        type: 'spring',
                                        stiffness: 400,
                                        damping: 12,
                                        delay: 0.1 + idx * 0.05,
                                      }}
                                      className="absolute left-1 top-1 w-2.5 h-2.5 rounded-full bg-white ring-2 ring-violet-500"
                                    />
                                    <div className="flex-1 min-w-0">
                                      <div className="flex items-baseline justify-between gap-2">
                                        <p className="text-xs font-semibold text-slate-900">
                                          {step.tactic}
                                        </p>
                                        <span className="text-[10px] text-slate-400 tabular-nums">
                                          {step.timestamp
                                            ? step.timestamp.replace('T', ' ').slice(11, 19)
                                            : ''}
                                        </span>
                                      </div>
                                      <p className="text-[11px] text-violet-700 mt-0.5">
                                        {step.technique}
                                      </p>
                                      <p className="text-[10px] text-slate-500 mt-0.5">
                                        {step.protocol ?? '-'} · {step.attackType ?? '-'}
                                      </p>
                                    </div>
                                  </motion.li>
                                ))}
                              </ol>
                            </div>
                          )}

                          {/* Attack types */}
                          {p.attackTypes.length > 0 && (
                            <div className="mt-4 pt-3 border-t border-slate-200/70">
                              <p className="text-[10px] uppercase font-semibold tracking-wider text-slate-500 mb-2">
                                Attack types observed
                              </p>
                              <div className="flex flex-wrap gap-1">
                                {p.attackTypes.map((t) => (
                                  <span
                                    key={t}
                                    className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-white text-slate-700 ring-1 ring-slate-200"
                                  >
                                    {t}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* First seen / last seen */}
                          <div className="mt-4 pt-3 border-t border-slate-200/70 grid grid-cols-2 gap-3">
                            <div>
                              <p className="text-[10px] uppercase font-semibold tracking-wider text-slate-500">
                                First seen
                              </p>
                              <p className="text-xs text-slate-700 mt-0.5 tabular-nums">
                                {p.firstSeen
                                  ? p.firstSeen.replace('T', ' ').slice(0, 19)
                                  : '-'}
                              </p>
                            </div>
                            <div>
                              <p className="text-[10px] uppercase font-semibold tracking-wider text-slate-500">
                                Last seen
                              </p>
                              <p className="text-xs text-slate-700 mt-0.5 tabular-nums">
                                {p.lastSeen
                                  ? p.lastSeen.replace('T', ' ').slice(0, 19)
                                  : '-'}
                              </p>
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              );
            })}
          </AnimatePresence>
        </motion.div>
      )}
    </div>
  );
};

export default AttackerWatchlist;
