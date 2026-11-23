import React, { useCallback, useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { threatIntelService, FeedSummary, AttackerIntelSummary } from '../services/threatIntelService';
import { PageHero, Panel, Icon, pageContainer, pageItem } from './theme';
import AnonymityBadge from './AnonymityBadge';

function fmt(ts: string | null): string {
  if (!ts) return '-';
  const d = new Date(ts);
  return isNaN(d.getTime()) ? '-' : d.toLocaleString();
}

const OutboundIntelFeed: React.FC = () => {
  const [summary, setSummary] = useState<FeedSummary | null>(null);
  const [iocs, setIocs] = useState<AttackerIntelSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [copied, setCopied] = useState(false);

  const feedUrl = `${window.location.origin}/api/threat-intel/feed`;

  const refresh = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [s, a] = await Promise.all([
        threatIntelService.getFeedSummary(),
        threatIntelService.listAttackers(),
      ]);
      setSummary(s);
      setIocs(a);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load the intel feed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const downloadStix = async () => {
    setDownloading(true);
    try {
      const stix = await threatIntelService.getFeed();
      const blob = new Blob([typeof stix === 'string' ? stix : JSON.stringify(stix, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `otshield-ot-intel-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch { /* ignore */ } finally { setDownloading(false); }
  };

  const copyUrl = async () => {
    try { await navigator.clipboard.writeText(feedUrl); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* ignore */ }
  };

  // Shell-first: render the hero and panels immediately; values stream in behind
  // pulsing skeletons instead of a full-page spinner. Only a hard error bails.
  if (error) {
    return <div className="flex items-center justify-center min-h-[60vh]"><div className="rounded-xl bg-rose-50 ring-1 ring-rose-200 text-rose-700 px-6 py-4 font-medium">{error}</div></div>;
  }

  // Pulsing skeleton in place of a value while the first fetch is in flight.
  // Light tint for the hero (dark bg); callers pass a slate tint for white panels.
  const lv = (node: React.ReactNode, w: string = 'w-10', tint: string = 'bg-white/30') =>
    loading
      ? <span className={`inline-block align-middle rounded ${tint} animate-pulse h-[0.9em] ${w}`} aria-hidden="true" />
      : <>{node}</>;

  const riskTone = (s?: number | null) =>
    s == null ? 'text-slate-400' : s >= 70 ? 'text-rose-600' : s >= 40 ? 'text-amber-600' : 'text-emerald-600';

  return (
    <motion.div variants={pageContainer} initial="hidden" animate="visible" className="space-y-6">
      <PageHero
        eyebrow="DETECT · OUTBOUND INTELLIGENCE"
        title="First-Party OT Threat Intelligence"
        subtitle="You do not just consume threat intel - you produce it. Every attacker that engages the decoy fabric becomes a first-party, OT-specific IOC, published here as a live STIX feed you can share with your ISAC, SIEM or peers."
        icon={<Icon.Bolt className="w-6 h-6" />}
        stats={[
          { label: 'Produced IOCs', value: lv(summary?.producedIocs ?? 0) },
          { label: 'High-risk', value: lv(summary?.highRisk ?? 0) },
          { label: 'Countries', value: lv(summary?.countries ?? 0) },
          { label: 'Tactics covered', value: lv(summary?.tacticsCovered ?? 0) },
        ]}
      />

      {/* Publish / subscribe */}
      <motion.div variants={pageItem}>
        <Panel title="Publish & subscribe" subtitle={loading ? 'Loading live feed…' : `Live feed · updated ${fmt(summary?.lastUpdated ?? null)} · formats: ${(summary?.formats ?? []).join(', ')}`} icon={<Icon.Network className="w-4 h-4" />}>
          <div className="flex flex-wrap items-center gap-3">
            <button onClick={downloadStix} disabled={downloading}
              className="px-4 py-2 text-sm font-semibold text-white rounded-lg bg-gradient-to-r from-violet-500 to-fuchsia-500 hover:shadow-md transition disabled:opacity-50">
              {downloading ? 'Building bundle...' : 'Download STIX 2.1 bundle'}
            </button>
            <div className="flex items-center gap-2 rounded-lg ring-1 ring-slate-200 bg-slate-50 px-3 py-2 text-xs font-mono text-slate-600 min-w-0">
              <span className="truncate">{feedUrl}</span>
              <button onClick={copyUrl} className="flex-shrink-0 text-violet-700 font-semibold hover:text-violet-900">{copied ? 'Copied' : 'Copy'}</button>
            </div>
            <span className="text-xs text-slate-500">Poll this URL (with your API token) to subscribe.</span>
          </div>
          {!loading && summary?.protocols && summary.protocols.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {summary.protocols.map((p) => (
                <span key={p} className="inline-flex px-2 py-0.5 rounded-md text-[11px] font-semibold bg-violet-50 text-violet-700 ring-1 ring-violet-200">{p}</span>
              ))}
            </div>
          )}
        </Panel>
      </motion.div>

      {/* The produced IOC feed */}
      <motion.div variants={pageItem}>
        <Panel title="Published IOCs" subtitle={loading ? 'Loading indicators…' : `${iocs.length} first-party attacker indicators observed on your decoys`} icon={<Icon.Target className="w-4 h-4" />}>
          {!loading && iocs.length === 0 ? (
            <div className="py-10 text-center text-sm text-slate-400">No attacker IOCs observed yet. As attackers engage the decoy fabric they appear here automatically.</div>
          ) : (
            <div className="overflow-x-auto overflow-y-auto max-h-[60vh] rounded-lg ring-1 ring-slate-100">
              <table className="min-w-full text-sm">
                <thead className="sticky top-0 z-10 bg-white">
                  <tr className="text-left text-[11px] uppercase tracking-wide text-slate-400 border-b border-slate-200">
                    <th className="py-2 pr-4 pl-3">Indicator (IP)</th>
                    <th className="py-2 pr-4">Country</th>
                    <th className="py-2 pr-4">Origin</th>
                    <th className="py-2 pr-4">Score</th>
                    <th className="py-2 pr-4">Protocols</th>
                    <th className="py-2 pr-4">Dominant tactic</th>
                    <th className="py-2 pr-4">Techniques</th>
                    <th className="py-2 pr-4">Last seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {loading
                    ? Array.from({ length: 8 }).map((_, i) => (
                        <tr key={`ioc-skel-${i}`}>
                          {Array.from({ length: 8 }).map((__, c) => (
                            <td key={c} className={`py-2 pr-4 ${c === 0 ? 'pl-3' : ''}`}>
                              <div className="h-3 w-full max-w-[110px] rounded bg-slate-200 animate-pulse" />
                            </td>
                          ))}
                        </tr>
                      ))
                    : iocs.map((a) => (
                        <tr key={a.ip} className="hover:bg-slate-50">
                          <td className="py-2 pr-4 pl-3 font-mono text-slate-800">{a.ip}</td>
                          <td className="py-2 pr-4 text-slate-600">{a.countryName || a.country || '-'}</td>
                          <td className="py-2 pr-4"><AnonymityBadge a={a} /></td>
                          <td className={`py-2 pr-4 font-bold ${riskTone(a.threatScore)}`}>{a.threatScore ?? '-'}</td>
                          <td className="py-2 pr-4 text-slate-600">{(a.protocols || []).join(', ') || '-'}</td>
                          <td className="py-2 pr-4 text-slate-600">{a.dominantTactic || '-'}</td>
                          <td className="py-2 pr-4 text-slate-600">{a.distinctTechniques ?? 0}</td>
                          <td className="py-2 pr-4 text-slate-500 whitespace-nowrap">{fmt(a.lastSeen)}</td>
                        </tr>
                      ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </motion.div>
    </motion.div>
  );
};

export default OutboundIntelFeed;
