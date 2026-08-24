import React, { useCallback, useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  siemService, SiemConfig, SiemStats, SiemTestResult,
  SiemProtocol, SiemFormat, SiemSeverity,
} from '../services/siemService';
import { PageHero, Panel, Icon, pageContainer, pageItem } from './theme';

function fmt(ts: string | null): string {
  if (!ts) return '-';
  const d = new Date(ts);
  return isNaN(d.getTime()) ? '-' : d.toLocaleString();
}

const SEVERITIES: SiemSeverity[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const SiemForwarding: React.FC = () => {
  const [config, setConfig] = useState<SiemConfig | null>(null);
  const [stats, setStats] = useState<SiemStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<SiemTestResult | null>(null);

  const loadStats = useCallback(async () => {
    try { setStats(await siemService.getStats()); } catch { /* keep prior */ }
  }, []);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [c, s] = await Promise.all([siemService.getConfig(), siemService.getStats()]);
      setConfig(c);
      setStats(s);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load SIEM forwarding config');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  // live stats refresh
  useEffect(() => {
    const t = setInterval(() => { void loadStats(); }, 8000);
    return () => clearInterval(t);
  }, [loadStats]);

  const set = <K extends keyof SiemConfig>(k: K, v: SiemConfig[K]) =>
    setConfig((c) => (c ? { ...c, [k]: v } : c));

  const save = async () => {
    if (!config) return;
    setSaving(true);
    setSaved(false);
    try {
      const updated = await siemService.updateConfig(config);
      setConfig(updated);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      await loadStats();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  const runTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      // Persist current form first so the test uses what the user sees.
      if (config) await siemService.updateConfig(config);
      const r = await siemService.test();
      setTestResult(r);
      await loadStats();
    } catch (e) {
      setTestResult({ ok: false, error: e instanceof Error ? e.message : 'Test failed' });
    } finally {
      setTesting(false);
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center min-h-[60vh]"><div className="animate-spin rounded-full h-12 w-12 border-4 border-violet-200 border-t-violet-600" /></div>;
  }
  if (error || !config) {
    return <div className="flex items-center justify-center min-h-[60vh]"><div className="rounded-xl bg-rose-50 ring-1 ring-rose-200 text-rose-700 px-6 py-4 font-medium">{error || 'No data'}</div></div>;
  }

  const statusTone = config.enabled
    ? 'bg-emerald-100 text-emerald-700 ring-emerald-200'
    : 'bg-slate-100 text-slate-600 ring-slate-200';

  return (
    <motion.div variants={pageContainer} initial="hidden" animate="visible" className="space-y-6">
      <PageHero
        eyebrow="RESPOND · SIEM INTEGRATION"
        title="SIEM Event Forwarding"
        subtitle="Push OTShield's deception breaches and OT anomalies into the SIEM you already run - Splunk, QRadar, Microsoft Sentinel, Wazuh - as standard syslog or CEF. OTShield does not replace your SOC tooling; it feeds it the OT-specific signals it cannot see on its own."
        icon={<Icon.Network className="w-6 h-6" />}
        stats={[
          { label: 'Events sent', value: stats?.sent ?? 0 },
          { label: 'Failed', value: stats?.failed ?? 0 },
          { label: 'Below threshold', value: stats?.droppedBelowThreshold ?? 0 },
          { label: 'Last sent', value: stats?.lastSentAt ? fmt(stats.lastSentAt).split(',')[1]?.trim() || fmt(stats.lastSentAt) : '-' },
        ]}
      />

      {/* Configuration */}
      <motion.div variants={pageItem}>
        <Panel
          title="Forwarding target"
          subtitle="Where OTShield ships events. Off by default - nothing leaves the platform until you enable it."
          icon={<Icon.Activity className="w-4 h-4" />}
          actions={
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ring-1 ${statusTone}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${config.enabled ? 'bg-emerald-500' : 'bg-slate-400'}`} />
              {config.enabled ? 'Forwarding on' : 'Forwarding off'}
            </span>
          }
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-5">
            {/* Enable toggle */}
            <label className="flex items-center justify-between md:col-span-2 rounded-xl ring-1 ring-slate-200 bg-slate-50 px-4 py-3">
              <div>
                <div className="text-sm font-semibold text-slate-800">Enable forwarding</div>
                <div className="text-xs text-slate-500">When on, breaches forward in real time and new anomalies are tailed every 30s.</div>
              </div>
              <button
                type="button"
                onClick={() => set('enabled', !config.enabled)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition ${config.enabled ? 'bg-violet-600' : 'bg-slate-300'}`}
                aria-pressed={config.enabled}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${config.enabled ? 'translate-x-6' : 'translate-x-1'}`} />
              </button>
            </label>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 mb-1.5">SIEM host / collector IP</label>
              <input
                type="text"
                value={config.host}
                onChange={(e) => set('host', e.target.value)}
                placeholder="e.g. 10.0.0.20 or siem.corp.local"
                className="w-full rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-400 px-3 py-2 text-sm font-mono outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 mb-1.5">Port</label>
              <input
                type="number"
                value={config.port}
                onChange={(e) => set('port', Number(e.target.value))}
                placeholder="514"
                className="w-full rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-400 px-3 py-2 text-sm font-mono outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 mb-1.5">Transport</label>
              <div className="flex gap-2">
                {(['UDP', 'TCP'] as SiemProtocol[]).map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => set('protocol', p)}
                    className={`flex-1 rounded-lg px-3 py-2 text-sm font-semibold ring-1 transition ${config.protocol === p ? 'bg-violet-600 text-white ring-violet-600' : 'bg-white text-slate-600 ring-slate-200 hover:bg-slate-50'}`}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 mb-1.5">Message format</label>
              <div className="flex gap-2">
                {([['CEF', 'CEF (ArcSight)'], ['RFC5424', 'Syslog (RFC 5424)']] as [SiemFormat, string][]).map(([v, label]) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => set('format', v)}
                    className={`flex-1 rounded-lg px-3 py-2 text-xs font-semibold ring-1 transition ${config.format === v ? 'bg-violet-600 text-white ring-violet-600' : 'bg-white text-slate-600 ring-slate-200 hover:bg-slate-50'}`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 mb-1.5">Minimum severity</label>
              <select
                value={config.minSeverity}
                onChange={(e) => set('minSeverity', e.target.value as SiemSeverity)}
                className="w-full rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-400 px-3 py-2 text-sm outline-none bg-white"
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>{s} and above</option>
                ))}
              </select>
            </div>
          </div>

          <div className="mt-6 flex flex-wrap items-center gap-3">
            <button
              onClick={save}
              disabled={saving}
              className="px-4 py-2 text-sm font-semibold text-white rounded-lg bg-gradient-to-r from-violet-500 to-fuchsia-500 hover:shadow-md transition disabled:opacity-50"
            >
              {saving ? 'Saving...' : 'Save configuration'}
            </button>
            <button
              onClick={runTest}
              disabled={testing || !config.host}
              className="px-4 py-2 text-sm font-semibold text-violet-700 rounded-lg bg-violet-50 ring-1 ring-violet-200 hover:bg-violet-100 transition disabled:opacity-50"
            >
              {testing ? 'Sending...' : 'Send test event'}
            </button>
            {saved && <span className="text-sm font-medium text-emerald-600">Saved</span>}
            {!config.host && <span className="text-xs text-slate-400">Enter a host to send a test.</span>}
          </div>

          {testResult && (
            <div className={`mt-4 rounded-xl px-4 py-3 text-sm ring-1 ${testResult.ok ? 'bg-emerald-50 ring-emerald-200 text-emerald-800' : 'bg-rose-50 ring-rose-200 text-rose-800'}`}>
              <div className="font-semibold">
                {testResult.ok ? `Test event sent to ${testResult.target}` : `Test failed: ${testResult.error}`}
              </div>
              {testResult.sample && (
                <pre className="mt-2 overflow-x-auto rounded-lg bg-slate-900 text-slate-100 text-[11px] leading-relaxed p-3 font-mono whitespace-pre-wrap break-all">{testResult.sample}</pre>
              )}
            </div>
          )}
        </Panel>
      </motion.div>

      {/* Runtime / delivery health */}
      <motion.div variants={pageItem}>
        <Panel
          title="Delivery health"
          subtitle="Live counters since the backend started. Updates every 8s."
          icon={<Icon.CheckCircle className="w-4 h-4" />}
        >
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Stat label="Target" value={stats?.target || 'not set'} mono />
            <Stat label="Format" value={stats?.format || config.format} />
            <Stat label="Events sent" value={String(stats?.sent ?? 0)} tone="emerald" />
            <Stat label="Failed" value={String(stats?.failed ?? 0)} tone={(stats?.failed ?? 0) > 0 ? 'rose' : undefined} />
            <Stat label="Dropped (below threshold)" value={String(stats?.droppedBelowThreshold ?? 0)} />
            <Stat label="Min severity" value={stats?.minSeverity || config.minSeverity} />
            <Stat label="Last sent" value={fmt(stats?.lastSentAt ?? null)} />
            <Stat label="Status" value={stats?.enabled ? 'Enabled' : 'Disabled'} tone={stats?.enabled ? 'emerald' : undefined} />
          </div>

          {stats?.lastError && (
            <div className="mt-4 rounded-xl bg-rose-50 ring-1 ring-rose-200 text-rose-700 px-4 py-3 text-sm">
              <span className="font-semibold">Last error: </span>{stats.lastError}
            </div>
          )}

          {stats?.lastMessage && (
            <div className="mt-4">
              <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-1.5">Last message on the wire</div>
              <pre className="overflow-x-auto rounded-lg bg-slate-900 text-slate-100 text-[11px] leading-relaxed p-3 font-mono whitespace-pre-wrap break-all">{stats.lastMessage}</pre>
            </div>
          )}
        </Panel>
      </motion.div>

      {/* What gets forwarded */}
      <motion.div variants={pageItem}>
        <Panel title="What OTShield forwards" subtitle="Real platform signals only - nothing synthetic." icon={<Icon.Bolt className="w-4 h-4" />}>
          <ul className="space-y-3 text-sm text-slate-600">
            <li className="flex gap-3">
              <span className="flex-shrink-0 mt-0.5 w-6 h-6 rounded-lg bg-rose-50 text-rose-600 ring-1 ring-rose-200 flex items-center justify-center text-xs font-bold">1</span>
              <span><span className="font-semibold text-slate-800">Decoy twin writes</span> - an attacker issued a write to a cloned OT device. Forwarded in real time as HIGH. These are false-positive-free by design.</span>
            </li>
            <li className="flex gap-3">
              <span className="flex-shrink-0 mt-0.5 w-6 h-6 rounded-lg bg-rose-50 text-rose-600 ring-1 ring-rose-200 flex items-center justify-center text-xs font-bold">2</span>
              <span><span className="font-semibold text-slate-800">Honeytoken trips</span> - a planted decoy credential or beacon was used. Forwarded in real time as HIGH.</span>
            </li>
            <li className="flex gap-3">
              <span className="flex-shrink-0 mt-0.5 w-6 h-6 rounded-lg bg-amber-50 text-amber-600 ring-1 ring-amber-200 flex items-center justify-center text-xs font-bold">3</span>
              <span><span className="font-semibold text-slate-800">OT anomalies</span> - the detection engine's findings, tailed every 30s and forwarded once each, carrying MITRE ATT&CK for ICS mapping, Purdue level and risk score.</span>
            </li>
          </ul>
        </Panel>
      </motion.div>
    </motion.div>
  );
};

const Stat: React.FC<{ label: string; value: string; mono?: boolean; tone?: 'emerald' | 'rose' }> = ({ label, value, mono, tone }) => {
  const toneClass = tone === 'emerald' ? 'text-emerald-600' : tone === 'rose' ? 'text-rose-600' : 'text-slate-900';
  return (
    <div className="rounded-xl ring-1 ring-slate-200 bg-slate-50/60 px-4 py-3">
      <div className="text-[10px] uppercase tracking-wider text-slate-400">{label}</div>
      <div className={`mt-1 text-lg font-bold ${toneClass} ${mono ? 'font-mono text-sm break-all' : ''}`}>{value}</div>
    </div>
  );
};

export default SiemForwarding;
