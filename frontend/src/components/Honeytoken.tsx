import React, { useEffect, useMemo, useState } from 'react';
import { Icon, PageHero, Panel } from './theme';
import {
  honeytokenService,
  Honeytoken as Token,
  HoneytokenTrip,
  HoneytokenType,
  HoneytokenStats,
} from '../services/honeytokenService';

/**
 * Honeytokens & Lures
 * ============================================================
 * Decoy artifacts (fake credentials, API keys, connection strings, bookmark
 * URLs, document beacons) planted in the REAL environment. No legitimate user
 * has any reason to touch them, so a trip is a false-positive-free breach
 * signal. This turns the deception fabric from a passive trap into an active
 * lure that pulls an intruder toward the decoys and reveals them the moment
 * they take the bait. Every trip auto-opens a SOC case.
 */

interface TypeMeta {
  label: string;
  blurb: string;
  plant: string;
  beacon: boolean; // trips instantly via callback
  icon: React.ReactNode;
}

const TYPE_META: Record<HoneytokenType, TypeMeta> = {
  URL_BEACON: {
    label: 'Bookmark URL',
    blurb: 'A fake HMI / engineering portal link.',
    plant: 'Drop as a browser bookmark or a link in an ops runbook / jump host. It beacons home the instant it is opened.',
    beacon: true,
    icon: <Icon.Eye className="w-4 h-4" />,
  },
  FILE_BEACON: {
    label: 'Document beacon',
    blurb: 'A fake "PLC backup" file that phones home when opened.',
    plant: 'Place on an engineering workstation or file share. It calls the beacon URL the moment someone opens it.',
    beacon: true,
    icon: <Icon.Layers className="w-4 h-4" />,
  },
  CREDENTIAL: {
    label: 'Decoy credential',
    blurb: 'A fake service login no real system uses.',
    plant: 'Seed into a password manager, a script, or a config file. It trips when an attacker harvests and replays it against the decoy fabric.',
    beacon: false,
    icon: <Icon.Lock className="w-4 h-4" />,
  },
  API_KEY: {
    label: 'Decoy API key',
    blurb: 'A fake API key that grants access to nothing.',
    plant: 'Commit to a repo, .env, or CI variable. It trips if the key surfaces in captured decoy telemetry.',
    beacon: false,
    icon: <Icon.Bolt className="w-4 h-4" />,
  },
  CONNECTION_STRING: {
    label: 'DB connection string',
    blurb: 'A fake historian / SCADA DB connection.',
    plant: 'Drop into an app config or a historian export. It trips if the decoy account name is replayed against the fabric.',
    beacon: false,
    icon: <Icon.Server className="w-4 h-4" />,
  },
};

const TYPE_ORDER: HoneytokenType[] = ['URL_BEACON', 'FILE_BEACON', 'CREDENTIAL', 'API_KEY', 'CONNECTION_STRING'];

const timeAgo = (iso?: string | null) => {
  if (!iso) return '-';
  const d = new Date(iso).getTime();
  const s = Math.floor((Date.now() - d) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};

const Honeytoken: React.FC = () => {
  const [tokens, setTokens] = useState<Token[]>([]);
  const [trips, setTrips] = useState<HoneytokenTrip[]>([]);
  const [stats, setStats] = useState<HoneytokenStats | null>(null);
  const [error, setError] = useState<string | null>(null);

  // generator form
  const [newType, setNewType] = useState<HoneytokenType>('URL_BEACON');
  const [newLabel, setNewLabel] = useState('');
  const [newNote, setNewNote] = useState('');
  const [creating, setCreating] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const loadAll = async () => {
    try {
      const [tk, tr, st] = await Promise.all([
        honeytokenService.list(),
        honeytokenService.trips(),
        honeytokenService.stats(),
      ]);
      setTokens(tk);
      setTrips(tr);
      setStats(st);
      setError(null);
    } catch {
      setError('Could not load honeytokens. Is the backend running?');
    }
  };

  useEffect(() => {
    loadAll();
    const t = setInterval(loadAll, 15000); // trips arrive out-of-band; poll
    return () => clearInterval(t);
  }, []);

  const handleCreate = async () => {
    setCreating(true);
    try {
      await honeytokenService.create(newType, newLabel, newNote);
      setNewLabel('');
      setNewNote('');
      await loadAll();
    } catch {
      setError('Could not generate the honeytoken.');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await honeytokenService.remove(id);
      await loadAll();
    } catch {
      /* swallow */
    }
  };

  const copy = (text: string, key: string) => {
    navigator.clipboard?.writeText(text).then(() => {
      setCopied(key);
      setTimeout(() => setCopied((c) => (c === key ? null : c)), 1400);
    });
  };

  const trippedIds = useMemo(() => new Set(trips.map((t) => t.tokenId)), [trips]);

  return (
    <div className="space-y-6">
      <PageHero
        eyebrow="ACTIVE DECEPTION"
        icon={<Icon.Lock className="w-3.5 h-3.5" />}
        title="Honeytokens & Lures"
        subtitle="Plant decoy credentials, keys and beacons in the real environment. No legitimate user touches a lure, so every trip is a high-confidence breach signal that auto-opens a case."
        stats={stats ? [
          { label: 'Lures planted', value: stats.totalTokens, sub: `${stats.trippedTokens} tripped` },
          { label: 'Total trips', value: stats.totalTrips, sub: 'false-positive-free' },
          { label: 'Last trip', value: stats.lastTrippedAt ? timeAgo(stats.lastTrippedAt) : '-', sub: stats.lastTrippedAt ? 'breach signal' : 'none yet' },
        ] : []}
        actions={
          <button
            onClick={loadAll}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-white bg-white/10 hover:bg-white/20 ring-1 ring-white/20 backdrop-blur-sm"
          >
            <Icon.Refresh className="w-4 h-4" /> Refresh
          </button>
        }
      />

      {error && (
        <div className="p-4 rounded-2xl bg-rose-50 ring-1 ring-rose-200 text-rose-700 text-sm">{error}</div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ---- Generator ---- */}
        <Panel
          title="Plant a lure"
          subtitle="Generate a decoy artifact, then drop it where an intruder will find it."
          icon={<Icon.Target className="w-5 h-5" />}
          className="lg:col-span-1 h-fit"
        >
          <div className="space-y-4">
            <div>
              <label className="text-xs font-semibold text-slate-600">Type</label>
              <div className="mt-1.5 grid grid-cols-1 gap-1.5">
                {TYPE_ORDER.map((t) => {
                  const m = TYPE_META[t];
                  const active = newType === t;
                  return (
                    <button
                      key={t}
                      onClick={() => setNewType(t)}
                      className={`text-left px-3 py-2 rounded-xl ring-1 transition flex items-start gap-2.5 ${
                        active ? 'bg-violet-50 ring-violet-300' : 'bg-white ring-slate-200 hover:bg-slate-50'
                      }`}
                    >
                      <span className={`mt-0.5 ${active ? 'text-violet-600' : 'text-slate-400'}`}>{m.icon}</span>
                      <span className="min-w-0">
                        <span className="block text-sm font-semibold text-slate-900">{m.label}</span>
                        <span className="block text-xs text-slate-500 leading-snug">{m.blurb}</span>
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-600">Placement location</label>
              <input
                value={newLabel}
                onChange={(e) => setNewLabel(e.target.value)}
                placeholder="e.g. ENG-WKSTN-01 / Desktop"
                className="mt-1.5 w-full px-3 py-2 rounded-xl ring-1 ring-slate-200 text-sm focus:ring-violet-400 focus:outline-none"
              />
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-600">Note (optional)</label>
              <input
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                placeholder="why / where you planted it"
                className="mt-1.5 w-full px-3 py-2 rounded-xl ring-1 ring-slate-200 text-sm focus:ring-violet-400 focus:outline-none"
              />
            </div>

            <div className="rounded-xl bg-slate-50 ring-1 ring-slate-200 p-3 text-xs text-slate-600 leading-snug">
              {TYPE_META[newType].plant}
            </div>

            <button
              onClick={handleCreate}
              disabled={creating}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold text-white bg-gradient-to-r from-violet-600 to-fuchsia-600 hover:shadow disabled:opacity-50"
            >
              {creating ? 'Generating…' : 'Generate honeytoken'}
            </button>
          </div>
        </Panel>

        {/* ---- Planted tokens ---- */}
        <Panel
          title={`Planted lures (${tokens.length})`}
          subtitle="Copy each payload and drop it into the location you named."
          icon={<Icon.Lock className="w-5 h-5" />}
          className="lg:col-span-2"
        >
          {tokens.length === 0 ? (
            <div className="text-sm text-slate-500 py-8 text-center">
              No lures planted yet. Generate one on the left to start baiting intruders.
            </div>
          ) : (
            <div className="space-y-3">
              {tokens.map((tk) => {
                const m = TYPE_META[tk.type];
                const isTripped = tk.trips > 0 || trippedIds.has(tk.id);
                const payload = m.beacon ? honeytokenService.beaconUrl(tk.id) : tk.tokenValue;
                return (
                  <div
                    key={tk.id}
                    className={`rounded-xl p-3 ring-1 ${
                      isTripped ? 'bg-rose-50 ring-rose-300' : 'bg-white ring-slate-200'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={isTripped ? 'text-rose-600' : 'text-violet-500'}>{m.icon}</span>
                        <span className="text-sm font-semibold text-slate-900">{m.label}</span>
                        <span className="text-xs text-slate-500 truncate">@ {tk.label}</span>
                      </div>
                      <div className="flex items-center gap-2 whitespace-nowrap">
                        {isTripped ? (
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-700">
                            ⚠ TRIPPED · {tk.trips}
                          </span>
                        ) : (
                          <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-600">
                            armed
                          </span>
                        )}
                        <button
                          onClick={() => handleDelete(tk.id)}
                          className="text-[10px] font-semibold px-2 py-1 rounded-lg ring-1 ring-slate-300 text-slate-500 hover:bg-slate-100"
                        >
                          Remove
                        </button>
                      </div>
                    </div>

                    <div className="mt-2 flex items-center gap-2">
                      <code className="flex-1 min-w-0 truncate text-xs bg-slate-900 text-emerald-300 rounded-lg px-2.5 py-1.5 font-mono">
                        {payload}
                      </code>
                      <button
                        onClick={() => copy(payload, tk.id)}
                        className="text-[10px] font-bold px-2.5 py-1.5 rounded-lg bg-violet-100 text-violet-700 hover:bg-violet-200"
                      >
                        {copied === tk.id ? 'Copied' : 'Copy'}
                      </button>
                    </div>

                    <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-slate-500">
                      <span>{m.beacon ? 'Trips instantly when opened' : 'Trips on replay against the fabric'}</span>
                      {isTripped && tk.lastSourceIp && <span className="text-rose-600 font-semibold">last: {tk.lastSourceIp} · {timeAgo(tk.lastTrippedAt)}</span>}
                      {tk.note && <span className="italic">{tk.note}</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </div>

      {/* ---- Trips feed ---- */}
      <Panel
        title="Trip feed"
        subtitle="Every firing is a high-confidence breach event and opens a case automatically."
        icon={<Icon.Alert className="w-5 h-5" />}
      >
        {trips.length === 0 ? (
          <div className="text-sm text-slate-500 py-6 text-center">
            No trips yet. When an intruder takes the bait, it lands here.
          </div>
        ) : (
          <div className="space-y-2">
            {trips.map((t) => (
              <div key={t.id} className="flex items-start gap-3 rounded-xl bg-rose-50/60 ring-1 ring-rose-200 p-3">
                <span className="mt-0.5 text-rose-600"><Icon.Alert className="w-4 h-4" /></span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-semibold text-slate-900">{t.tokenType} tripped</span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-700">
                      {t.method === 'CALLBACK' ? 'beacon opened' : 'credential replayed'}
                    </span>
                    <span className="text-xs text-slate-500">@ {t.tokenLabel}</span>
                    <span className="text-xs text-slate-400 ml-auto">{timeAgo(t.ts)}</span>
                  </div>
                  <div className="text-xs text-slate-600 mt-0.5 break-words">{t.detail}</div>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    source <span className="font-mono text-rose-600">{t.sourceIp}</span>
                    {t.userAgent ? ` · ${t.userAgent}` : ''}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
};

export default Honeytoken;
