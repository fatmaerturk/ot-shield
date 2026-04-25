import React, { useEffect, useMemo, useState, useCallback } from 'react';
import {
  threatIntelService,
  AttackerIntelSummary,
  AttackerIntelDetail,
  CampaignCluster,
} from '../services/threatIntelService';
import AttackerList from './threatintel/AttackerList';
import TtpMatrixCanvas from './threatintel/TtpMatrixCanvas';
import CampaignPanel from './threatintel/CampaignPanel';
import IocExportDrawer from './threatintel/IocExportDrawer';
import { Icon, PageHero } from './theme';

const ThreatIntelAttackers: React.FC = () => {
  const [attackers, setAttackers] = useState<AttackerIntelSummary[]>([]);
  const [campaigns, setCampaigns] = useState<CampaignCluster[]>([]);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [detail, setDetail] = useState<AttackerIntelDetail | null>(null);
  const [loadingList, setLoadingList] = useState(false);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerScope, setDrawerScope] = useState<string[]>([]);

  // Filters
  const [filterCountry, setFilterCountry] = useState<string>('');
  const [filterAsn, setFilterAsn] = useState<string>('');
  const [minScore, setMinScore] = useState<number>(0);

  const loadList = useCallback(async () => {
    setLoadingList(true);
    setError(null);
    try {
      const [list, camps] = await Promise.all([
        threatIntelService.listAttackers({
          country: filterCountry || undefined,
          asn: filterAsn || undefined,
          minScore: minScore > 0 ? minScore : undefined,
        }),
        threatIntelService.listCampaigns(),
      ]);
      setAttackers(list);
      setCampaigns(camps);
      // auto-select top attacker if none selected or selection not in list
      if (list.length > 0) {
        const stillThere = selectedIp && list.some(a => a.ip === selectedIp);
        if (!stillThere) {
          setSelectedIp(list[0].ip);
        }
      } else {
        setSelectedIp(null);
        setDetail(null);
      }
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setLoadingList(false);
    }
  }, [filterCountry, filterAsn, minScore, selectedIp]);

  useEffect(() => {
    loadList();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterCountry, filterAsn, minScore]);

  useEffect(() => {
    if (!selectedIp) { setDetail(null); return; }
    let cancelled = false;
    setLoadingDetail(true);
    threatIntelService.getAttacker(selectedIp)
      .then(d => { if (!cancelled) setDetail(d); })
      .catch(e => { if (!cancelled) setError(String(e?.message || e)); })
      .finally(() => { if (!cancelled) setLoadingDetail(false); });
    return () => { cancelled = true; };
  }, [selectedIp]);

  // Derived stats for hero
  const stats = useMemo(() => {
    const total = attackers.length;
    const avgScore = total > 0
      ? Math.round(attackers.reduce((s, a) => s + (a.threatScore || 0), 0) / total)
      : 0;
    const blocked = attackers.filter(a => a.blocked).length;
    const totalTechniques = attackers.reduce((s, a) => s + (a.distinctTechniques || 0), 0);
    const tacticCounts: Record<string, number> = {};
    attackers.forEach(a => {
      if (a.dominantTactic) {
        tacticCounts[a.dominantTactic] = (tacticCounts[a.dominantTactic] || 0) + 1;
      }
    });
    const topTactic = Object.entries(tacticCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || '-';
    const uniqueCountries = new Set(attackers.map(a => a.country).filter(Boolean)).size;
    return {
      total,
      avgScore,
      blocked,
      totalTechniques,
      topTactic,
      uniqueCountries,
      campaignCount: campaigns.length,
    };
  }, [attackers, campaigns]);

  // Country filter options
  const countryOptions = useMemo(() => {
    const set = new Map<string, string>();
    attackers.forEach(a => {
      if (a.country) set.set(a.country, a.countryName || a.country);
    });
    return Array.from(set.entries()).sort((a, b) => a[1].localeCompare(b[1]));
  }, [attackers]);

  const openDrawerForSelected = () => {
    setDrawerScope(selectedIp ? [selectedIp] : []);
    setDrawerOpen(true);
  };
  const openDrawerForAll = () => {
    setDrawerScope([]);
    setDrawerOpen(true);
  };

  const onSelectRelated = (ip: string) => {
    setSelectedIp(ip);
  };

  return (
    <div className="space-y-6">
      <PageHero
        eyebrow="THREAT INTELLIGENCE"
        icon={<Icon.Target className="w-3.5 h-3.5" />}
        title="Attacker TTPs & Behavioral Intel"
        subtitle="Every decoy engagement becomes intel. Aggregate MITRE ATT&CK for ICS coverage per attacker, cluster campaigns by behavioral fingerprint, and ship IOCs to SIEM/TAXII/MISP."
        stats={[
          { label: 'Attackers', value: stats.total, sub: `${stats.uniqueCountries} countries` },
          { label: 'Campaigns', value: stats.campaignCount, sub: `${stats.totalTechniques} TTPs seen` },
          { label: 'Avg threat', value: stats.avgScore, sub: `${stats.blocked} blocked` },
          { label: 'Top tactic', value: stats.topTactic, sub: 'dominant across fleet' },
        ]}
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={openDrawerForSelected}
              disabled={!selectedIp}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-white bg-white/10 hover:bg-white/20 ring-1 ring-white/20 backdrop-blur-sm disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Export IOCs (selected)
            </button>
            <button
              onClick={openDrawerForAll}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-white bg-white/10 hover:bg-white/20 ring-1 ring-white/20 backdrop-blur-sm"
            >
              Export all IOCs
            </button>
          </div>
        }
      />

      {/* Filters */}
      <div>
        <div className="bg-white rounded-2xl ring-1 ring-violet-100 shadow-sm p-3 flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5">
            <label className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Country</label>
            <select
              value={filterCountry}
              onChange={e => setFilterCountry(e.target.value)}
              className="text-[12px] border border-slate-300 rounded px-2 py-1 bg-white"
            >
              <option value="">All</option>
              {countryOptions.map(([cc, name]) => (
                <option key={cc} value={cc}>{name} ({cc})</option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-1.5">
            <label className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">ASN</label>
            <input
              value={filterAsn}
              onChange={e => setFilterAsn(e.target.value)}
              placeholder="AS4134"
              className="text-[12px] border border-slate-300 rounded px-2 py-1 w-32 font-mono"
            />
          </div>
          <div className="flex items-center gap-2 flex-1 min-w-[220px]">
            <label className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider whitespace-nowrap">
              Min score: <span className="text-violet-700 font-bold">{minScore}</span>
            </label>
            <input
              type="range"
              min={0}
              max={100}
              step={5}
              value={minScore}
              onChange={e => setMinScore(Number(e.target.value))}
              className="flex-1 accent-violet-600"
            />
          </div>
          <button
            onClick={() => { setFilterCountry(''); setFilterAsn(''); setMinScore(0); }}
            className="text-[11px] px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold"
          >
            Reset
          </button>
          <button
            onClick={loadList}
            className="text-[11px] px-2 py-1 rounded bg-violet-600 hover:bg-violet-700 text-white font-semibold"
          >
            {loadingList ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* 3-zone layout */}
      <div className="grid grid-cols-12 gap-4">
        {/* LEFT: Attacker list */}
        <div className="col-span-12 lg:col-span-3">
          <div className="bg-white rounded-2xl ring-1 ring-violet-100 shadow-sm p-3 h-[calc(100vh-280px)] min-h-[500px] overflow-y-auto">
            <div className="flex items-center justify-between mb-2 sticky top-0 bg-white pb-2 border-b border-slate-100">
              <h2 className="text-sm font-bold text-slate-900">Attackers</h2>
              <span className="text-[10.5px] text-violet-600 font-semibold">
                {attackers.length} total
              </span>
            </div>
            {loadingList
              ? <div className="text-center text-sm text-slate-400 py-8">Loading attackers…</div>
              : <AttackerList items={attackers} selectedIp={selectedIp} onSelect={setSelectedIp} />
            }
          </div>
        </div>

        {/* CENTER: TTP matrix + selected header */}
        <div className="col-span-12 lg:col-span-6">
          <div className="bg-white rounded-2xl ring-1 ring-violet-100 shadow-sm p-4 h-[calc(100vh-280px)] min-h-[500px] overflow-hidden flex flex-col">
            <SelectedAttackerHeader detail={detail} loading={loadingDetail} />
            <div className="flex-1 overflow-auto mt-3">
              <TtpMatrixCanvas
                matrix={detail?.ttpMatrix || null}
                emptyMessage={selectedIp
                  ? 'Loading ATT&CK coverage…'
                  : 'Select an attacker to view their ATT&CK coverage.'}
              />
            </div>
          </div>
        </div>

        {/* RIGHT: Campaigns + fingerprint */}
        <div className="col-span-12 lg:col-span-3">
          <div className="bg-white rounded-2xl ring-1 ring-violet-100 shadow-sm p-3 h-[calc(100vh-280px)] min-h-[500px] overflow-y-auto">
            <div className="flex items-center justify-between mb-2 sticky top-0 bg-white pb-2 border-b border-slate-100">
              <h2 className="text-sm font-bold text-slate-900">Campaigns & peers</h2>
              {detail && (
                <span className="text-[10px] text-fuchsia-600 font-semibold">
                  {detail.campaigns.length} cluster(s)
                </span>
              )}
            </div>

            {detail && (
              <FingerprintMiniCard detail={detail} />
            )}

            <div className="mt-3">
              <CampaignPanel
                campaigns={detail?.campaigns || []}
                relatedIps={detail?.relatedIps || []}
                onSelectRelated={onSelectRelated}
              />
            </div>

            {detail && detail.iocHighlights.length > 0 && (
              <div className="mt-3 rounded-lg bg-slate-900 ring-1 ring-slate-700 p-3">
                <div className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold mb-1.5">
                  IOC highlights
                </div>
                <div className="font-mono text-[10.5px] text-emerald-300 space-y-0.5 max-h-40 overflow-auto">
                  {detail.iocHighlights.map((h, i) => <div key={i}>{h}</div>)}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {error && (
        <div className="fixed bottom-4 right-4 max-w-md rounded-lg bg-rose-50 ring-1 ring-rose-300 p-3 text-[12px] text-rose-800 shadow-lg z-40">
          <div className="font-semibold mb-0.5">Threat intel error</div>
          {error}
          <button
            onClick={() => setError(null)}
            className="mt-1 text-[10.5px] text-rose-600 hover:text-rose-800 underline"
          >
            Dismiss
          </button>
        </div>
      )}

      <IocExportDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        ips={drawerScope}
      />
    </div>
  );
};

// ---------- Helpers ----------

const SelectedAttackerHeader: React.FC<{ detail: AttackerIntelDetail | null; loading: boolean }> = ({ detail, loading }) => {
  if (loading && !detail) {
    return <div className="text-sm text-slate-400">Loading attacker detail…</div>;
  }
  if (!detail) {
    return (
      <div className="text-sm text-slate-500">
        <span className="font-semibold text-slate-700">No attacker selected.</span> Pick one from the list to see their TTP coverage.
      </div>
    );
  }
  const s = detail.summary;
  return (
    <div className="flex items-start justify-between gap-3 flex-wrap">
      <div>
        <div className="text-[10px] uppercase tracking-wider text-violet-600 font-semibold">Selected attacker</div>
        <div className="flex items-baseline gap-2 flex-wrap">
          <span className="font-mono text-lg font-bold text-slate-900">{s.ip}</span>
          <span className="text-[11.5px] text-slate-500">{s.asn} · {s.asnName || s.countryName}</span>
          {s.blocked && <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-600 text-white font-bold">BLOCKED</span>}
          {s.quarantined && <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500 text-white font-bold">QUAR</span>}
        </div>
        <div className="mt-1 flex flex-wrap gap-1">
          {(s.tags || []).map(t => (
            <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-violet-100 text-violet-700 font-semibold">{t}</span>
          ))}
          {(s.protocols || []).slice(0, 4).map(p => (
            <span key={p} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 font-mono">{p}</span>
          ))}
        </div>
      </div>
      <div className="flex items-center gap-2">
        <div className="text-right">
          <div className="text-[10px] text-slate-500 uppercase tracking-wider">Threat</div>
          <div className="text-2xl font-bold text-rose-600 leading-none">{s.threatScore || 0}</div>
        </div>
        <div className="text-right">
          <div className="text-[10px] text-slate-500 uppercase tracking-wider">Engagements</div>
          <div className="text-2xl font-bold text-violet-600 leading-none">{s.engagementCount}</div>
        </div>
        <div className="text-right">
          <div className="text-[10px] text-slate-500 uppercase tracking-wider">Decoys hit</div>
          <div className="text-2xl font-bold text-fuchsia-600 leading-none">{s.distinctDecoysHit}</div>
        </div>
      </div>
    </div>
  );
};

const FingerprintMiniCard: React.FC<{ detail: AttackerIntelDetail }> = ({ detail }) => {
  const fp = detail.fingerprint;
  const protoEntries = Object.entries(fp.protocolMix || {}).sort((a, b) => b[1] - a[1]).slice(0, 4);
  return (
    <div className="rounded-lg bg-gradient-to-br from-violet-600 to-fuchsia-600 text-white p-3 shadow">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-white/80 font-semibold">Fingerprint</div>
          <div className="font-mono text-[11.5px] font-bold">{fp.hash}</div>
        </div>
        <div className="text-right">
          <div className="text-[10px] text-white/80 uppercase tracking-wider">Pattern</div>
          <div className="text-[11.5px] font-bold truncate max-w-[120px]">{fp.pattern}</div>
        </div>
      </div>
      <div className="mt-2 grid grid-cols-3 gap-1 text-center">
        <MicroBar label="Repeat" value={fp.repetitionScore} />
        <MicroBar label="Night" value={fp.nightRatio * 100} />
        <MicroBar label="Burst" value={fp.burstiness} />
      </div>
      {protoEntries.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {protoEntries.map(([p, c]) => (
            <span key={p} className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-white/20">{p}·{c}</span>
          ))}
        </div>
      )}
      {fp.notableAnomalies.length > 0 && (
        <div className="mt-1.5 text-[10.5px] text-white/90 italic truncate">
          ⚠ {fp.notableAnomalies.slice(0, 2).join(' · ')}
        </div>
      )}
    </div>
  );
};

const MicroBar: React.FC<{ label: string; value: number }> = ({ label, value }) => {
  const v = Math.max(0, Math.min(100, Math.round(value || 0)));
  return (
    <div>
      <div className="text-[9.5px] text-white/80 uppercase tracking-wider">{label}</div>
      <div className="h-1 bg-white/20 rounded-full overflow-hidden mt-0.5">
        <div className="h-full bg-white rounded-full" style={{ width: `${v}%` }} />
      </div>
      <div className="text-[10px] font-bold mt-0.5">{v}</div>
    </div>
  );
};

export default ThreatIntelAttackers;
