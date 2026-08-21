import React, { useCallback, useEffect, useState } from 'react';
import { decoyService, AssetCoverage, TwinSpec, TwinInteraction } from '../../services/decoyService';

/**
 * Deception coverage for a single asset - the bridge from the real inventory to
 * the decoy fabric. Answers: is this asset's protocol mirrored by a decoy, and
 * has an attacker probing that protocol already been seen on the fabric? If the
 * asset is exposed (unmirrored), one click deploys a decoy that impersonates it.
 */
interface Props {
  assetId: string;
  assetName?: string;
}

const AssetDeceptionCoverage: React.FC<Props> = ({ assetId, assetName }) => {
  const [cov, setCov] = useState<AssetCoverage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deploying, setDeploying] = useState(false);

  // Digital-twin (Clone) state
  const [twin, setTwin] = useState<TwinSpec | null>(null);
  const [twinRunning, setTwinRunning] = useState(false);
  const [cloning, setCloning] = useState(false);
  const [interactions, setInteractions] = useState<TwinInteraction[]>([]);

  const loadTwin = useCallback(async () => {
    try {
      const [spec, status] = await Promise.all([
        decoyService.getTwinSpec(assetId),
        decoyService.twinStatus(),
      ]);
      setTwin(spec);
      setTwinRunning(!!status.running && status.spec?.assetId === assetId);
    } catch {
      setTwin(null);
      setTwinRunning(false);
    }
  }, [assetId]);

  useEffect(() => {
    loadTwin();
  }, [loadTwin]);

  // Poll interactions while this asset's twin is live.
  useEffect(() => {
    if (!twinRunning) {
      setInteractions([]);
      return;
    }
    let cancelled = false;
    const tick = async () => {
      try {
        const rows = await decoyService.twinInteractions();
        if (!cancelled) setInteractions(rows);
      } catch { /* ignore */ }
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => { cancelled = true; clearInterval(id); };
  }, [twinRunning]);

  const handleClone = async () => {
    setCloning(true);
    try {
      const spec = await decoyService.startTwin(assetId);
      setTwin(spec);
      setTwinRunning(true);
    } catch {
      setError('Could not start the twin.');
    } finally {
      setCloning(false);
    }
  };

  const handleStopTwin = async () => {
    setCloning(true);
    try {
      await decoyService.stopTwin();
      setTwinRunning(false);
      await loadTwin();
    } catch { /* ignore */ } finally {
      setCloning(false);
    }
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const all = await decoyService.getAssetCoverage();
      setCov(all.find((c) => c.assetId === assetId) ?? null);
      setError(null);
    } catch {
      setError('Could not load deception coverage.');
    } finally {
      setLoading(false);
    }
  }, [assetId]);

  useEffect(() => {
    load();
  }, [load]);

  const handleDeploy = async () => {
    if (!cov) return;
    setDeploying(true);
    try {
      await decoyService.deployForAsset(cov);
      await load(); // flips to mirrored
    } catch {
      setError('Deploy failed.');
    } finally {
      setDeploying(false);
    }
  };

  if (loading) {
    return <div className="p-6 text-sm text-slate-500">Loading deception coverage…</div>;
  }
  if (error) {
    return <div className="p-4 rounded-xl bg-rose-50 ring-1 ring-rose-200 text-rose-700 text-sm">{error}</div>;
  }
  if (!cov) {
    return <div className="p-6 text-sm text-slate-500">No coverage data for this asset.</div>;
  }

  // IT gear / unmapped vendor - the fabric only mirrors ICS protocols.
  if (!cov.applicable) {
    return (
      <div className="p-5 rounded-xl bg-slate-50 ring-1 ring-slate-200">
        <div className="text-sm font-semibold text-slate-800">Not an ICS deception target</div>
        <p className="text-sm text-slate-500 mt-1 leading-snug">
          {assetName || cov.assetName} ({cov.manufacturer || 'unknown vendor'}) does not speak an industrial
          protocol the decoy fabric mirrors. Deception focuses on the OT protocols attackers target.
        </p>
      </div>
    );
  }

  const mirrored = cov.mirrored;
  const probed = !!cov.probed;

  return (
    <div className="space-y-4">
      {/* Framing: separate this asset's own traffic from the protocol-level deception signal */}
      <div className="text-[11px] text-slate-500 leading-snug">
        This asset's own operational traffic is in the <span className="font-medium">OT Activity</span> tab. Below is the
        protocol-level deception picture: whether a decoy mirrors this asset's protocol, and the attacks that decoy
        absorbed on its behalf (shared by every {cov.protocol} asset - not direct hits on this internal device).
      </div>

      {/* Coverage status */}
      <div className={`p-5 rounded-xl ring-1 ${mirrored ? 'bg-emerald-50 ring-emerald-200' : 'bg-rose-50 ring-rose-200'}`}>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className={`text-sm font-bold ${mirrored ? 'text-emerald-700' : 'text-rose-700'}`}>
                {mirrored ? '✓ Mirrored by a decoy' : '⚠ Exposed - not mirrored'}
              </span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-white/70 text-slate-600">
                {cov.protocol}
              </span>
            </div>
            <p className="text-sm text-slate-600 mt-1 leading-snug">
              {mirrored ? (
                <>
                  A decoy impersonates this asset's protocol, so an attacker who finds it hits the trap instead of the
                  real device. Decoy: <span className="font-semibold">{cov.decoyName}</span>.
                </>
              ) : (
                <>
                  No decoy currently impersonates this asset's <span className="font-semibold">{cov.protocol}</span>{' '}
                  protocol. Deploy one so attackers probing {cov.protocol} are drawn to the decoy, not this real device.
                </>
              )}
            </p>
          </div>
          {!mirrored && (
            <button
              onClick={handleDeploy}
              disabled={deploying}
              className="shrink-0 text-xs font-bold px-3 py-2 rounded-lg bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white hover:shadow disabled:opacity-50 whitespace-nowrap"
            >
              {deploying ? 'Deploying…' : 'Deploy matching decoy'}
            </button>
          )}
        </div>
      </div>

      {/* Protocol-level deception signal - attacks the decoy absorbed, NOT direct hits on this internal asset */}
      <div className={`p-5 rounded-xl ring-1 ${probed ? 'bg-amber-50 ring-amber-200' : 'bg-slate-50 ring-slate-200'}`}>
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-slate-800">
            {probed ? `${cov.protocol} is targeted in the wild` : 'No probing seen yet'}
          </span>
          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-200 text-slate-600">
            protocol-level
          </span>
        </div>
        {probed ? (
          <p className="text-sm text-slate-600 mt-1 leading-snug">
            The {cov.protocol} decoy absorbed <span className="font-semibold">{cov.attackCount}</span> interactions from{' '}
            <span className="font-semibold">{cov.uniqueAttackers}</span> attacker IP
            {cov.uniqueAttackers === 1 ? '' : 's'}. These hit the internet-exposed decoy - this internal device was
            never touched (it is not internet-reachable)
            {!mirrored && ', and it currently has no decoy in front of it'}. Shared signal across every {cov.protocol} asset.
          </p>
        ) : (
          <p className="text-sm text-slate-500 mt-1 leading-snug">
            No {cov.protocol} probing has landed on the decoy fabric in the analyzed window. Coverage still matters - deploy
            ahead of the threat.
          </p>
        )}
      </div>

      {/* Digital twin (Clone) - a decoy that impersonates THIS asset. */}
      {cov.protocol === 'MODBUS' && (
        <div className="p-5 rounded-xl ring-1 bg-white ring-slate-200">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-slate-800">Digital twin</span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-violet-100 text-violet-700">clone</span>
              <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-600">
                127.0.0.1 only
              </span>
            </div>
            {!twinRunning ? (
              <button
                onClick={handleClone}
                disabled={cloning}
                className="text-xs font-bold px-3 py-2 rounded-lg bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white hover:shadow disabled:opacity-50 whitespace-nowrap"
              >
                {cloning ? 'Starting…' : 'Clone this asset'}
              </button>
            ) : (
              <button
                onClick={handleStopTwin}
                disabled={cloning}
                className="text-xs font-semibold px-3 py-2 rounded-lg ring-1 ring-slate-300 text-slate-600 hover:bg-slate-100 disabled:opacity-50 whitespace-nowrap"
              >
                {cloning ? 'Stopping…' : 'Stop twin'}
              </button>
            )}
          </div>

          <p className="text-sm text-slate-600 mt-1.5 leading-snug">
            Stand up a decoy that impersonates this device - the same{' '}
            <span className="font-semibold">{twin?.vendor}</span>{' '}
            <span className="font-semibold">{twin?.modelName}</span> identity (served on a real MODBUS listener), so an
            attacker fingerprinting it cannot tell it from the real asset. A write to the twin is a breach signal.
            It binds to loopback only - nothing is exposed.
          </p>
          <p className="text-xs text-slate-500 mt-1.5 leading-snug">
            Asset-level attribution: a write here opens a CRITICAL case naming this device - blast radius is this one
            asset, not "some MODBUS device".
          </p>

          {twin?.observedFunctions && twin.observedFunctions.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {twin.observedFunctions.map((f) => (
                <span key={f} className="text-[10px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-600">{f}</span>
              ))}
            </div>
          )}

          {twinRunning && (
            <div className="mt-3">
              <div className="text-xs font-semibold text-emerald-700 bg-emerald-50 ring-1 ring-emerald-200 rounded-lg px-3 py-2 inline-flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                Live on {twin?.listenHost}:{twin?.listenPort}
              </div>
              <div className="mt-2.5">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-1">
                  Interactions ({interactions.length})
                </div>
                {interactions.length === 0 ? (
                  <div className="text-xs text-slate-400 py-2">No interactions yet. Anything that touches this twin lands here.</div>
                ) : (
                  <div className="space-y-1 max-h-56 overflow-y-auto">
                    {interactions.map((it, idx) => (
                      <div
                        key={idx}
                        className={`flex items-center gap-2 text-[11px] rounded-lg px-2.5 py-1.5 ring-1 ${
                          it.write ? 'bg-rose-50 ring-rose-200' : 'bg-slate-50 ring-slate-200'
                        }`}
                      >
                        <span className="font-mono text-slate-500">{it.functionCode}</span>
                        <span className="font-semibold text-slate-800">{it.function}</span>
                        {it.write && (
                          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-rose-100 text-rose-700">breach signal</span>
                        )}
                        <span className="text-slate-500 truncate">{it.detail}</span>
                        <span className="ml-auto font-mono text-slate-400">{it.sourceIp}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default AssetDeceptionCoverage;
