import React, { useEffect, useState } from 'react';
import { Panel, Icon } from '../theme';
import { decoyService, SegmentPlacement } from '../../services/decoyService';

/**
 * Segment-aware placement plan - where decoy twins should sit, grouped by
 * network segment + Purdue level and ranked by criticality. Turns "Place" from
 * a protocol-wide suggestion into a topology-aware list driven by the real
 * inventory: each segment with real ICS assets but no in-segment decoy is a gap.
 */
const SegmentPlanPanel: React.FC = () => {
  const [rows, setRows] = useState<SegmentPlacement[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [cloning, setCloning] = useState<string | null>(null);
  const [started, setStarted] = useState<Record<string, string>>({});

  const load = async () => {
    try {
      setRows(await decoyService.getSegmentPlan());
      setError(null);
    } catch {
      setError('Could not load the segment plan.');
    }
  };

  useEffect(() => {
    load();
  }, []);

  const cloneHere = async (seg: SegmentPlacement) => {
    if (!seg.exampleAssetId) return;
    setCloning(seg.subnet);
    try {
      const spec = await decoyService.startTwin(seg.exampleAssetId);
      setStarted((s) => ({ ...s, [seg.subnet]: `${spec.listenHost}:${spec.listenPort}` }));
    } catch {
      setError('Could not start a twin in this segment.');
    } finally {
      setCloning(null);
    }
  };

  if (error) {
    return (
      <Panel title="Segment placement plan" icon={<Icon.Network className="w-5 h-5" />}>
        <div className="text-sm text-rose-600">{error}</div>
      </Panel>
    );
  }

  return (
    <Panel
      title="Segment placement plan"
      subtitle="Where a decoy twin should sit - by network segment and Purdue level"
      icon={<Icon.Network className="w-5 h-5" />}
    >
      {rows.length === 0 ? (
        <div className="text-sm text-slate-500 py-6 text-center">
          No ICS segments discovered yet. Upload a capture so the inventory has devices to place decoys against.
        </div>
      ) : (
        <div className="space-y-2.5">
          {rows.map((s) => (
            <div key={s.subnet} className="rounded-xl p-3 ring-1 bg-white ring-slate-200">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                      s.priority === 'HIGH' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700'
                    }`}
                  >
                    {s.priority}
                  </span>
                  <span className="text-sm font-semibold text-slate-900 font-mono">{s.subnet}</span>
                  <span className="text-xs text-slate-500">{s.purdueLabel}</span>
                  {s.probed && (
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-amber-50 text-amber-700">
                      targeted in the wild
                    </span>
                  )}
                </div>
                {started[s.subnet] ? (
                  <span className="text-[11px] font-semibold text-emerald-700 inline-flex items-center gap-1.5 whitespace-nowrap">
                    <span className="w-2 h-2 rounded-full bg-emerald-500" /> twin live on {started[s.subnet]}
                  </span>
                ) : (
                  <button
                    onClick={() => cloneHere(s)}
                    disabled={cloning === s.subnet}
                    className="text-[10px] font-bold px-2.5 py-1 rounded-lg bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white hover:shadow disabled:opacity-50 whitespace-nowrap"
                  >
                    {cloning === s.subnet ? 'Starting…' : 'Clone a device here'}
                  </button>
                )}
              </div>
              <p className="mt-1.5 text-xs text-slate-600 leading-snug">{s.recommendation}</p>
              <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-slate-500">
                <span>{s.assetCount} asset{s.assetCount === 1 ? '' : 's'}</span>
                <span>{s.protocols.join(', ')}</span>
                <span className={s.protocolMirrored ? 'text-emerald-600' : 'text-slate-400'}>
                  {s.protocolMirrored ? 'protocol mirrored' : 'no decoy shadow'}
                </span>
                {s.samples.length > 0 && <span className="italic truncate">{s.samples.join(' · ')}</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
};

export default SegmentPlanPanel;
