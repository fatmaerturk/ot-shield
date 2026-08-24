import React, { useEffect, useState } from 'react';
import api from '../services/api';
import { PageHero, Panel, Icon, pageContainer, pageItem } from './theme';
import { motion } from 'framer-motion';
import { threatIntelService, TtpMatrix, TtpTechnique } from '../services/threatIntelService';

interface MitreMatrixProps {
  /**
   * Optional extra technique IDs to force-highlight (e.g. IDs detected in a
   * pcap). Merged with the techniques the backend reports as observed.
   */
  highlightedTechniqueIds?: string[];
}

/**
 * Renders the real MITRE ATT&CK for ICS matrix served by
 * {@code /api/threat-intel/ttp-matrix}: the full tactic/technique taxonomy the
 * platform tracks, with the cells that were actually observed on the deception
 * fabric highlighted from real observation counts. Nothing here is hard-coded -
 * the taxonomy and the "observed" overlay both come from the backend.
 */
const MitreMatrix: React.FC<MitreMatrixProps> = ({ highlightedTechniqueIds = [] }) => {
  const [matrix, setMatrix] = useState<TtpMatrix | null>(null);
  const [observedIds, setObservedIds] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const data = await threatIntelService.getMatrix();
        if (!cancelled) { setMatrix(data); setError(null); }
      } catch (err: any) {
        if (!cancelled) setError(err?.response?.data?.message || 'Failed to load the ATT&CK for ICS matrix');
      } finally {
        if (!cancelled) setLoading(false);
      }
      // Overlay the techniques actually observed across all attackers (the
      // aggregate honeypot TTP report). IDs appear inside "T0846 Name" strings,
      // so we scan for MITRE ICS ids. Never fabricated - absence keeps cells cold.
      try {
        const rep = await api.get('/api/honeypot/ttp-analysis');
        const ids = (JSON.stringify(rep.data).match(/T0\d{3,4}/g) || []).map(s => s.toUpperCase());
        if (!cancelled) setObservedIds(new Set(ids));
      } catch { /* leave observed empty on failure */ }
    })();
    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-violet-200 border-t-violet-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="rounded-xl bg-rose-50 ring-1 ring-rose-200 text-rose-700 px-6 py-4 font-medium">
          {error}
        </div>
      </div>
    );
  }

  const tactics = (matrix?.tactics ?? []).slice().sort((a, b) => a.order - b.order);
  const highlightSet = new Set(highlightedTechniqueIds.map(id => id.toUpperCase()));
  const isObserved = (t: TtpTechnique) => {
    const id = (t.id || '').toUpperCase();
    return t.observationCount > 0 || highlightSet.has(id) || observedIds.has(id);
  };

  const totalTactics = tactics.length;
  const totalTechniques = tactics.reduce((sum, t) => sum + t.techniques.length, 0);
  const observedCount = tactics.reduce((sum, t) => sum + t.techniques.filter(isObserved).length, 0);
  const maxTechniques = Math.max(1, ...tactics.map(t => t.techniques.length));

  return (
    <motion.div variants={pageContainer} initial="hidden" animate="visible" className="space-y-6">
      <PageHero
        eyebrow="THREAT FRAMEWORK"
        icon={<Icon.Target className="w-4 h-4" />}
        title="MITRE ATT&CK for ICS"
        subtitle="The tactics and techniques the platform tracks, with the ones actually observed on your deception fabric highlighted from real telemetry."
        stats={[
          { label: 'Tactics', value: totalTactics },
          { label: 'Techniques', value: totalTechniques },
          { label: 'Observed', value: observedCount },
        ]}
      />

      <motion.div variants={pageItem}>
        <Panel
          title="ICS Kill Chain Matrix"
          subtitle="Highlighted cells were observed in your environment (real attacker telemetry). The number is the observation count."
          icon={<Icon.Layers className="w-5 h-5" />}
        >
          {tactics.length === 0 ? (
            <div className="py-10 text-center text-sm text-slate-400">No matrix data available yet.</div>
          ) : (
            <div className="overflow-x-auto rounded-xl ring-1 ring-slate-200/70">
              <table className="min-w-full border-collapse">
                <thead>
                  <tr>
                    {tactics.map(tac => (
                      <th
                        key={tac.id || tac.name}
                        className="bg-gradient-to-b from-slate-50 to-slate-100 border-b border-r border-slate-200 p-3 text-center align-top min-w-[140px]"
                      >
                        <div className="text-xs font-bold text-slate-900 uppercase tracking-wide">{tac.name}</div>
                        <div className="text-[10px] text-slate-500 mt-1">
                          {tac.techniques.length} technique{tac.techniques.length === 1 ? '' : 's'}
                        </div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {Array.from({ length: maxTechniques }, (_, i) => (
                    <tr key={i}>
                      {tactics.map(tac => {
                        const technique = tac.techniques[i];
                        const observed = technique ? isObserved(technique) : false;
                        return (
                          <td
                            key={`${tac.id || tac.name}-${i}`}
                            className={`border-b border-r border-slate-200/70 p-1.5 text-xs align-top ${technique ? '' : 'bg-slate-50/50'}`}
                          >
                            {technique && (
                              <div
                                className={`rounded-lg px-2 py-1.5 transition-all duration-150 cursor-default ${
                                  observed
                                    ? 'bg-gradient-to-r from-rose-500 to-fuchsia-500 text-white font-semibold shadow-md ring-1 ring-rose-400/60'
                                    : 'bg-white text-slate-700 hover:bg-violet-50 hover:text-violet-900 ring-1 ring-slate-100'
                                }`}
                                title={`${technique.name} (${technique.id})${technique.observationCount > 0 ? ` - ${technique.observationCount} observation(s)` : ''}`}
                              >
                                {technique.name}
                                {observed && technique.observationCount > 0 && (
                                  <span className="ml-1 font-bold">· {technique.observationCount}</span>
                                )}
                              </div>
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="mt-4 flex items-center gap-4 text-xs text-slate-500">
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-gradient-to-r from-rose-500 to-fuchsia-500"></div>
              <span>Observed in environment</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-white ring-1 ring-slate-200"></div>
              <span>Not currently observed</span>
            </div>
          </div>
        </Panel>
      </motion.div>
    </motion.div>
  );
};

export default MitreMatrix;
