import React, { useState } from 'react';
import api from '../../services/api';
import { streamChat, AssistantCitation } from '../../services/assistantService';

/**
 * Copilot tie-in for the Decoy Layer.
 *
 * Given an attacker IP, it asks the backend to build a grounded question that
 * combines what this attacker did on the decoy fabric with the operator's real
 * assets, then streams the research copilot's cited answer to "does this attack
 * threaten my real PLCs?". The answer can then be saved as a SOC case in one
 * click - closing the loop from detection to analysis to a tracked incident.
 */
const DecoyThreatCopilot: React.FC<{ ip: string }> = ({ ip }) => {
  const [answer, setAnswer] = useState('');
  const [citations, setCitations] = useState<AssistantCitation[]>([]);
  const [protocols, setProtocols] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [asked, setAsked] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savedCase, setSavedCase] = useState<string | null>(null);

  const assess = async () => {
    setLoading(true);
    setAsked(true);
    setAnswer('');
    setCitations([]);
    setSavedCase(null);
    try {
      const { data } = await api.get<{ question: string; protocols?: string[] }>(
        `/api/decoy/attackers/${encodeURIComponent(ip)}/threat-question`,
      );
      setProtocols(data.protocols || []);
      await streamChat({
        question: data.question,
        onSources: (c) => setCitations(c),
        onToken: (t) => setAnswer((a) => a + t),
        onDone: () => setLoading(false),
        onError: () => { setAnswer((a) => a || 'Copilot unavailable (is Ollama running?).'); setLoading(false); },
      });
    } catch {
      setAnswer('Could not reach the copilot.');
      setLoading(false);
    }
  };

  const saveCase = async () => {
    setSaving(true);
    try {
      const { data } = await api.post<any>(
        `/api/decoy/attackers/${encodeURIComponent(ip)}/save-case`,
        { assessment: answer, protocols },
      );
      setSavedCase(data?.caseNumber || data?.id || 'saved');
    } catch {
      setSavedCase('error');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="mt-3 rounded-xl ring-1 ring-violet-200 bg-violet-50/50 p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-semibold text-violet-800">
          Does this threaten my real assets?
        </span>
        <button
          onClick={assess}
          disabled={loading}
          className="text-[10px] font-bold px-2.5 py-1 rounded-lg bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white hover:shadow disabled:opacity-50 whitespace-nowrap"
        >
          {loading ? 'Assessing...' : asked ? 'Re-assess' : 'Ask copilot'}
        </button>
      </div>
      {asked && (
        <p className="mt-2 text-xs text-slate-700 whitespace-pre-wrap break-words leading-snug">
          {answer || (loading ? 'Thinking...' : '')}
        </p>
      )}
      {citations.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1 text-[10px] text-violet-700">
          {citations.map((c, i) => (
            <span key={i} className="px-1.5 py-0.5 rounded bg-white ring-1 ring-violet-200">
              [{c.index ?? i + 1}] {c.source}
            </span>
          ))}
        </div>
      )}
      {answer && !loading && (
        <div className="mt-2 flex items-center justify-end gap-2">
          {savedCase && savedCase !== 'error' && (
            <span className="text-[10px] text-emerald-600 font-semibold">Saved as case {savedCase}</span>
          )}
          {savedCase === 'error' && (
            <span className="text-[10px] text-rose-600 font-semibold">Could not save case</span>
          )}
          <button
            onClick={saveCase}
            disabled={saving || (!!savedCase && savedCase !== 'error')}
            className="text-[10px] font-bold px-2.5 py-1 rounded-lg ring-1 ring-violet-300 text-violet-700 bg-white hover:bg-violet-50 disabled:opacity-50 whitespace-nowrap"
          >
            {saving ? 'Saving...' : savedCase && savedCase !== 'error' ? 'Saved' : 'Save as case'}
          </button>
        </div>
      )}
    </div>
  );
};

export default DecoyThreatCopilot;
