import React, { useState } from 'react';
import {
  decoyService,
  Engagement,
  DecoyActionType,
  DecoyActionRequest,
  DecoyActionResult,
} from '../../services/decoyService';
import { Icon } from '../theme';

/**
 * Response Action Bar
 *
 * Surfaces the SOC's response actions for an engagement directly on the page:
 *   - BLOCK_IP / UNBLOCK_IP        (perimeter firewall rule)
 *   - QUARANTINE_SESSION           (move attacker to deception VLAN)
 *   - ESCALATE_ALERT               (raise severity to CRITICAL, push to SOC tier-2)
 *   - ADD_HONEYTOKEN               (plant credential bait on the decoy)
 *   - ADD_BREADCRUMB               (stage a fake engineering file path)
 *   - TAG_ATTACKER                 (annotate attacker profile)
 *
 * Each action goes through a confirm dialog with a free-text justification
 * (audit trail), then optimistically updates the parent via `onActionApplied`.
 */

type ActionDef = {
  type: DecoyActionType;
  label: string;
  intent: 'primary' | 'danger' | 'neutral';
  needsReason: boolean;
  needsParam?: { key: string; label: string; placeholder: string };
};

const ACTIONS: ActionDef[] = [
  { type: 'BLOCK_IP',           label: 'Block attacker IP',     intent: 'danger',  needsReason: true },
  { type: 'QUARANTINE_SESSION', label: 'Quarantine session',    intent: 'danger',  needsReason: true },
  { type: 'ESCALATE_ALERT',     label: 'Escalate to SOC',       intent: 'danger',  needsReason: true },
  { type: 'ADD_HONEYTOKEN',     label: 'Plant honeytoken',      intent: 'primary', needsReason: false,
    needsParam: { key: 'tokenName', label: 'Token name', placeholder: 'credential.bait.svc' } },
  { type: 'ADD_BREADCRUMB',     label: 'Stage breadcrumb file', intent: 'primary', needsReason: false,
    needsParam: { key: 'path', label: 'File path', placeholder: 'C:\\Engineering\\TIA\\Project1.ap16' } },
  { type: 'TAG_ATTACKER',       label: 'Tag attacker',          intent: 'neutral', needsReason: false,
    needsParam: { key: 'tag', label: 'Tag', placeholder: 'MANUAL_REVIEW' } },
];

interface Props {
  engagement: Engagement;
  onActionApplied?: (result: DecoyActionResult) => void;
}

const ResponseActionBar: React.FC<Props> = ({ engagement, onActionApplied }) => {
  const [pending, setPending] = useState<ActionDef | null>(null);
  const [reason, setReason] = useState('');
  const [paramValue, setParamValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const open = (a: ActionDef) => {
    setPending(a);
    setReason('');
    setParamValue('');
  };

  const close = () => {
    setPending(null);
    setBusy(false);
  };

  const flash = (kind: 'ok' | 'err', text: string) => {
    setToast({ kind, text });
    window.setTimeout(() => setToast(null), 4000);
  };

  const apply = async () => {
    if (!pending) return;
    setBusy(true);
    const req: DecoyActionRequest = {
      type: pending.type,
      reason: reason || undefined,
      engagementId: engagement.id,
      decoyInstanceId: engagement.decoyInstanceId,
      targetIp: engagement.attackerIp,
    };
    if (pending.needsParam) {
      req.params = { [pending.needsParam.key]: paramValue || pending.needsParam.placeholder };
    }
    try {
      const res = await decoyService.applyAction(req);
      flash(res.status === 'APPLIED' ? 'ok' : 'err', res.message || res.status);
      onActionApplied?.(res);
      close();
    } catch (e: any) {
      flash('err', e?.message || 'Action failed');
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="flex flex-wrap gap-2">
        {ACTIONS.map(a => (
          <button
            key={a.type}
            onClick={() => open(a)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold ring-1 transition ${
              a.intent === 'danger'
                ? 'bg-rose-50 text-rose-700 ring-rose-200 hover:bg-rose-100'
                : a.intent === 'primary'
                ? 'bg-violet-50 text-violet-700 ring-violet-200 hover:bg-violet-100'
                : 'bg-slate-50 text-slate-700 ring-slate-200 hover:bg-slate-100'
            }`}
          >
            {a.intent === 'danger' && <Icon.Alert className="w-3.5 h-3.5" />}
            {a.intent === 'primary' && <Icon.Bolt className="w-3.5 h-3.5" />}
            {a.intent === 'neutral' && <Icon.Filter className="w-3.5 h-3.5" />}
            {a.label}
          </button>
        ))}
      </div>

      {/* Toast */}
      {toast && (
        <div
          className={`fixed bottom-6 right-6 z-50 px-4 py-3 rounded-xl shadow-lg text-sm font-medium ring-1 ${
            toast.kind === 'ok'
              ? 'bg-emerald-50 text-emerald-800 ring-emerald-200'
              : 'bg-rose-50 text-rose-800 ring-rose-200'
          }`}
        >
          {toast.text}
        </div>
      )}

      {/* Confirm dialog */}
      {pending && (
        <div className="fixed inset-0 z-40 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm">
          <div className="w-full max-w-md bg-white rounded-2xl shadow-2xl ring-1 ring-slate-200 overflow-hidden">
            <div className="p-5 border-b border-slate-100">
              <div className="text-xs uppercase tracking-wider text-violet-600 font-semibold">Response action</div>
              <h3 className="mt-1 text-lg font-bold text-slate-900">{pending.label}</h3>
              <p className="mt-1 text-xs text-slate-500">
                Target attacker: <span className="font-mono">{engagement.attackerIp}</span> · Decoy:{' '}
                <span className="font-mono">{engagement.decoyName}</span>
              </p>
            </div>
            <div className="p-5 space-y-3">
              {pending.needsParam && (
                <label className="block">
                  <span className="text-xs font-semibold text-slate-700">{pending.needsParam.label}</span>
                  <input
                    value={paramValue}
                    onChange={e => setParamValue(e.target.value)}
                    placeholder={pending.needsParam.placeholder}
                    className="mt-1 w-full px-3 py-2 text-sm rounded-lg ring-1 ring-slate-200 focus:ring-violet-400 focus:outline-none"
                  />
                </label>
              )}
              {pending.needsReason && (
                <label className="block">
                  <span className="text-xs font-semibold text-slate-700">Justification (audit trail)</span>
                  <textarea
                    value={reason}
                    onChange={e => setReason(e.target.value)}
                    rows={3}
                    placeholder="Why this action is being taken..."
                    className="mt-1 w-full px-3 py-2 text-sm rounded-lg ring-1 ring-slate-200 focus:ring-violet-400 focus:outline-none"
                  />
                </label>
              )}
              {!pending.needsReason && !pending.needsParam && (
                <p className="text-sm text-slate-600">Apply this action against the current engagement?</p>
              )}
            </div>
            <div className="px-5 py-4 bg-slate-50 flex items-center justify-end gap-2">
              <button
                onClick={close}
                disabled={busy}
                className="px-3 py-1.5 text-sm font-semibold rounded-lg text-slate-600 hover:bg-slate-100"
              >
                Cancel
              </button>
              <button
                onClick={apply}
                disabled={busy || (pending.needsReason && reason.trim().length < 3)}
                className={`px-4 py-1.5 text-sm font-semibold rounded-lg text-white shadow-sm ${
                  pending.intent === 'danger'
                    ? 'bg-gradient-to-r from-rose-500 to-pink-500'
                    : 'bg-gradient-to-r from-violet-500 to-fuchsia-500'
                } disabled:opacity-50`}
              >
                {busy ? 'Applying...' : 'Apply action'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ResponseActionBar;
