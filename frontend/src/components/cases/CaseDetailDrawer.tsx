import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  caseService, CaseDTO, CaseStatus, CaseTimelineEntry, CaseArtifact, CaseArtifactType,
  statusTone, priorityTone, severityDot, formatDuration, ageSince,
} from '../../services/caseService';
import { Icon, theme } from '../theme';

const TERMINAL: CaseStatus[] = ['RESOLVED', 'FALSE_POSITIVE', 'CLOSED'];

const CaseDetailDrawer: React.FC<{
  caseId: string;
  onClose: () => void;
  onChanged?: () => void;
}> = ({ caseId, onClose, onChanged }) => {
  const [caseObj, setCaseObj] = useState<CaseDTO | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setLoading(true);
      const c = await caseService.get(caseId);
      setCaseObj(c);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load case');
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => { void refresh(); }, [refresh]);

  const transition = async (to: CaseStatus, note?: string, resolutionSummary?: string) => {
    if (!caseObj) return;
    setSaving(true);
    try {
      const updated = await caseService.transition(caseObj.id, {
        toStatus: to, note, resolutionSummary, actorName: 'analyst',
      });
      setCaseObj(updated);
      onChanged?.();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-stretch justify-end bg-slate-900/50 backdrop-blur-sm">
      <div className="bg-white w-full max-w-5xl h-full flex flex-col shadow-2xl">
        {/* Header */}
        <div
          className="px-6 py-4 text-white relative overflow-hidden flex-shrink-0"
          style={{ background: theme.gradients.hero }}
        >
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="text-[11px] font-mono uppercase tracking-wider text-violet-200">
                {caseObj?.caseNumber ?? '-'}
              </div>
              <h2 className="mt-1 text-xl md:text-2xl font-bold leading-tight truncate">
                {caseObj?.title ?? 'Loading…'}
              </h2>
              {caseObj && (
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold ring-1 ${statusTone(caseObj.status)}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${severityDot(caseObj.severity)}`} />
                    {caseObj.status.replace('_', ' ')}
                  </span>
                  <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide ring-1 ${priorityTone(caseObj.priority)}`}>
                    {caseObj.priority}
                  </span>
                  {caseObj.category && (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold bg-white/10 ring-1 ring-white/20 text-violet-100">
                      {caseObj.category.replace(/_/g, ' ')}
                    </span>
                  )}
                  <span className="text-[11px] text-violet-200">Opened {ageSince(caseObj.createdAt)} ago</span>
                </div>
              )}
            </div>
            <button
              onClick={onClose}
              className="w-9 h-9 rounded-full bg-white/10 hover:bg-white/20 ring-1 ring-white/20 flex items-center justify-center transition"
              aria-label="Close"
            >
              <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <path d="M18 6 6 18M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 min-h-0 overflow-y-auto">
          {loading && (
            <div className="p-10 text-center text-slate-400 text-sm">Loading case…</div>
          )}
          {error && (
            <div className="p-6 bg-rose-50 text-rose-700 text-sm ring-1 ring-rose-200 m-6 rounded-lg">{error}</div>
          )}
          {caseObj && !loading && (
            <div className="p-6 grid grid-cols-1 xl:grid-cols-3 gap-6">
              {/* Left: info + timeline (2 cols) */}
              <div className="xl:col-span-2 space-y-6">
                <MttCard c={caseObj} />
                <DescriptionCard c={caseObj} />
                <TimelineSection
                  caseId={caseObj.id}
                  timeline={caseObj.timeline ?? []}
                  onAdded={refresh}
                />
              </div>

              {/* Right: actions, assignee, artifacts, alerts */}
              <div className="space-y-6">
                <ActionBar c={caseObj} saving={saving} onTransition={transition} />
                <AssignCard c={caseObj} onChanged={refresh} />
                <ArtifactsCard
                  caseId={caseObj.id}
                  artifacts={caseObj.artifacts ?? []}
                  onChanged={refresh}
                />
                <LinkedAlertsCard c={caseObj} />
                {caseObj.resolutionSummary && (
                  <div className="p-4 rounded-xl bg-emerald-50 ring-1 ring-emerald-200">
                    <div className="text-[11px] uppercase tracking-wider text-emerald-700 font-semibold">Resolution</div>
                    <div className="mt-1 text-sm text-emerald-900 whitespace-pre-wrap">{caseObj.resolutionSummary}</div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// ================================================================
// Sub-panels
// ================================================================

const MttCard: React.FC<{ c: CaseDTO }> = ({ c }) => {
  const items = [
    { label: 'MTT-Ack', value: formatDuration(c.mttAcknowledgeSeconds), sub: c.acknowledgedAt ? new Date(c.acknowledgedAt).toLocaleString() : '-' },
    { label: 'MTT-Contain', value: formatDuration(c.mttContainSeconds), sub: c.containedAt ? new Date(c.containedAt).toLocaleString() : '-' },
    { label: 'MTTR', value: formatDuration(c.mttResolveSeconds), sub: c.resolvedAt ? new Date(c.resolvedAt).toLocaleString() : '-' },
    { label: 'Age', value: ageSince(c.createdAt), sub: new Date(c.createdAt).toLocaleString() },
  ];
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {items.map((x, i) => (
        <div key={i} className="p-3 rounded-xl bg-gradient-to-br from-violet-50 to-fuchsia-50 ring-1 ring-violet-100">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-violet-700">{x.label}</div>
          <div className="mt-0.5 text-xl font-bold text-slate-900 tabular-nums">{x.value}</div>
          <div className="text-[10px] text-slate-500 mt-0.5 truncate" title={x.sub}>{x.sub}</div>
        </div>
      ))}
    </div>
  );
};

const DescriptionCard: React.FC<{ c: CaseDTO }> = ({ c }) => (
  <div className="bg-white rounded-xl ring-1 ring-slate-200 p-5">
    <div className="flex items-center justify-between mb-2">
      <h3 className="text-sm font-semibold text-slate-900">Description</h3>
      <span className="text-[10px] text-slate-400">Reported by {c.reporterName ?? 'system'}</span>
    </div>
    <p className="text-sm text-slate-600 whitespace-pre-wrap leading-relaxed">
      {c.description || <span className="italic text-slate-400">No description provided.</span>}
    </p>
    {c.tags && c.tags.length > 0 && (
      <div className="mt-3 flex flex-wrap gap-1.5">
        {c.tags.map(t => (
          <span key={t} className="text-[11px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-600">#{t}</span>
        ))}
      </div>
    )}
  </div>
);

// ---------- Timeline ----------
const TimelineSection: React.FC<{
  caseId: string;
  timeline: CaseTimelineEntry[];
  onAdded: () => void;
}> = ({ caseId, timeline, onAdded }) => {
  const [comment, setComment] = useState('');
  const [posting, setPosting] = useState(false);

  const sorted = useMemo(
    () => [...timeline].sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime()),
    [timeline]
  );

  const post = async () => {
    if (!comment.trim()) return;
    setPosting(true);
    try {
      await caseService.addComment(caseId, { content: comment.trim(), actorName: 'analyst' });
      setComment('');
      onAdded();
    } finally {
      setPosting(false);
    }
  };

  return (
    <div className="bg-white rounded-xl ring-1 ring-slate-200 p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
          <Icon.Clock className="w-4 h-4 text-violet-500" /> Investigation timeline
        </h3>
        <span className="text-[11px] text-slate-400">{sorted.length} entries</span>
      </div>

      {/* Comment input */}
      <div className="mb-4 p-3 rounded-lg bg-slate-50 ring-1 ring-slate-200">
        <textarea
          value={comment}
          onChange={e => setComment(e.target.value)}
          placeholder="Add an investigation note - what did you check? what's next?"
          rows={2}
          className="w-full px-3 py-2 text-sm bg-white rounded-md ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-500 outline-none"
        />
        <div className="mt-2 flex justify-end">
          <button
            onClick={post}
            disabled={posting || !comment.trim()}
            className="px-3 py-1.5 text-xs font-semibold text-white rounded-md bg-gradient-to-r from-violet-600 to-fuchsia-600 hover:from-violet-700 hover:to-fuchsia-700 disabled:opacity-50"
          >
            {posting ? 'Posting…' : 'Add note'}
          </button>
        </div>
      </div>

      {/* Entries */}
      <ol className="relative border-l-2 border-violet-100 pl-4 space-y-4">
        {sorted.length === 0 && (
          <div className="text-xs text-slate-400 italic py-2">No entries yet.</div>
        )}
        {sorted.map(e => <TimelineRow key={e.id} e={e} />)}
      </ol>
    </div>
  );
};

const TimelineRow: React.FC<{ e: CaseTimelineEntry }> = ({ e }) => {
  const tone = timelineTone(e.entryType);
  return (
    <li className="relative">
      <span
        className={`absolute -left-[22px] top-1 w-3 h-3 rounded-full ring-2 ring-white ${tone.dot}`}
      />
      <div className="flex items-center gap-2 text-[11px] text-slate-500 font-mono">
        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${tone.chip}`}>
          {e.entryType.replace(/_/g, ' ')}
        </span>
        <span>{new Date(e.ts).toLocaleString()}</span>
        {e.actorName && <span>· {e.actorName}</span>}
      </div>
      {e.content && (
        <div className="mt-1 text-sm text-slate-800 whitespace-pre-wrap leading-relaxed">
          {e.content}
        </div>
      )}
    </li>
  );
};

function timelineTone(t: CaseTimelineEntry['entryType']): { dot: string; chip: string } {
  switch (t) {
    case 'CREATED': return { dot: 'bg-violet-500', chip: 'bg-violet-100 text-violet-700' };
    case 'STATUS_CHANGE': return { dot: 'bg-fuchsia-500', chip: 'bg-fuchsia-100 text-fuchsia-700' };
    case 'PRIORITY_CHANGE': return { dot: 'bg-orange-500', chip: 'bg-orange-100 text-orange-700' };
    case 'ASSIGNED':
    case 'UNASSIGNED': return { dot: 'bg-sky-500', chip: 'bg-sky-100 text-sky-700' };
    case 'COMMENT': return { dot: 'bg-slate-400', chip: 'bg-slate-100 text-slate-700' };
    case 'ARTIFACT_ADDED':
    case 'ARTIFACT_REMOVED': return { dot: 'bg-indigo-500', chip: 'bg-indigo-100 text-indigo-700' };
    case 'ALERT_LINKED':
    case 'ALERT_UNLINKED': return { dot: 'bg-pink-500', chip: 'bg-pink-100 text-pink-700' };
    case 'ESCALATED': return { dot: 'bg-rose-500', chip: 'bg-rose-100 text-rose-700' };
    case 'RESOLUTION': return { dot: 'bg-emerald-500', chip: 'bg-emerald-100 text-emerald-700' };
    default: return { dot: 'bg-slate-400', chip: 'bg-slate-100 text-slate-600' };
  }
}

// ---------- Action bar ----------
const ActionBar: React.FC<{
  c: CaseDTO;
  saving: boolean;
  onTransition: (to: CaseStatus, note?: string, resolution?: string) => Promise<void>;
}> = ({ c, saving, onTransition }) => {
  const [showResolve, setShowResolve] = useState(false);
  const [resolutionText, setResolutionText] = useState('');

  const terminal = TERMINAL.includes(c.status);

  return (
    <div className="bg-white rounded-xl ring-1 ring-slate-200 p-4">
      <h3 className="text-sm font-semibold text-slate-900 mb-3">Actions</h3>
      {terminal ? (
        <div className="text-xs text-slate-500 italic">Case is {c.status.replace('_', ' ').toLowerCase()}. No further transitions.</div>
      ) : (
        <div className="space-y-2">
          {c.status === 'NEW' && (
            <button
              onClick={() => void onTransition('TRIAGING', 'Taking into triage')}
              disabled={saving}
              className="w-full px-3 py-2 text-sm font-semibold text-amber-800 bg-amber-100 ring-1 ring-amber-200 rounded-lg hover:bg-amber-200 disabled:opacity-50"
            >Start triaging</button>
          )}
          {(c.status === 'NEW' || c.status === 'TRIAGING') && (
            <button
              onClick={() => void onTransition('INVESTIGATING', 'Moved to active investigation')}
              disabled={saving}
              className="w-full px-3 py-2 text-sm font-semibold text-violet-800 bg-violet-100 ring-1 ring-violet-200 rounded-lg hover:bg-violet-200 disabled:opacity-50"
            >Begin investigation</button>
          )}
          {c.status !== 'CONTAINED' && (
            <button
              onClick={() => void onTransition('CONTAINED', 'Threat contained')}
              disabled={saving}
              className="w-full px-3 py-2 text-sm font-semibold text-indigo-800 bg-indigo-100 ring-1 ring-indigo-200 rounded-lg hover:bg-indigo-200 disabled:opacity-50"
            >Mark contained</button>
          )}
          <button
            onClick={() => setShowResolve(true)}
            disabled={saving}
            className="w-full px-3 py-2 text-sm font-semibold text-white bg-gradient-to-r from-emerald-600 to-teal-600 rounded-lg hover:from-emerald-700 hover:to-teal-700 disabled:opacity-50"
          >Resolve…</button>
          <button
            onClick={() => void onTransition('FALSE_POSITIVE', 'Marked as false positive', resolutionText || 'Classified as false positive after investigation.')}
            disabled={saving}
            className="w-full px-3 py-2 text-sm font-semibold text-slate-700 bg-slate-100 ring-1 ring-slate-200 rounded-lg hover:bg-slate-200 disabled:opacity-50"
          >Mark false positive</button>
        </div>
      )}

      {showResolve && (
        <div className="mt-3 p-3 rounded-lg bg-emerald-50 ring-1 ring-emerald-200">
          <div className="text-[11px] uppercase tracking-wider text-emerald-700 font-semibold mb-1">Resolution summary</div>
          <textarea
            value={resolutionText}
            onChange={e => setResolutionText(e.target.value)}
            placeholder="Root cause, remediation taken, lessons learned…"
            rows={3}
            className="w-full px-2.5 py-1.5 text-sm rounded-md ring-1 ring-emerald-200 bg-white focus:ring-2 focus:ring-emerald-500 outline-none"
          />
          <div className="mt-2 flex justify-end gap-2">
            <button
              onClick={() => { setShowResolve(false); setResolutionText(''); }}
              className="px-3 py-1 text-xs rounded-md ring-1 ring-slate-200 bg-white hover:bg-slate-50"
            >Cancel</button>
            <button
              onClick={async () => {
                await onTransition('RESOLVED', 'Case resolved', resolutionText || 'Resolved.');
                setShowResolve(false); setResolutionText('');
              }}
              disabled={saving}
              className="px-3 py-1 text-xs font-semibold text-white rounded-md bg-gradient-to-r from-emerald-600 to-teal-600 disabled:opacity-50"
            >Confirm resolve</button>
          </div>
        </div>
      )}
    </div>
  );
};

// ---------- Assign ----------
const AssignCard: React.FC<{ c: CaseDTO; onChanged: () => void }> = ({ c, onChanged }) => {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(c.assigneeName ?? '');
  const [saving, setSaving] = useState(false);

  const submit = async () => {
    setSaving(true);
    try {
      await caseService.assign(c.id, {
        assigneeId: name.trim() || undefined,
        assigneeName: name.trim() || undefined,
        actorName: 'analyst',
      });
      setEditing(false);
      onChanged();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-white rounded-xl ring-1 ring-slate-200 p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-slate-900">Assignee</h3>
        {!editing && (
          <button
            onClick={() => setEditing(true)}
            className="text-[11px] text-violet-600 hover:text-violet-800 font-semibold"
          >Change</button>
        )}
      </div>
      {!editing ? (
        c.assigneeName ? (
          <div className="flex items-center gap-2">
            <span className="w-8 h-8 rounded-full bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white flex items-center justify-center text-xs font-bold">
              {initials(c.assigneeName)}
            </span>
            <span className="text-sm font-medium text-slate-800">{c.assigneeName}</span>
          </div>
        ) : (
          <span className="text-xs text-slate-400 italic">Unassigned</span>
        )
      ) : (
        <div className="flex gap-2">
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="Analyst name (blank = unassign)"
            className="flex-1 px-2 py-1 text-sm rounded-md ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-500 outline-none"
          />
          <button
            onClick={submit}
            disabled={saving}
            className="px-3 py-1 text-xs font-semibold text-white rounded-md bg-violet-600 hover:bg-violet-700 disabled:opacity-50"
          >Save</button>
          <button
            onClick={() => { setEditing(false); setName(c.assigneeName ?? ''); }}
            className="px-2 py-1 text-xs rounded-md ring-1 ring-slate-200 bg-white hover:bg-slate-50"
          >✕</button>
        </div>
      )}
    </div>
  );
};

// ---------- Artifacts (IOCs) ----------
const ArtifactsCard: React.FC<{
  caseId: string;
  artifacts: CaseArtifact[];
  onChanged: () => void;
}> = ({ caseId, artifacts, onChanged }) => {
  const [adding, setAdding] = useState(false);
  const [type, setType] = useState<CaseArtifactType>('IP');
  const [value, setValue] = useState('');
  const [label, setLabel] = useState('');

  const submit = async () => {
    if (!value.trim()) return;
    await caseService.addArtifact(caseId, {
      artifactType: type, value: value.trim(), label: label.trim() || undefined,
      malicious: true, actorName: 'analyst',
    });
    setValue(''); setLabel('');
    setAdding(false);
    onChanged();
  };

  const remove = async (artifactId: string) => {
    await caseService.removeArtifact(caseId, artifactId, 'analyst');
    onChanged();
  };

  return (
    <div className="bg-white rounded-xl ring-1 ring-slate-200 p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
          <Icon.Target className="w-4 h-4 text-fuchsia-500" /> IOCs ({artifacts.length})
        </h3>
        <button
          onClick={() => setAdding(v => !v)}
          className="text-[11px] text-violet-600 hover:text-violet-800 font-semibold"
        >{adding ? 'Cancel' : '+ Add'}</button>
      </div>

      {adding && (
        <div className="mb-3 p-2.5 rounded-md bg-violet-50 ring-1 ring-violet-100 space-y-2">
          <div className="flex gap-2">
            <select
              value={type}
              onChange={e => setType(e.target.value as CaseArtifactType)}
              className="px-2 py-1 text-xs rounded-md ring-1 ring-violet-200 bg-white"
            >
              {(['IP','DOMAIN','URL','HASH','FILE','CVE','USER_ACCOUNT','PROCESS','HMI_INTERACTION','COMMAND','OTHER'] as const).map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
            <input
              value={value}
              onChange={e => setValue(e.target.value)}
              placeholder="Value"
              className="flex-1 px-2 py-1 text-xs rounded-md ring-1 ring-violet-200 focus:ring-2 focus:ring-violet-500 outline-none"
            />
          </div>
          <div className="flex gap-2">
            <input
              value={label}
              onChange={e => setLabel(e.target.value)}
              placeholder="Label (optional)"
              className="flex-1 px-2 py-1 text-xs rounded-md ring-1 ring-violet-200 focus:ring-2 focus:ring-violet-500 outline-none"
            />
            <button
              onClick={submit}
              disabled={!value.trim()}
              className="px-3 py-1 text-xs font-semibold text-white rounded-md bg-violet-600 hover:bg-violet-700 disabled:opacity-50"
            >Add</button>
          </div>
        </div>
      )}

      {artifacts.length === 0 ? (
        <div className="text-xs text-slate-400 italic">No artifacts logged.</div>
      ) : (
        <ul className="space-y-1.5">
          {artifacts.map(a => (
            <li key={a.id} className="group flex items-start gap-2 p-2 rounded-md hover:bg-slate-50">
              <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded tracking-wider ${artifactTone(a.artifactType)}`}>
                {a.artifactType}
              </span>
              <div className="flex-1 min-w-0">
                <div className="text-xs font-mono text-slate-800 break-all">{a.value}</div>
                {a.label && <div className="text-[10px] text-slate-500">{a.label}</div>}
              </div>
              <button
                onClick={() => void remove(a.id)}
                className="text-[10px] text-slate-400 hover:text-rose-600 opacity-0 group-hover:opacity-100 transition"
                title="Remove"
              >✕</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

function artifactTone(t: CaseArtifactType) {
  switch (t) {
    case 'IP': return 'bg-rose-100 text-rose-700';
    case 'DOMAIN':
    case 'URL': return 'bg-orange-100 text-orange-700';
    case 'HASH':
    case 'FILE': return 'bg-amber-100 text-amber-800';
    case 'CVE': return 'bg-fuchsia-100 text-fuchsia-700';
    case 'USER_ACCOUNT': return 'bg-sky-100 text-sky-700';
    case 'PROCESS':
    case 'COMMAND': return 'bg-indigo-100 text-indigo-700';
    case 'HMI_INTERACTION': return 'bg-violet-100 text-violet-700';
    default: return 'bg-slate-100 text-slate-600';
  }
}

// ---------- Linked alerts ----------
const LinkedAlertsCard: React.FC<{ c: CaseDTO }> = ({ c }) => {
  const ids = c.linkedAlertIds ?? [];
  return (
    <div className="bg-white rounded-xl ring-1 ring-slate-200 p-4">
      <h3 className="text-sm font-semibold text-slate-900 mb-2 flex items-center gap-2">
        <Icon.Alert className="w-4 h-4 text-rose-500" /> Linked alerts ({ids.length})
      </h3>
      {ids.length === 0 ? (
        <div className="text-xs text-slate-400 italic">No alerts linked yet.</div>
      ) : (
        <ul className="space-y-1">
          {ids.map(id => (
            <li key={id} className="text-[11px] font-mono text-slate-600 px-2 py-1 rounded bg-slate-50 truncate">
              {id}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

// ---------- helpers ----------
function initials(name?: string | null) {
  if (!name) return '?';
  return name.split(/\s+/).slice(0, 2).map(s => s[0]?.toUpperCase() ?? '').join('');
}

export default CaseDetailDrawer;
