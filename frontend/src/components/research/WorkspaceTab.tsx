import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Panel, Icon, pageItem, theme } from '../theme';
import { useBundles } from '../../contexts/BundleContext';
import api from '../../services/api';

/**
 * Workspace tab — per-bundle settings.
 *
 * <p>Rename the active bundle, edit tags/description, manage the watch
 * folder, and delete the bundle. HMGCC-flavoured: the watch folder is
 * the air-gapped ingest hook for Faz 4.5 (a background poller copies
 * files dropped there into the Library) and the delete guard prevents
 * accidentally wiping the Default Workspace.
 */

const WorkspaceTab: React.FC = () => {
  const {
    activeBundle,
    updateBundle,
    deleteBundle,
    bundles,
    refresh,
  } = useBundles();

  // Edit state is hydrated from the active bundle; dirty-check makes
  // the Save button meaningful.
  const [name, setName] = useState('');
  const [tags, setTags] = useState('');
  const [description, setDescription] = useState('');
  const [watchFolderPath, setWatchFolderPath] = useState('');
  const [watchEnabled, setWatchEnabled] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [reporting, setReporting] = useState(false);

  useEffect(() => {
    if (!activeBundle) return;
    setName(activeBundle.name);
    setTags(activeBundle.tags ?? '');
    setDescription(activeBundle.description ?? '');
    setWatchFolderPath(activeBundle.watchFolderPath ?? '');
    setWatchEnabled(activeBundle.watchEnabled);
    setMessage(null);
    setError(null);
  }, [activeBundle]);

  if (!activeBundle) {
    return (
      <Panel
        title="No active bundle"
        subtitle="Pick a bundle from the sidebar or create a new one."
        icon={<Icon.Layers className="w-5 h-5" />}
      >
        <div className="py-6 text-sm text-slate-500 text-center">
          Select a bundle on the left to edit its settings.
        </div>
      </Panel>
    );
  }

  const dirty =
    name !== activeBundle.name ||
    tags !== (activeBundle.tags ?? '') ||
    description !== (activeBundle.description ?? '') ||
    watchFolderPath !== (activeBundle.watchFolderPath ?? '') ||
    watchEnabled !== activeBundle.watchEnabled;

  const save = async () => {
    if (!dirty) return;
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      await updateBundle(activeBundle.id, {
        name: name.trim(),
        tags: tags.trim(),
        description: description.trim(),
        watchFolderPath: watchFolderPath.trim() || undefined,
        watchEnabled,
      });
      setMessage('Saved.');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  /**
   * Fetch the bundle as a ZIP and trigger a browser download. Uses
   * blob response so axios doesn't attempt to parse it as JSON. We
   * prefer the filename the server suggested via Content-Disposition,
   * falling back to the bundle slug if the header is missing.
   */
  const handleExportSnapshot = async () => {
    if (!activeBundle) return;
    setExporting(true);
    setError(null);
    setMessage(null);
    try {
      const res = await api.get<Blob>(
        `/api/research/bundles/${activeBundle.id}/snapshot.zip`,
        { responseType: 'blob' }
      );
      const disposition = res.headers['content-disposition'] as string | undefined;
      let filename = `otshield-bundle-${activeBundle.slug}.zip`;
      if (disposition) {
        const match = /filename="?([^";]+)"?/.exec(disposition);
        if (match) filename = match[1];
      }
      const blob = res.data instanceof Blob
        ? res.data
        : new Blob([res.data], { type: 'application/zip' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      setMessage(`Downloaded ${filename}.`);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Snapshot download failed');
    } finally {
      setExporting(false);
    }
  };

  /**
   * Fetch the bundle as a polished PDF report and trigger a browser
   * download. Same pattern as {@link handleExportSnapshot} — blob
   * response so axios doesn't try to JSON-parse the bytes, header
   * sniff for filename, object URL for the download trigger.
   */
  const handleExportReport = async () => {
    if (!activeBundle) return;
    setReporting(true);
    setError(null);
    setMessage(null);
    try {
      const res = await api.get<Blob>(
        `/api/research/bundles/${activeBundle.id}/report.pdf`,
        { responseType: 'blob' }
      );
      const disposition = res.headers['content-disposition'] as string | undefined;
      let filename = `otshield-research-report-${activeBundle.slug}.pdf`;
      if (disposition) {
        const match = /filename="?([^";]+)"?/.exec(disposition);
        if (match) filename = match[1];
      }
      const blob = res.data instanceof Blob
        ? res.data
        : new Blob([res.data], { type: 'application/pdf' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      setMessage(`Downloaded ${filename}.`);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Report download failed');
    } finally {
      setReporting(false);
    }
  };

  const handleDelete = async () => {
    if (bundles.length === 1) {
      window.alert('Cannot delete the last bundle - create another one first.');
      return;
    }
    if (!window.confirm(
      `Delete "${activeBundle.name}"?\n\nDocuments, threads, findings and vulns in this bundle stay in the database but become unassigned (bundle_id becomes NULL). You can re-home them by editing each record.`
    )) return;
    try {
      await deleteBundle(activeBundle.id);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Delete failed');
    }
  };

  return (
    <motion.div variants={pageItem} className="space-y-6">
      <Panel
        title="Workspace"
        subtitle="Rename, tag, and configure the active bundle. Settings are scoped to this bundle only."
        icon={<Icon.Layers className="w-5 h-5" />}
        actions={
          <button
            type="button"
            onClick={() => void refresh()}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-700 bg-slate-100 ring-1 ring-slate-200 hover:bg-slate-200 transition inline-flex items-center gap-1.5"
          >
            <Icon.Refresh className="w-3.5 h-3.5" /> Refresh
          </button>
        }
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Labelled label="Name">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
            />
          </Labelled>
          <Labelled label="Slug (read-only)">
            <input
              value={activeBundle.slug}
              readOnly
              className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm bg-slate-50 text-slate-500 font-mono"
            />
          </Labelled>
          <Labelled label="Tags (comma-separated)">
            <input
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="siemens, s7, plc"
              className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
            />
          </Labelled>
          <Labelled label="Description">
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Short note about the scope of this investigation"
              className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
            />
          </Labelled>
        </div>
      </Panel>

      <Panel
        title="Watch folder (air-gapped ingest)"
        subtitle="Point to a local folder. When enabled, the backend poller copies any new file dropped there into the Library for offline hand-offs between machines."
        icon={<Icon.Bolt className="w-5 h-5" />}
      >
        <div className="space-y-3">
          <Labelled label="Watch folder path (server-side absolute)">
            <input
              value={watchFolderPath}
              onChange={(e) => setWatchFolderPath(e.target.value)}
              placeholder="e.g. C:\\ingest\\drop or /var/inbox/ot"
              className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm font-mono"
            />
          </Labelled>
          <label className="inline-flex items-center gap-2 text-sm text-slate-700">
            <input
              type="checkbox"
              checked={watchEnabled}
              onChange={(e) => setWatchEnabled(e.target.checked)}
            />
            Enable watch folder polling
            <span className="text-xs text-slate-400">(poller lives in Faz 4.5 — toggle is saved but inert until then)</span>
          </label>
        </div>
      </Panel>

      {/* Save + message + danger */}
      <div className="bg-white rounded-2xl ring-1 ring-slate-200 shadow-sm p-4 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => void save()}
          disabled={!dirty || saving}
          className={`px-4 py-2 rounded-xl text-sm font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} disabled:opacity-50 hover:shadow-md transition`}
        >
          {saving ? 'Saving…' : 'Save bundle settings'}
        </button>
        <button
          type="button"
          onClick={() => void handleExportSnapshot()}
          disabled={exporting}
          title="Download a single ZIP containing the full bundle — manifest, documents, threads, findings, vulns — for air-gapped hand-off."
          className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-700 bg-slate-100 ring-1 ring-slate-200 hover:bg-slate-200 transition inline-flex items-center gap-1.5 disabled:opacity-50"
        >
          <Icon.Layers className="w-3.5 h-3.5" />
          {exporting ? 'Building…' : 'Export snapshot (.zip)'}
        </button>
        <button
          type="button"
          onClick={() => void handleExportReport()}
          disabled={reporting}
          title="Render a polished PDF report (cover, summary, findings, vulns, transcripts) suitable for handing to a reviewer."
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} hover:shadow-md hover:shadow-violet-500/30 transition inline-flex items-center gap-1.5 disabled:opacity-60`}
        >
          <Icon.CheckCircle className="w-3.5 h-3.5" />
          {reporting ? 'Rendering…' : 'Export report (.pdf)'}
        </button>
        {message && <span className="text-xs text-emerald-700">{message}</span>}
        {error && <span className="text-xs text-rose-700">{error}</span>}
        <div className="flex-1" />
        <button
          type="button"
          onClick={() => void handleDelete()}
          className="px-3 py-1.5 rounded-lg text-xs font-semibold text-rose-700 bg-rose-50 ring-1 ring-rose-200 hover:bg-rose-100 transition"
        >
          Delete bundle
        </button>
      </div>
    </motion.div>
  );
};

const Labelled: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className="flex flex-col gap-1">
    <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</label>
    {children}
  </div>
);

export default WorkspaceTab;
