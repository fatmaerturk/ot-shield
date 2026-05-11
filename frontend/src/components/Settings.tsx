import React, { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence, Variants } from 'framer-motion';
import api from '../services/api';
import {
  UserCircleIcon,
  PaintBrushIcon,
  UsersIcon,
  ShieldCheckIcon,
  KeyIcon,
  GlobeAltIcon,
  BellAlertIcon,
  ClipboardDocumentListIcon,
  Cog6ToothIcon,
} from '@heroicons/react/24/outline';

// =====================================================================
// Settings - unified configuration page
// 9 tabs in a left sidebar:
//   1. Profile      - current user, password, 2FA
//   2. Users        - admin user CRUD
//   3. Roles        - RBAC matrix
//   4. API Keys     - honeypot ingest token, rotate
//   5. Alerts       - severity thresholds, notifications
//   6. Tunnel       - Cloudflare tunnel status, forwarder health
//   7. Audit        - every config/security change with filters + export
//   8. Appearance   - theme, language, date format, default landing
//   9. System       - version, DB stats, runtime, danger zone
// =====================================================================

type TabId =
  | 'profile' | 'users' | 'roles' | 'apikeys'
  | 'alerts' | 'tunnel' | 'audit' | 'appearance' | 'system';

interface UserRow {
  id?: string;
  email?: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  role?: string;
  isActive?: boolean;
  isSuspended?: boolean;
  isAdmin?: boolean;
  department?: string;
  lastLoginAt?: string;
  createdAt?: string;
}

interface AuditEntry {
  id: number;
  actor: string;
  action: string;
  description: string;
  targetType: string | null;
  targetId: string | null;
  sourceIp: string | null;
  outcome: string;
  createdAt: string | null;
}

interface SystemStatus {
  backendVersion: string;
  javaVersion: string;
  springProfile: string;
  database: { honeypotLogs: number; alerts: number; auditLogs: number; users: number };
  runtime: { totalMemoryMB: number; freeMemoryMB: number; maxMemoryMB: number; availableProcessors: number; uptime: number };
  health: { databaseReachable: boolean; ingestEndpointEnabled: boolean; retentionCompliant: boolean };
}

interface TunnelStatus {
  tunnelUrl: string;
  ingestToken: string;
  ingestEnabled: boolean;
  eventsLastHour: number;
  totalEvents: number;
}

type IconCmp = React.ComponentType<{ className?: string }>;
const TABS: Array<{ id: TabId; label: string; Icon: IconCmp; group: string }> = [
  { id: 'profile',    label: 'Profile',     Icon: UserCircleIcon,             group: 'You' },
  { id: 'appearance', label: 'Appearance',  Icon: PaintBrushIcon,             group: 'You' },
  { id: 'users',      label: 'Users',       Icon: UsersIcon,                  group: 'Organization' },
  { id: 'roles',      label: 'Roles',       Icon: ShieldCheckIcon,            group: 'Organization' },
  { id: 'apikeys',    label: 'API Keys',    Icon: KeyIcon,                    group: 'Integration' },
  { id: 'tunnel',     label: 'Tunnel',      Icon: GlobeAltIcon,               group: 'Integration' },
  { id: 'alerts',     label: 'Alerts',      Icon: BellAlertIcon,              group: 'Operations' },
  { id: 'audit',      label: 'Audit Log',   Icon: ClipboardDocumentListIcon,  group: 'Operations' },
  { id: 'system',     label: 'System',      Icon: Cog6ToothIcon,              group: 'Operations' },
];

const containerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.05 } },
};
const cardVariants: Variants = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 130, damping: 18 } },
};

const Card: React.FC<React.PropsWithChildren<{ title?: string; description?: string }>> = ({
  title, description, children,
}) => (
  <motion.div
    initial={{ opacity: 0, y: 12 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ type: 'spring', stiffness: 130, damping: 18 }}
    className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-6"
  >
    {(title || description) && (
      <div className="mb-4">
        {title && <h3 className="text-base font-semibold text-slate-900">{title}</h3>}
        {description && <p className="text-xs text-slate-500 mt-0.5">{description}</p>}
      </div>
    )}
    {children}
  </motion.div>
);

const Pill: React.FC<{ tone?: 'emerald' | 'rose' | 'amber' | 'violet' | 'slate'; children: React.ReactNode }> = ({
  tone = 'slate', children,
}) => {
  const map: Record<string, string> = {
    emerald: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
    rose: 'bg-rose-50 text-rose-700 ring-rose-200',
    amber: 'bg-amber-50 text-amber-700 ring-amber-200',
    violet: 'bg-violet-50 text-violet-700 ring-violet-200',
    slate: 'bg-slate-50 text-slate-600 ring-slate-200',
  };
  return (
    <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ring-1 ${map[tone]}`}>
      {children}
    </span>
  );
};

const fmtDate = (iso?: string | null) => {
  if (!iso) return '-';
  return new Date(iso).toLocaleString();
};

const Settings: React.FC = () => {
  const [tab, setTab] = useState<TabId>('profile');
  const [search, setSearch] = useState('');

  // Shared state
  const [me, setMe] = useState<UserRow | null>(null);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [auditFilter, setAuditFilter] = useState('');
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [tunnel, setTunnel] = useState<TunnelStatus | null>(null);
  const [settings, setSettings] = useState<Record<string, any>>({});
  const [savingTimer, setSavingTimer] = useState<number | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  // password & 2FA
  const [oldPwd, setOldPwd] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [pwdMsg, setPwdMsg] = useState<string | null>(null);

  // user create modal
  const [showCreate, setShowCreate] = useState(false);
  const [newUser, setNewUser] = useState({ email: '', username: '', firstName: '', lastName: '', role: 'USER' });

  // === LOADERS ===
  useEffect(() => {
    // Restore theme from localStorage on mount (covers full-page reload).
    const savedTheme = localStorage.getItem('themePreference');
    if (savedTheme) {
      const dark = savedTheme === 'dark'
        || (savedTheme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
      if (dark) document.documentElement.classList.add('dark');
      else document.documentElement.classList.remove('dark');
    }

    api.get<UserRow>('/api/users/me').then((r) => setMe(r.data)).catch(() => {});

    // Defaults so the form is always interactive even if backend is unreachable.
    const defaults: Record<string, any> = {
      tunnelUrl: '',
      ingestToken: '',
      alertSeverityFloor: 'MEDIUM',
      emailNotifications: false,
      slackWebhook: '',
      retentionMonths: 6,
      theme: 'light',
      language: 'en',
      dateFormat: 'ISO',
      defaultLanding: '/attack-intelligence',
      twoFactorEnabled: false,
    };
    setSettings(defaults);

    fetch('http://localhost:8080/api/settings')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setSettings((s) => ({ ...defaults, ...s, ...d })))
      .catch(() => {});

    fetch('http://localhost:8080/api/settings/system-status')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setSystemStatus(d))
      .catch(() => {});

    fetch('http://localhost:8080/api/settings/tunnel-status')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setTunnel(d))
      .catch(() => {});

    fetch('http://localhost:8080/api/settings/audit-log?limit=200')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => Array.isArray(d) && setAudit(d))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (tab === 'users') {
      setUsersLoading(true);
      api.get<any>('/api/users?size=100')
        .then((r) => {
          const list = r.data?.content ?? r.data ?? [];
          setUsers(Array.isArray(list) ? list : []);
        })
        .catch(() => setUsers([]))
        .finally(() => setUsersLoading(false));
    }
    if (tab === 'audit') {
      fetch('http://localhost:8080/api/settings/audit-log?limit=200').then(r => r.json()).then(setAudit).catch(() => {});
    }
    if (tab === 'system') {
      fetch('http://localhost:8080/api/settings/system-status').then(r => r.json()).then(setSystemStatus).catch(() => {});
    }
    if (tab === 'tunnel') {
      fetch('http://localhost:8080/api/settings/tunnel-status').then(r => r.json()).then(setTunnel).catch(() => {});
    }
  }, [tab]);

  const applySideEffects = (key: string, value: any) => {
    // Apply UI changes immediately so the user sees the impact of their choice.
    if (key === 'theme') {
      // 'system' = follow OS preference, otherwise force light/dark.
      let dark = false;
      if (value === 'dark') dark = true;
      else if (value === 'light') dark = false;
      else if (value === 'system') {
        dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      }
      if (dark) document.documentElement.classList.add('dark');
      else document.documentElement.classList.remove('dark');
      localStorage.setItem('darkMode', JSON.stringify(dark));
      localStorage.setItem('themePreference', value);
    }
    if (key === 'language') {
      localStorage.setItem('language', value);
      // Trigger a one-shot reload so any localized strings refresh.
      // We delay slightly so the audit/save fetch has time to fire.
    }
    if (key === 'dateFormat') {
      localStorage.setItem('dateFormat', value);
    }
    if (key === 'defaultLanding') {
      localStorage.setItem('defaultLanding', value);
    }
  };

  const updateSetting = (key: string, value: any) => {
    setSettings((s) => ({ ...s, [key]: value }));
    applySideEffects(key, value);
    if (savingTimer !== null) window.clearTimeout(savingTimer);
    const t = window.setTimeout(() => {
      fetch('http://localhost:8080/api/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [key]: value }),
      }).then(() => setSavedAt(Date.now())).catch(() => {});
    }, 700);
    setSavingTimer(t);
  };

  const rotateToken = async () => {
    if (!window.confirm('Rotate the honeypot ingest token? Your forwarder will stop ingesting until you update OTSHIELD_INGEST_TOKEN env var.')) return;
    const r = await fetch('http://localhost:8080/api/settings/rotate-token', { method: 'POST' });
    if (r.ok) {
      const d = await r.json();
      setSettings((s) => ({ ...s, ingestToken: d.newToken }));
      alert(`New token: ${d.newToken}\n\nUpdate forwarder env var to keep ingestion working.`);
    }
  };

  const changePassword = async () => {
    setPwdMsg(null);
    if (!me?.id) { setPwdMsg('No user loaded'); return; }
    if (newPwd !== confirmPwd) { setPwdMsg('Passwords do not match'); return; }
    if (newPwd.length < 8) { setPwdMsg('Min 8 characters'); return; }
    try {
      await api.post(`/api/users/${me.id}/change-password`, { newPassword: newPwd });
      setPwdMsg('Password changed successfully');
      setOldPwd(''); setNewPwd(''); setConfirmPwd('');
    } catch (e: any) {
      setPwdMsg(e?.response?.data?.message ?? 'Failed to change password');
    }
  };

  const createUser = async () => {
    try {
      await api.post('/api/users', newUser);
      setShowCreate(false);
      setNewUser({ email: '', username: '', firstName: '', lastName: '', role: 'USER' });
      // refresh
      const r = await api.get<any>('/api/users?size=100');
      const list = r.data?.content ?? r.data ?? [];
      setUsers(Array.isArray(list) ? list : []);
    } catch (e: any) {
      alert(e?.response?.data?.message ?? 'Failed to create user');
    }
  };

  const suspendUser = async (id: string) => {
    if (!window.confirm('Suspend this user?')) return;
    try {
      await api.post(`/api/users/${id}/suspend`, {});
      const r = await api.get<any>('/api/users?size=100');
      setUsers(r.data?.content ?? r.data ?? []);
    } catch { /* noop */ }
  };
  const activateUser = async (id: string) => {
    try {
      await api.post(`/api/users/${id}/activate`, {});
      const r = await api.get<any>('/api/users?size=100');
      setUsers(r.data?.content ?? r.data ?? []);
    } catch { /* noop */ }
  };
  const deleteUser = async (id: string) => {
    if (!window.confirm('Delete this user? This cannot be undone.')) return;
    try {
      await api.delete(`/api/users/${id}`);
      const r = await api.get<any>('/api/users?size=100');
      setUsers(r.data?.content ?? r.data ?? []);
    } catch { /* noop */ }
  };

  const filteredUsers = useMemo(() => {
    if (!search.trim()) return users;
    const q = search.toLowerCase();
    return users.filter((u) =>
      [u.email, u.username, u.firstName, u.lastName, u.role, u.department]
        .filter(Boolean).some((v) => (v ?? '').toLowerCase().includes(q)),
    );
  }, [users, search]);

  const filteredAudit = useMemo(() => {
    if (!auditFilter.trim()) return audit;
    const q = auditFilter.toLowerCase();
    return audit.filter((a) =>
      [a.actor, a.action, a.description, a.targetType, a.targetId, a.sourceIp]
        .filter(Boolean).some((v) => (v ?? '').toLowerCase().includes(q)),
    );
  }, [audit, auditFilter]);

  const exportAuditCsv = () => {
    const rows = ['id,createdAt,actor,action,outcome,description,targetType,targetId,sourceIp']
      .concat(audit.map((a) => [
        a.id, a.createdAt, a.actor, a.action, a.outcome,
        (a.description ?? '').replace(/"/g, '""'),
        a.targetType ?? '', a.targetId ?? '', a.sourceIp ?? '',
      ].map(x => `"${x}"`).join(',')));
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'otshield-audit-log.csv'; a.click();
    URL.revokeObjectURL(url);
  };

  // ========================================================================
  return (
    <motion.div className="space-y-6" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }}>
      {/* Hero */}
      <motion.div
        variants={cardVariants}
        className="relative overflow-hidden rounded-2xl p-6 md:p-8 text-white"
        style={{ background: 'linear-gradient(135deg, #1e1b4b 0%, #4c1d95 45%, #7c3aed 100%)' }}
      >
        <div className="absolute -top-16 -right-16 w-56 h-56 rounded-full bg-fuchsia-500/20 blur-3xl" />
        <div className="relative flex items-end justify-between gap-4 flex-wrap">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 ring-1 ring-white/20 text-xs font-semibold tracking-wider backdrop-blur-sm mb-2">
              SETTINGS
            </div>
            <h1 className="text-2xl md:text-3xl font-bold">Workspace Configuration</h1>
            <p className="text-violet-100/80 text-sm mt-1">
              Manage users, integrations, alerting, and platform behavior - every change is audited.
            </p>
          </div>
          {savedAt && (Date.now() - savedAt < 2500) && (
            <Pill tone="emerald">✓ Saved</Pill>
          )}
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-[240px_1fr] gap-6">
        {/* Sidebar */}
        <motion.div variants={cardVariants} className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-2 h-fit sticky top-4">
          {Array.from(new Set(TABS.map((t) => t.group))).map((group) => (
            <div key={group} className="mb-3">
              <p className="px-3 pt-2 pb-1 text-[10px] uppercase tracking-wider font-bold text-slate-400">{group}</p>
              {TABS.filter((t) => t.group === group).map((t) => {
                const TabIcon = t.Icon;
                return (
                  <button
                    key={t.id}
                    onClick={() => setTab(t.id)}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-semibold transition ${
                      tab === t.id
                        ? 'bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white shadow shadow-violet-500/30'
                        : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                    }`}
                  >
                    <TabIcon className="w-4 h-4" />
                    {t.label}
                  </button>
                );
              })}
            </div>
          ))}
        </motion.div>

        {/* Active panel */}
        <div className="space-y-6">
          <motion.div
            key={tab}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2 }}
            className="space-y-6"
          >

              {/* ───── PROFILE ───── */}
              {tab === 'profile' && (
                <>
                  <Card title="Your profile" description="Your account on this workspace.">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Field label="Full name" value={`${me?.firstName ?? ''} ${me?.lastName ?? ''}`.trim() || '-'} />
                      <Field label="Email" value={me?.email ?? '-'} />
                      <Field label="Username" value={me?.username ?? '-'} />
                      <Field label="Role" value={me?.role ?? '-'} />
                      <Field label="Department" value={me?.department ?? '-'} />
                      <Field label="Last login" value={fmtDate(me?.lastLoginAt)} />
                    </div>
                  </Card>

                  <Card title="Change password" description="Use at least 8 characters.">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 max-w-2xl">
                      <Input label="Current password" type="password" value={oldPwd} onChange={setOldPwd} />
                      <Input label="New password" type="password" value={newPwd} onChange={setNewPwd} />
                      <Input label="Confirm password" type="password" value={confirmPwd} onChange={setConfirmPwd} />
                    </div>
                    <div className="mt-4 flex items-center gap-3">
                      <button onClick={changePassword} className="px-4 py-2 rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white text-sm font-semibold hover:shadow-lg hover:shadow-violet-500/30 transition">
                        Update password
                      </button>
                      {pwdMsg && <span className="text-xs text-slate-600">{pwdMsg}</span>}
                    </div>
                  </Card>

                  <Card title="Two-factor authentication" description="Add a second factor to protect your sign-in.">
                    <Toggle label="Enable 2FA" value={!!settings.twoFactorEnabled} onChange={(v) => updateSetting('twoFactorEnabled', v)} />
                    <p className="text-[11px] text-slate-500 mt-3">
                      When enabled, you'll need a one-time code from your authenticator app to sign in.
                    </p>
                  </Card>
                </>
              )}

              {/* ───── APPEARANCE ───── */}
              {tab === 'appearance' && (
                <Card title="Appearance" description="Personalize how the dashboard looks and feels.">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <Select label="Theme" value={settings.theme ?? 'light'} onChange={(v) => updateSetting('theme', v)}
                      options={[{ value: 'light', label: 'Light' }, { value: 'dark', label: 'Dark' }, { value: 'system', label: 'System' }]} />
                    <Select label="Language" value={settings.language ?? 'en'} onChange={(v) => updateSetting('language', v)}
                      options={[{ value: 'en', label: 'English' }, { value: 'tr', label: 'Türkçe' }]} />
                    <Select label="Date format" value={settings.dateFormat ?? 'ISO'} onChange={(v) => updateSetting('dateFormat', v)}
                      options={[
                        { value: 'ISO', label: 'ISO (2026-04-28 14:30)' },
                        { value: 'EU', label: 'EU (28/04/2026 14:30)' },
                        { value: 'US', label: 'US (04/28/2026 2:30 PM)' },
                      ]} />
                    <Select label="Default landing page" value={settings.defaultLanding ?? '/attack-intelligence'} onChange={(v) => updateSetting('defaultLanding', v)}
                      options={[
                        { value: '/attack-intelligence', label: 'Attack Intelligence' },
                        { value: '/alerts', label: 'Alerts' },
                        { value: '/integrations/ics-decoy', label: 'ICS Decoy Telemetry' },
                        { value: '/compliance/nis2', label: 'NIS2 Compliance' },
                      ]} />
                  </div>
                </Card>
              )}

              {/* ───── USERS ───── */}
              {tab === 'users' && (
                <Card title="Users" description="Manage everyone with access to this workspace.">
                  <div className="flex items-center gap-2 mb-4">
                    <input
                      placeholder="Search by name, email, role…"
                      value={search} onChange={(e) => setSearch(e.target.value)}
                      className="flex-1 text-sm px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-300 outline-none"
                    />
                    <button onClick={() => setShowCreate(true)} className="px-3 py-2 rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white text-sm font-semibold hover:shadow-lg transition">
                      + New user
                    </button>
                  </div>
                  {usersLoading ? (
                    <p className="text-xs text-slate-500 py-4">Loading users…</p>
                  ) : filteredUsers.length === 0 ? (
                    <p className="text-xs text-slate-500 py-4">No users.</p>
                  ) : (
                    <div className="overflow-x-auto -mx-6">
                      <table className="w-full text-sm">
                        <thead className="bg-slate-50 text-[11px] uppercase tracking-wider text-slate-500">
                          <tr>
                            <th className="text-left px-4 py-2 font-semibold">User</th>
                            <th className="text-left px-4 py-2 font-semibold">Email</th>
                            <th className="text-left px-4 py-2 font-semibold">Role</th>
                            <th className="text-left px-4 py-2 font-semibold">Status</th>
                            <th className="text-left px-4 py-2 font-semibold">Last login</th>
                            <th className="text-right px-4 py-2 font-semibold">Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredUsers.map((u) => (
                            <tr key={u.id} className="border-t border-slate-100 hover:bg-slate-50">
                              <td className="px-4 py-2">
                                <p className="font-semibold text-slate-900">{`${u.firstName ?? ''} ${u.lastName ?? ''}`.trim() || u.username}</p>
                                <p className="text-[11px] text-slate-500">{u.username}</p>
                              </td>
                              <td className="px-4 py-2 text-xs text-slate-700">{u.email}</td>
                              <td className="px-4 py-2"><Pill tone={u.isAdmin ? 'rose' : 'violet'}>{u.role ?? 'USER'}</Pill></td>
                              <td className="px-4 py-2">
                                {u.isSuspended ? <Pill tone="rose">SUSPENDED</Pill> :
                                 u.isActive ? <Pill tone="emerald">ACTIVE</Pill> : <Pill>INACTIVE</Pill>}
                              </td>
                              <td className="px-4 py-2 text-xs text-slate-500">{fmtDate(u.lastLoginAt)}</td>
                              <td className="px-4 py-2 text-right">
                                <div className="inline-flex gap-1">
                                  {u.isSuspended ? (
                                    <button onClick={() => activateUser(u.id!)} className="text-[11px] text-emerald-700 hover:text-emerald-900 font-semibold">Activate</button>
                                  ) : (
                                    <button onClick={() => suspendUser(u.id!)} className="text-[11px] text-amber-700 hover:text-amber-900 font-semibold">Suspend</button>
                                  )}
                                  <span className="text-slate-300">·</span>
                                  <button onClick={() => deleteUser(u.id!)} className="text-[11px] text-rose-700 hover:text-rose-900 font-semibold">Delete</button>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Card>
              )}

              {/* ───── ROLES ───── */}
              {tab === 'roles' && (
                <Card title="Roles & permissions" description="Built-in roles and the permissions they grant.">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {[
                      { role: 'ADMIN', tone: 'rose' as const, desc: 'Full control: settings, users, billing, danger zone.', perms: ['users.write', 'settings.write', 'alerts.write', 'audit.read', 'system.danger'] },
                      { role: 'ANALYST', tone: 'violet' as const, desc: 'Triage incidents, manage alerts, run threat hunts.', perms: ['alerts.write', 'cases.write', 'audit.read', 'compliance.read'] },
                      { role: 'OPERATOR', tone: 'amber' as const, desc: 'Day-to-day ICS monitoring; can ack alerts but not delete.', perms: ['alerts.ack', 'honeypot.read', 'compliance.read'] },
                      { role: 'USER', tone: 'slate' as const, desc: 'Read-only dashboard access. No mutations.', perms: ['*.read'] },
                    ].map((r) => (
                      <div key={r.role} className="border border-slate-200 rounded-xl p-4">
                        <div className="flex items-center justify-between mb-1">
                          <Pill tone={r.tone}>{r.role}</Pill>
                          <span className="text-[10px] text-slate-400">{r.perms.length} permissions</span>
                        </div>
                        <p className="text-xs text-slate-600 mt-1.5">{r.desc}</p>
                        <div className="mt-2 flex flex-wrap gap-1">
                          {r.perms.map((p) => (
                            <code key={p} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-50 text-slate-700 ring-1 ring-slate-200">{p}</code>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                  <p className="text-[11px] text-slate-500 mt-4">
                    Custom roles are coming. For now, attach a built-in role to each user from the Users tab.
                  </p>
                </Card>
              )}

              {/* ───── API KEYS ───── */}
              {tab === 'apikeys' && (
                <Card title="API Keys" description="Tokens used by external agents (forwarder, integrations) to push data to OTShield.">
                  <div className="space-y-4">
                    <div className="border border-slate-200 rounded-xl p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="text-sm font-semibold text-slate-900">Honeypot ingest token</p>
                          <p className="text-xs text-slate-500 mt-0.5">Forwarder uses this token in the <code>Authorization: Bearer</code> header.</p>
                          <code className="block mt-2 text-[11px] text-violet-700 bg-violet-50 px-2 py-1 rounded select-all break-all">
                            {settings.ingestToken ?? '-'}
                          </code>
                        </div>
                        <button onClick={rotateToken} className="shrink-0 px-3 py-1.5 rounded-lg bg-amber-500 text-white text-xs font-semibold hover:bg-amber-600 transition">
                          Rotate
                        </button>
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-500">
                      ⚠️ Rotating the token will break ingestion until the forwarder is updated with the new value
                      (<code>OTSHIELD_INGEST_TOKEN</code> env var).
                    </p>
                  </div>
                </Card>
              )}

              {/* ───── ALERTS ───── */}
              {tab === 'alerts' && (
                <>
                  <Card title="Alert thresholds" description="Decide which honeypot events become alerts.">
                    <Select label="Minimum severity to alert" value={settings.alertSeverityFloor ?? 'MEDIUM'} onChange={(v) => updateSetting('alertSeverityFloor', v)}
                      options={[
                        { value: 'LOW', label: 'LOW (every event becomes an alert)' },
                        { value: 'MEDIUM', label: 'MEDIUM (default - recommended)' },
                        { value: 'HIGH', label: 'HIGH (critical only)' },
                        { value: 'CRITICAL', label: 'CRITICAL (rare, very noisy)' },
                      ]} />
                  </Card>
                  <Card title="Notifications" description="Where alerts get delivered besides the in-app inbox.">
                    <Toggle label="Email notifications" value={!!settings.emailNotifications} onChange={(v) => updateSetting('emailNotifications', v)} />
                    <div className="mt-4">
                      <Input label="Slack webhook URL" value={settings.slackWebhook ?? ''} onChange={(v) => updateSetting('slackWebhook', v)} placeholder="https://hooks.slack.com/services/..." />
                    </div>
                  </Card>
                </>
              )}

              {/* ───── TUNNEL ───── */}
              {tab === 'tunnel' && (
                <>
                  <Card title="Cloudflare tunnel" description="Public ingest endpoint reachable by the GCP forwarder.">
                    <Input label="Tunnel URL" value={settings.tunnelUrl ?? ''} onChange={(v) => updateSetting('tunnelUrl', v)} placeholder="https://your-tunnel.trycloudflare.com" />
                    <p className="text-[11px] text-slate-500 mt-2">
                      Quick tunnels rotate every restart. Switch to a named tunnel for a stable URL in production.
                    </p>
                  </Card>
                  <Card title="Forwarder health" description="Live ingest activity from the Conpot forwarder.">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <Stat label="Status" value={tunnel?.ingestEnabled ? 'Enabled' : 'Disabled'} tone={tunnel?.ingestEnabled ? 'emerald' : 'rose'} />
                      <Stat label="Events / hour" value={(tunnel?.eventsLastHour ?? 0).toLocaleString()} />
                      <Stat label="Total events" value={(tunnel?.totalEvents ?? 0).toLocaleString()} />
                      <Stat label="Token (masked)" value={tunnel?.ingestToken ?? '-'} mono />
                    </div>
                  </Card>
                </>
              )}

              {/* ───── AUDIT LOG ───── */}
              {tab === 'audit' && (
                <Card title="Audit log" description="Every settings change, login, and alert action is recorded here.">
                  <div className="flex items-center gap-2 mb-3">
                    <input
                      placeholder="Search by actor, action, target…"
                      value={auditFilter} onChange={(e) => setAuditFilter(e.target.value)}
                      className="flex-1 text-sm px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-300 outline-none"
                    />
                    <button onClick={exportAuditCsv} className="px-3 py-2 rounded-lg bg-white ring-1 ring-slate-300 text-slate-700 text-xs font-semibold hover:bg-slate-50">
                      Export CSV
                    </button>
                  </div>
                  {filteredAudit.length === 0 ? (
                    <p className="text-xs text-slate-500 py-6 text-center">No audit entries yet.</p>
                  ) : (
                    <div className="overflow-x-auto -mx-6">
                      <table className="w-full text-sm">
                        <thead className="bg-slate-50 text-[11px] uppercase tracking-wider text-slate-500">
                          <tr>
                            <th className="text-left px-4 py-2 font-semibold">Time</th>
                            <th className="text-left px-4 py-2 font-semibold">Actor</th>
                            <th className="text-left px-4 py-2 font-semibold">Action</th>
                            <th className="text-left px-4 py-2 font-semibold">Description</th>
                            <th className="text-left px-4 py-2 font-semibold">Outcome</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredAudit.map((a) => (
                            <tr key={a.id} className="border-t border-slate-100 hover:bg-slate-50">
                              <td className="px-4 py-2 text-xs text-slate-500 tabular-nums whitespace-nowrap">{fmtDate(a.createdAt)}</td>
                              <td className="px-4 py-2 text-xs font-mono">{a.actor}</td>
                              <td className="px-4 py-2"><Pill tone="violet">{a.action}</Pill></td>
                              <td className="px-4 py-2 text-xs text-slate-700">{a.description}</td>
                              <td className="px-4 py-2">
                                <Pill tone={a.outcome === 'SUCCESS' ? 'emerald' : a.outcome === 'FAILURE' ? 'rose' : 'amber'}>{a.outcome}</Pill>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Card>
              )}

              {/* ───── SYSTEM ───── */}
              {tab === 'system' && (
                <>
                  <Card title="System status" description="Backend health and resource usage.">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <Stat label="Backend version" value={systemStatus?.backendVersion ?? '-'} mono />
                      <Stat label="Java" value={systemStatus?.javaVersion ?? '-'} mono />
                      <Stat label="Profile" value={systemStatus?.springProfile ?? '-'} />
                      <Stat label="CPU cores" value={String(systemStatus?.runtime.availableProcessors ?? 0)} />
                      <Stat label="Memory used"
                        value={`${(systemStatus?.runtime ? systemStatus.runtime.totalMemoryMB - systemStatus.runtime.freeMemoryMB : 0)} MB / ${systemStatus?.runtime.maxMemoryMB ?? 0} MB`} />
                      <Stat label="DB reachable" value={systemStatus?.health.databaseReachable ? 'Yes' : 'No'} tone={systemStatus?.health.databaseReachable ? 'emerald' : 'rose'} />
                      <Stat label="Ingest endpoint" value={systemStatus?.health.ingestEndpointEnabled ? 'Enabled' : 'Disabled'} tone={systemStatus?.health.ingestEndpointEnabled ? 'emerald' : 'rose'} />
                      <Stat label="Retention OK" value={systemStatus?.health.retentionCompliant ? 'Yes' : 'No'} tone="emerald" />
                    </div>
                  </Card>

                  <Card title="Database" description="Row counts across primary tables.">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <Stat label="Honeypot logs" value={(systemStatus?.database.honeypotLogs ?? 0).toLocaleString()} />
                      <Stat label="Alerts" value={(systemStatus?.database.alerts ?? 0).toLocaleString()} />
                      <Stat label="Audit log" value={(systemStatus?.database.auditLogs ?? 0).toLocaleString()} />
                      <Stat label="Users" value={(systemStatus?.database.users ?? 0).toLocaleString()} />
                    </div>
                  </Card>

                  <Card title="Retention" description="How long telemetry is preserved before being archived.">
                    <Input
                      label="Retention months (NIS2 minimum: 6)"
                      type="number"
                      value={String(settings.retentionMonths ?? 6)}
                      onChange={(v) => updateSetting('retentionMonths', parseInt(v, 10) || 6)}
                    />
                  </Card>

                  <Card title="Danger zone" description="Irreversible actions. Take backups first.">
                    <div className="border border-rose-200 bg-rose-50/40 rounded-xl p-4 space-y-3">
                      <DangerRow
                        title="Clear honeypot logs"
                        description="Delete all collected attacker telemetry. Alerts and audit log are preserved."
                        confirm="DELETE LOGS"
                        onConfirm={async () => {
                          await fetch('http://localhost:8080/api/honeypot/logs/clear', { method: 'POST' });
                          alert('Honeypot logs cleared.');
                        }}
                      />
                      <DangerRow
                        title="Reset demo data"
                        description="Resets honeypot logs and alert state for a clean demo run."
                        confirm="RESET DEMO"
                        onConfirm={() => alert('Demo reset is mocked in this build.')}
                      />
                    </div>
                  </Card>
                </>
              )}

          </motion.div>
        </div>
      </div>

      {/* Create user modal */}
      <AnimatePresence>
        {showCreate && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4"
            onClick={() => setShowCreate(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-white rounded-2xl shadow-2xl max-w-lg w-full p-6"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-lg font-bold text-slate-900 mb-4">New user</h3>
              <div className="space-y-3">
                <Input label="Email" value={newUser.email} onChange={(v) => setNewUser({ ...newUser, email: v })} />
                <Input label="Username" value={newUser.username} onChange={(v) => setNewUser({ ...newUser, username: v })} />
                <div className="grid grid-cols-2 gap-3">
                  <Input label="First name" value={newUser.firstName} onChange={(v) => setNewUser({ ...newUser, firstName: v })} />
                  <Input label="Last name" value={newUser.lastName} onChange={(v) => setNewUser({ ...newUser, lastName: v })} />
                </div>
                <Select label="Role" value={newUser.role} onChange={(v) => setNewUser({ ...newUser, role: v })}
                  options={[{ value: 'ADMIN', label: 'Admin' }, { value: 'ANALYST', label: 'Analyst' }, { value: 'OPERATOR', label: 'Operator' }, { value: 'USER', label: 'User' }]} />
              </div>
              <p className="text-[11px] text-slate-500 mt-3">
                A temporary password ("changeme") will be set; the user must change it on first login.
              </p>
              <div className="mt-5 flex justify-end gap-2">
                <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg ring-1 ring-slate-300 text-slate-700 text-sm font-semibold hover:bg-slate-50">Cancel</button>
                <button onClick={createUser} className="px-4 py-2 rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white text-sm font-semibold hover:shadow-lg hover:shadow-violet-500/30">Create</button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

// ───── small primitives ──────────────────────────────────────────────
const Field: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div>
    <p className="text-[10px] uppercase font-bold tracking-wider text-slate-500">{label}</p>
    <p className="text-sm text-slate-900 mt-0.5">{value}</p>
  </div>
);

const Input: React.FC<{ label: string; value: string | undefined; onChange: (v: string) => void; type?: string; placeholder?: string }> = ({
  label, value, onChange, type = 'text', placeholder,
}) => (
  <label className="block">
    <span className="block text-[10px] uppercase font-bold tracking-wider text-slate-500 mb-1">{label}</span>
    <input
      type={type}
      value={value ?? ''}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full text-sm px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-300 outline-none transition"
    />
  </label>
);

const Select: React.FC<{
  label: string; value: string | undefined; onChange: (v: string) => void;
  options: Array<{ value: string; label: string }>;
}> = ({ label, value, onChange, options }) => {
  const safeValue = value ?? options[0]?.value ?? '';
  return (
    <label className="block">
      <span className="block text-[10px] uppercase font-bold tracking-wider text-slate-500 mb-1">{label}</span>
      <select
        value={safeValue}
        onChange={(e) => onChange(e.target.value)}
        className="w-full text-sm px-3 py-2 rounded-lg ring-1 ring-slate-200 bg-white focus:ring-2 focus:ring-violet-300 outline-none transition"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </label>
  );
};

const Toggle: React.FC<{ label: string; value: boolean; onChange: (v: boolean) => void }> = ({
  label, value, onChange,
}) => (
  <label className="flex items-center gap-3 cursor-pointer">
    <button
      type="button"
      onClick={() => onChange(!value)}
      className={`relative w-11 h-6 rounded-full transition ${value ? 'bg-violet-500' : 'bg-slate-300'}`}
    >
      <motion.span
        animate={{ x: value ? 20 : 2 }}
        transition={{ type: 'spring', stiffness: 500, damping: 30 }}
        className="absolute top-1 w-4 h-4 bg-white rounded-full shadow"
      />
    </button>
    <span className="text-sm text-slate-700">{label}</span>
  </label>
);

const Stat: React.FC<{ label: string; value: string; tone?: 'emerald' | 'rose' | 'amber'; mono?: boolean }> = ({
  label, value, tone, mono,
}) => {
  const toneClass = tone === 'emerald' ? 'text-emerald-700' : tone === 'rose' ? 'text-rose-700' : tone === 'amber' ? 'text-amber-700' : 'text-slate-900';
  return (
    <div className="bg-slate-50 rounded-lg p-3 ring-1 ring-slate-200/60">
      <p className="text-[10px] uppercase font-bold tracking-wider text-slate-500">{label}</p>
      <p className={`mt-1 text-base font-bold tabular-nums ${toneClass} ${mono ? 'font-mono text-xs break-all' : ''}`}>{value}</p>
    </div>
  );
};

const DangerRow: React.FC<{ title: string; description: string; confirm: string; onConfirm: () => void }> = ({
  title, description, confirm, onConfirm,
}) => {
  const [phase, setPhase] = useState<'idle' | 'confirm'>('idle');
  const [typed, setTyped] = useState('');
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="flex-1">
        <p className="text-sm font-semibold text-rose-900">{title}</p>
        <p className="text-xs text-rose-700/80">{description}</p>
      </div>
      {phase === 'idle' ? (
        <button onClick={() => setPhase('confirm')} className="px-3 py-1.5 rounded-lg bg-rose-600 text-white text-xs font-semibold hover:bg-rose-700">
          Run…
        </button>
      ) : (
        <div className="flex items-center gap-2">
          <input
            placeholder={`Type ${confirm}`}
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            className="text-xs px-2 py-1.5 rounded-md ring-1 ring-rose-300 outline-none w-32"
          />
          <button
            disabled={typed !== confirm}
            onClick={() => { onConfirm(); setPhase('idle'); setTyped(''); }}
            className="px-3 py-1.5 rounded-lg bg-rose-700 text-white text-xs font-semibold disabled:opacity-50"
          >
            Confirm
          </button>
          <button onClick={() => { setPhase('idle'); setTyped(''); }} className="text-xs text-slate-500 hover:text-slate-700">
            Cancel
          </button>
        </div>
      )}
    </div>
  );
};

export default Settings;
