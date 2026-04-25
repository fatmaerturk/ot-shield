import React, { useEffect, useState, useMemo } from 'react';
import api from '../services/api';  // axios veya benzeri kurulumunuz
import { motion, AnimatePresence } from 'framer-motion';
import Skeleton from 'react-loading-skeleton';
import Tippy from '@tippyjs/react';
import 'react-loading-skeleton/dist/skeleton.css';
import 'tippy.js/dist/tippy.css';
import { Sparklines, SparklinesLine } from 'react-sparklines';
import { AuditRecord } from '../types/audit';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';

interface Threat {
  id: string;
  title: string;
  description: string;
  source: string;
  date: string;
  tags: string[];
  logoUrl: string;
  link: string;
}

// Helper functions for IOC lookup actions
const handleCopyIP = (ip: string) => {
  navigator.clipboard.writeText(ip);
};
const handleLookupVT = (ip: string) => {
  window.open(`https://www.virustotal.com/gui/search/${ip}`, '_blank');
};

// Helper to log audit events
const logAudit = (actionType: string, details: string) => {
  api.post('/api/audit', null, { params: { actionType, details } })
     .catch(console.error);
};

const ThreatIntelligence: React.FC = () => {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditRecord[]>([]);

  // Filter state'leri
  const [query, setQuery] = useState('');
  const [selectedSource, setSelectedSource] = useState('All');
  const [dateRange, setDateRange] = useState<'All' | 'Last 7 Days' | 'Last 30 Days'>('All');

  // --- Advanced filter state ---
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>(['Critical', 'High', 'Medium']);
  const [dateFilterOption, setDateFilterOption] = useState<'All' | 'Last 24h' | 'Last 7 Days' | 'Custom'>('All');
  const [customStart, setCustomStart] = useState<string>('');
  const [customEnd, setCustomEnd] = useState<string>('');

  // --- Bookmark & Annotation state ---
  const [favorites, setFavorites] = useState<Set<string>>(new Set());
  const [comments, setComments] = useState<Record<string, string>>({});

  // Toggle favorite (star) for a threat
  const toggleFavorite = (id: string) => {
    setFavorites(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) newSet.delete(id);
      else newSet.add(id);
      return newSet;
    });
  };

  // Prompt user for a comment/note on a threat
  const addComment = (id: string) => {
    const note = prompt('Enter comment:', comments[id] || '');
    if (note !== null) {
      setComments(prev => ({ ...prev, [id]: note }));
    }
  };

  // Severity checkbox handler
  const handleSeverityChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { value, checked } = e.target;
    setSelectedSeverities(prev =>
      checked ? [...prev, value] : prev.filter(s => s !== value)
    );
  };

  // compute filtered list
  const filteredThreats = useMemo(() => {
    // copy then filter
    let list = [...threats];
    // Filter by severity
    if (selectedSeverities.length) {
      list = list.filter(th => {
        const sev = th.tags.includes('Critical') ? 'Critical'
                  : th.tags.includes('High')    ? 'High'
                  : 'Medium';
        return selectedSeverities.includes(sev);
      });
    }
    // Filter by date
    const now = Date.now();
    if (dateFilterOption === 'Last 24h') {
      list = list.filter(th => new Date(th.date).getTime() > now - 24*60*60*1000);
    } else if (dateFilterOption === 'Last 7 Days') {
      list = list.filter(th => new Date(th.date).getTime() > now - 7*24*60*60*1000);
    } else if (dateFilterOption === 'Custom' && customStart && customEnd) {
      const start = new Date(customStart).getTime();
      const end = new Date(customEnd).getTime() + 24*60*60*1000 - 1;
      list = list.filter(th => {
        const t = new Date(th.date).getTime();
        return t >= start && t <= end;
      });
    }
    // ensure newest-first order after filters
    list.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
    return list;
  }, [threats, selectedSeverities, dateFilterOption, customStart, customEnd]);

  // Metrics now based on filteredThreats
  const totalCount = filteredThreats.length;
  const criticalCount = filteredThreats.filter(th => th.tags.includes('Critical')).length;
  const last24hCount = filteredThreats.filter(th => new Date(th.date).getTime() > Date.now() - 24*60*60*1000).length;

  // Generate a consistent mock sparkline for each threat
  const trendMap = useMemo(() => {
    const map: Record<string, number[]> = {};
    filteredThreats.forEach(th => {
      const seed = parseInt(th.id, 10) || 1;
      // build a simple 10-point trend array
      map[th.id] = Array.from({ length: 10 }, (_, i) =>
        Math.abs((seed + i) % 5) + Math.random() * 2
      );
    });
    return map;
  }, [filteredThreats]);

  // --- Group threats by source IP for similarity clusters ---
  const sourceClusters = useMemo<Record<string, Threat[]>>(() => {
    const map: Record<string, Threat[]> = {};
    filteredThreats.forEach(th => {
      if (!map[th.source]) map[th.source] = [];
      map[th.source].push(th);
    });
    return map;
  }, [filteredThreats]);

  // List of similar threats (same source IP) excluding the selected one
  const similarThreats = useMemo(() => {
    if (!selectedThreat) return [];
    return (sourceClusters[selectedThreat.source] || []).filter(
      th => th.id !== selectedThreat.id
    );
  }, [selectedThreat, sourceClusters]);

  // 1) Simplify risk‐score to depend only on severity and normalize to 0–100
  const computeRiskScore = (th: Threat): number => {
    // severity weight: Critical=3, High=2, Medium/Low=1
    const sevValue = th.tags.includes('Critical') ? 3
                   : th.tags.includes('High')     ? 2
                   : 1;
    // normalize severity (1–3) into 0–100
    return Math.round((sevValue / 3) * 100);
  };

  useEffect(() => {
    if (!selectedThreat && filteredThreats.length > 0) {
      setSelectedThreat(filteredThreats[0]);
    }
  }, [filteredThreats, selectedThreat]);

  useEffect(() => {
    const fetchThreats = async () => {
      setLoading(true);
      setError(null);
      try {
        let endpoint = '/api/threat-intel';
        const parts: string[] = [];
        if (query) parts.push(`q=${encodeURIComponent(query)}`);
        if (selectedSource !== 'All') parts.push(`source=${encodeURIComponent(selectedSource)}`);
        if (dateRange !== 'All') parts.push(`dateRange=${encodeURIComponent(dateRange)}`);
        if (parts.length) endpoint += `?${parts.join('&')}`;
        const res = await api.get<Threat[]>(endpoint);
        // sort newest first
        const sorted = res.data.sort(
          (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
        );
        setThreats(sorted);
      } catch (err: any) {
        setError(err.message || 'Failed to load data');
      } finally {
        setLoading(false);
      }
    };
    fetchThreats();
  }, [query, selectedSource, dateRange]);

  // WebSocket for live threat updates
  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8080/ws/threats');
    ws.onmessage = (e) => {
      const newThreat: Threat = JSON.parse(e.data);
      setThreats(prev => [newThreat, ...prev]);
    };
    return () => ws.close();
  }, []);

  // when filters change
  useEffect(() => {
    // Fetch logic...
    // Log filter usage
    logAudit('FILTER_CHANGE', JSON.stringify({
      severities: selectedSeverities,
      dateOption: dateFilterOption,
      start: customStart,
      end: customEnd
    }));
  }, [selectedSeverities, dateFilterOption, customStart, customEnd]);

  // when user clicks a row
  const handleRowClick = (threat: Threat) => {
    setSelectedThreat(threat);
    logAudit('ROW_VIEW', JSON.stringify({ id: threat.id, source: threat.source }));
  };

  const sources = ['All', 'FireEye', 'Cisco Talos', 'Kaspersky', 'CrowdStrike'];

  const rowVariants = {
    hidden: { opacity: 0, y: 10 },
    visible: (i: number) => ({
      opacity: 1,
      y: 0,
      transition: { delay: i * 0.05, duration: 0.3 }
    })
  };

  // Fetch audit logs on mount
  useEffect(() => {
    api.get<AuditRecord[]>('/api/audit')
      .then(res => setAuditLogs(res.data))
      .catch(console.error);
  }, []);

  // --- Export & Share helpers ---
  const exportCSV = () => {
    const headers = ['#','Title','Source','Date','Severity','Tags'];
    const rows = filteredThreats.map((th, idx) => [
      idx + 1,
      th.title,
      th.source,
      new Date(th.date).toLocaleDateString(),
      th.tags.includes('Critical') ? 'Critical'
        : th.tags.includes('High') ? 'High'
        : 'Medium',
      th.tags.join(';')
    ]);
    const csvContent = [headers, ...rows].map(r => r.join(',')).join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'threats.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const exportPDF = async () => {
    const input = document.getElementById('threat-table');
    if (!input) return;
    const canvas = await html2canvas(input);
    const imgData = canvas.toDataURL('image/png');
    const pdf = new jsPDF('landscape');
    const pdfWidth = pdf.internal.pageSize.getWidth();
    const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
    pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
    pdf.save('threats.pdf');
  };

  const copyTable = () => {
    const headers = ['#','Title','Source','Date','Severity','Tags'];
    const rows = filteredThreats.map((th, idx) => [
      idx + 1,
      th.title,
      th.source,
      new Date(th.date).toLocaleDateString(),
      th.tags.includes('Critical') ? 'Critical'
        : th.tags.includes('High') ? 'High'
        : 'Medium',
      th.tags.join(';')
    ]);
    const text = [headers, ...rows].map(r => r.join('\t')).join('\n');
    navigator.clipboard.writeText(text);
  };

  return (
    <motion.div
      className="space-y-6"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      transition={{ duration: 0.5 }}
    >
      {/* Hero */}
      <div
        className="relative overflow-hidden rounded-2xl p-8 md:p-10 text-white"
        style={{ background: 'linear-gradient(135deg, #1e1b4b 0%, #4c1d95 45%, #7c3aed 100%)' }}
      >
        <div className="absolute -top-20 -right-20 w-72 h-72 rounded-full bg-fuchsia-500/20 blur-3xl" />
        <div className="absolute -bottom-10 -left-10 w-60 h-60 rounded-full bg-violet-400/10 blur-3xl" />
        <div className="relative">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 ring-1 ring-white/20 text-xs font-semibold tracking-wider backdrop-blur-sm mb-4">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            THREAT INTELLIGENCE
          </div>
          <h1 className="text-3xl md:text-4xl font-bold leading-tight">
            Global threat landscape for industrial operations
            <span className="block text-violet-100/90 font-medium text-lg md:text-xl mt-2">
              Curated IOCs, CVEs and advisories across your OT perimeter.
            </span>
          </h1>
        </div>
      </div>

      {/* Filter bar */}
      <header className="flex flex-col md:flex-row items-start md:items-center justify-between space-y-3 md:space-y-0">
        <div className="text-sm text-slate-500">
          Refine feed by source, severity or date range
        </div>
        <div className="flex flex-wrap gap-3">
          {/* Search input with icon */}
          <div className="relative">
            <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-gray-400">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M21 21l-4.35-4.35M17 11a6 6 0 11-12 0 6 6 0 0112 0z" />
              </svg>
            </span>
            <input
              type="text"
              placeholder="Search indicators..."
              value={query}
              onChange={e => setQuery(e.target.value)}
              className="pl-10 pr-3 py-2 bg-white border border-slate-200 rounded-xl shadow-sm focus:outline-none focus:ring-2 focus:ring-violet-400 focus:border-violet-400 transition"
            />
          </div>
          <select
            value={selectedSource}
            onChange={e => setSelectedSource(e.target.value)}
            className="bg-white border border-slate-200 rounded-xl px-3 py-2 shadow-sm focus:outline-none focus:ring-2 focus:ring-violet-400 focus:border-violet-400 transition"
          >
            {sources.map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select
            value={dateRange}
            onChange={e => setDateRange(e.target.value as any)}
            className="bg-white border border-slate-200 rounded-xl px-3 py-2 shadow-sm focus:outline-none focus:ring-2 focus:ring-violet-400 focus:border-violet-400 transition"
          >
            {['All', 'Last 7 Days', 'Last 30 Days'].map(dr => (
              <option key={dr} value={dr}>{dr}</option>
            ))}
          </select>
        </div>
      </header>

      {/* --- Advanced Filters --- */}
      <div className="mb-4 flex flex-wrap items-center gap-6">
        {/* Severity Multi-Select */}
        <div className="flex space-x-4">
          {['Critical', 'High', 'Medium'].map(level => (
            <label key={level} className="inline-flex items-center">
              <input
                type="checkbox"
                value={level}
                checked={selectedSeverities.includes(level)}
                onChange={handleSeverityChange}
                className="h-4 w-4 text-blue-600 border-gray-300 rounded"
              />
              <span className="ml-2 text-sm">{level}</span>
            </label>
          ))}
        </div>
        {/* Date Range Picker */}
        <div className="flex items-center space-x-2">
          <select
            value={dateFilterOption}
            onChange={e => setDateFilterOption(e.target.value as any)}
            className="border px-2 py-1 rounded text-sm"
          >
            <option value="All">All Time</option>
            <option value="Last 24h">Last 24h</option>
            <option value="Last 7 Days">Last 7 Days</option>
            <option value="Custom">Custom</option>
          </select>
          {dateFilterOption === 'Custom' && (
            <>
              <input
                type="date"
                value={customStart}
                onChange={e => setCustomStart(e.target.value)}
                className="border px-2 py-1 rounded text-sm"
              />
              <span className="text-sm">to</span>
              <input
                type="date"
                value={customEnd}
                onChange={e => setCustomEnd(e.target.value)}
                className="border px-2 py-1 rounded text-sm"
              />
            </>
          )}
        </div>
      </div>

      {/* Export & Share Buttons */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={exportCSV}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-violet-500 to-fuchsia-500 hover:shadow-lg hover:shadow-violet-500/30 transition"
        >
          Export CSV
        </button>
        <button
          onClick={exportPDF}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-violet-700 bg-white ring-1 ring-violet-200 hover:bg-violet-50 transition"
        >
          Export PDF
        </button>
        <button
          onClick={copyTable}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-slate-700 bg-white ring-1 ring-slate-200 hover:bg-slate-50 transition"
        >
          Copy Table
        </button>
      </div>

      {/* --- Threat Overview KPIs --- */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          whileHover={{ scale: 1.02 }}
          className="relative overflow-hidden bg-white rounded-2xl p-5 ring-1 ring-slate-200/70 shadow-sm"
        >
          <div className="absolute top-0 right-0 w-24 h-24 rounded-full bg-violet-500/10 blur-2xl" />
          <div className="relative">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-500 uppercase tracking-wide">Total Threats</h3>
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white flex items-center justify-center shadow">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
            </div>
            <p className="mt-3 text-3xl font-bold text-slate-900">{totalCount}</p>
            <p className="text-xs text-slate-500 mt-1">Indicators in current view</p>
          </div>
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          whileHover={{ scale: 1.02 }}
          className="relative overflow-hidden bg-white rounded-2xl p-5 ring-1 ring-slate-200/70 shadow-sm"
        >
          <div className="absolute top-0 right-0 w-24 h-24 rounded-full bg-rose-500/10 blur-2xl" />
          <div className="relative">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-500 uppercase tracking-wide">Critical Ratio</h3>
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-rose-500 to-fuchsia-500 text-white flex items-center justify-center shadow">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
            </div>
            <p className="mt-3 text-3xl font-bold text-slate-900">
              {totalCount ? ((criticalCount / totalCount) * 100).toFixed(0) : '0'}%
            </p>
            <p className="text-xs text-slate-500 mt-1">Severity-high share</p>
          </div>
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
          whileHover={{ scale: 1.02 }}
          className="relative overflow-hidden bg-white rounded-2xl p-5 ring-1 ring-slate-200/70 shadow-sm"
        >
          <div className="absolute top-0 right-0 w-24 h-24 rounded-full bg-fuchsia-500/10 blur-2xl" />
          <div className="relative">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-500 uppercase tracking-wide">Added Last 24h</h3>
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-fuchsia-500 to-pink-500 text-white flex items-center justify-center shadow">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>
            <p className="mt-3 text-3xl font-bold text-slate-900">{last24hCount}</p>
            <p className="text-xs text-slate-500 mt-1">New in the last day</p>
          </div>
        </motion.div>
      </div>

      {/* Threats Table */}
      <div className="bg-white shadow-lg rounded-lg mb-6 overflow-hidden border border-gray-200">
        <div className="overflow-x-auto">
          <div className="max-h-96 overflow-y-auto">
            <table id="threat-table" className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50 sticky top-0 z-20">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase sticky left-0 bg-gray-50 z-30">#</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Date</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Tags</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Trend</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                <AnimatePresence>
                  {loading
                    ? Array.from({ length: 5 }).map((_, i) => (
                        <motion.tr
                          key={i}
                          initial="hidden"
                          animate="visible"
                          variants={rowVariants}
                        >
                          <td colSpan={6} className="px-4 py-2">
                            <Skeleton height={24} />
                          </td>
                        </motion.tr>
                      ))
                    : filteredThreats.map((th, idx) => (
                        <motion.tr
                          key={th.id}
                          custom={idx}
                          initial="hidden"
                          animate="visible"
                          variants={rowVariants}
                          onClick={() => handleRowClick(th)}
                          className={`transition-colors cursor-pointer ${
                            selectedThreat?.id === th.id
                              ? 'bg-blue-50'
                              : 'even:bg-gray-50 hover:bg-gray-100'
                          }`}
                        >
                          <td className="px-4 py-2 text-sm text-gray-700">{idx + 1}</td>
                          <td className="px-4 py-2 text-sm text-gray-700">{th.title}</td>
                          <td className="px-4 py-2 text-sm text-gray-700">{th.source}</td>
                          <td className="px-4 py-2 text-sm text-gray-700">{new Date(th.date).toLocaleDateString()}</td>
                          <td className="px-4 py-2">
                            <Tippy content={th.tags.includes('Critical') ? 'Critical risk' : 'Severity'}>
                              <span
                                className={`inline-block text-xs font-semibold px-2 py-1 rounded-full ${
                                  th.tags.includes('Critical')
                                    ? 'bg-red-100 text-red-700 animate-pulse'
                                    : th.tags.includes('High')
                                    ? 'bg-orange-100 text-orange-700'
                                    : 'bg-green-100 text-green-700'
                                }`}
                              >
                                {th.tags.includes('Critical')
                                  ? 'Critical'
                                  : th.tags.includes('High')
                                  ? 'High'
                                  : 'Medium'}
                              </span>
                            </Tippy>
                          </td>
                          <td className="px-4 py-2 text-sm">
                            {th.tags.map(tag => (
                              <span key={tag} className="inline-block bg-blue-50 text-blue-700 px-2 py-0.5 rounded mr-1">{tag}</span>
                            ))}
                          </td>
                          <td className="px-4 py-2">
                            <Sparklines data={trendMap[th.id]} width={80} height={20} margin={0}>
                              <SparklinesLine
                                color="#3b82f6"
                                style={{ strokeWidth: 1, fill: 'none' }}
                              />
                            </Sparklines>
                          </td>
                          <td className="px-4 py-2 space-x-2">
                            <button
                              onClick={() => toggleFavorite(th.id)}
                              className="text-yellow-500 hover:text-yellow-600"
                            >
                              {favorites.has(th.id) ? '⭐' : '☆'}
                            </button>
                            <button
                              onClick={() => addComment(th.id)}
                              className="text-gray-500 hover:text-gray-700"
                            >
                              💬
                            </button>
                            <button
                              onClick={() => handleCopyIP(th.source)}
                              className="text-blue-600 hover:underline text-xs"
                            >
                              Copy IP
                            </button>
                            <button
                              onClick={() => handleLookupVT(th.source)}
                              className="text-blue-600 hover:underline text-xs"
                            >
                              VT Lookup
                            </button>
                          </td>
                        </motion.tr>
                      ))}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Timeline */}
      {selectedThreat && (
        <motion.div
          className="overflow-x-auto mb-6"
          drag="x"
          dragConstraints={{ left: 0, right: 0 }}
          whileTap={{ cursor: 'grabbing' }}
        >
          <div className="flex space-x-4">
            {['Initial Access','Execution','Persistence','Privilege Escalation','Discovery'].map(tactic => (
              <div key={tactic} className="flex-shrink-0 w-48 bg-gray-100 p-4 rounded">
                <h3 className="text-sm font-semibold mb-2">{tactic}</h3>
                <ul className="space-y-1">
                  <li className="bg-gray-200 text-gray-700 text-xs px-2 py-1 rounded">
                    {tactic} – Sample Technique
                  </li>
                </ul>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Detail Panel */}
      {selectedThreat && (
        <AnimatePresence>
          <motion.section
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.3 }}
          >
            <div className="bg-white shadow rounded p-4">
              <h3 className="font-semibold mb-2">Description</h3>
              <p className="text-sm text-gray-700">{selectedThreat.description}</p>
              <a
                href={selectedThreat.link}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-3 inline-block text-blue-600 hover:underline text-sm"
              >
                Read more →
              </a>
            </div>
          </motion.section>
        </AnimatePresence>
      )}

      {/* --- AI Suggestions / Anomaly Detection --- */}
      {selectedThreat && (
        <section className="bg-white shadow rounded-lg p-4 mb-6">
          <h3 className="text-lg font-semibold mb-2">AI Suggestions</h3>
          {/* Similar IP threats */}
          {similarThreats.length > 0 ? (
            <p className="text-sm mb-2">
              Similar threats from same IP ({selectedThreat.source}):{' '}
              {similarThreats.map(th => th.title).join(', ')}
            </p>
          ) : (
            <p className="text-sm mb-2">No similar threats detected.</p>
          )}
          {/* Auto risk score */}
          <p className="text-sm">
            Auto Risk Score (0–100):{' '}
            <span className="font-bold">
              {computeRiskScore(selectedThreat)}
            </span>/100
          </p>
        </section>
      )}

      {/* Audit Trail */}
      <section className="mt-8">
        <h2 className="text-xl font-semibold mb-2">Audit Trail</h2>
        <div className="bg-white shadow rounded mb-6 overflow-auto max-h-64">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">User</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Details</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200 text-sm">
              {auditLogs.map(log => (
                <tr key={log.id}>
                  <td className="px-4 py-2">{new Date(log.timestamp).toLocaleString()}</td>
                  <td className="px-4 py-2">{log.username}</td>
                  <td className="px-4 py-2">{log.actionType}</td>
                  <td className="px-4 py-2">{log.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </motion.div>
  );
};

export default ThreatIntelligence; 