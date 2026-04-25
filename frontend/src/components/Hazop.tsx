import React, { useEffect, useRef, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Network, DataSet } from 'vis-network/standalone';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import markerIcon2x from 'leaflet/dist/images/marker-icon-2x.png';
import markerIcon from 'leaflet/dist/images/marker-icon.png';
import markerShadow from 'leaflet/dist/images/marker-shadow.png';

L.Icon.Default.mergeOptions({
  iconRetinaUrl: markerIcon2x,
  iconUrl: markerIcon,
  shadowUrl: markerShadow,
});

interface PacketInfo {
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  timestamp: string;
  sourceLevel: string;
  destinationLevel: string;
  sourceManufacturer: string;
  destinationManufacturer: string;
  sourceModel: string;
  destinationModel: string;
}

interface HazopEntry {
  id: string;
  hazard: string;
  cause: string;
  consequence: string;
  safeguards: string;
  severity: string;
  likelihood: string;
  risk: string;
}

const Hazop: React.FC = () => {
  // Suppress ResizeObserver loop errors
  useEffect(() => {
    const onError = (event: ErrorEvent) => {
      if (event.message.includes('ResizeObserver loop completed')) {
        event.stopImmediatePropagation();
        event.preventDefault();
      }
    };
    window.addEventListener('error', onError);
    return () => window.removeEventListener('error', onError);
  }, []);

  const navigate = useNavigate();
  const [currentUser, setCurrentUser] = useState<any>(null);
  const networkContainer = useRef<HTMLDivElement>(null);
  const [packetInfos, setPacketInfos] = useState<PacketInfo[]>([]);

  useEffect(() => {
    const userStr = localStorage.getItem('user');
    if (userStr) {
      try {
        const userData = JSON.parse(userStr);
        setCurrentUser(userData);
      } catch (error) {
        console.error('Error parsing user data:', error);
      }
    }
  }, []);

  useEffect(() => {
    const stored = localStorage.getItem('packetInfos');
    if (stored) {
      try {
        const data = JSON.parse(stored);
        setPacketInfos(Array.isArray(data) ? data : []);
      } catch (e) {
        console.error('Invalid packetInfos in localStorage', e);
        setPacketInfos([]);
      }
    }
  }, []);

  // Build HAZOP entries by simple anomaly rules (e.g. unencrypted protocols)
  const hazopEntries: HazopEntry[] = useMemo(() => {
    return packetInfos.map((p, idx) => ({
      id: `${idx}`,
      hazard: p.protocol,
      cause: `Unexpected ${p.protocol} packet`,
      consequence: 'Potential SCADA disruption',
      safeguards: 'Segmentation, ACL',
      severity: p.protocol === 'IEC104' ? 'High' : 'Medium',
      likelihood: 'Low',
      risk: p.protocol === 'IEC104' ? 'High' : 'Medium'
    }));
  }, [packetInfos]);

  // KPI summary metrics
  const totalHazards = hazopEntries.length;
  const highSeverityCount = hazopEntries.filter(entry => entry.severity === 'High').length;
  const mediumSeverityCount = hazopEntries.filter(entry => entry.severity === 'Medium').length;

  // Filtering & sorting state and handlers
  const [filters, setFilters] = useState<{ severity: string; likelihood: string; risk: string }>({ severity: 'All', likelihood: 'All', risk: 'All' });
  const [sortConfig, setSortConfig] = useState<{ key: keyof HazopEntry; direction: 'ascending' | 'descending' }>({ key: 'id', direction: 'ascending' });
  const handleSort = (key: keyof HazopEntry) => {
    setSortConfig(prev => prev.key === key
      ? { key, direction: prev.direction === 'ascending' ? 'descending' : 'ascending' }
      : { key, direction: 'ascending' }
    );
    setCurrentPage(1);
  };
  const filteredEntries = useMemo(() => hazopEntries.filter(entry => {
    if (filters.severity !== 'All' && entry.severity !== filters.severity) return false;
    if (filters.likelihood !== 'All' && entry.likelihood !== filters.likelihood) return false;
    if (filters.risk !== 'All' && entry.risk !== filters.risk) return false;
    return true;
  }), [hazopEntries, filters]);
  const sortedEntries = useMemo(() => {
    const entries = [...filteredEntries];
    entries.sort((a, b) => {
      const aVal = a[sortConfig.key] as string;
      const bVal = b[sortConfig.key] as string;
      if (aVal < bVal) return sortConfig.direction === 'ascending' ? -1 : 1;
      if (aVal > bVal) return sortConfig.direction === 'ascending' ? 1 : -1;
      return 0;
    });
    return entries;
  }, [filteredEntries, sortConfig]);

  // Drill-down detail state
  const [selectedEntry, setSelectedEntry] = useState<HazopEntry | null>(null);
  const selectedPacketInfo = selectedEntry ? packetInfos[Number(selectedEntry.id)] : null;
  // Integration: fetch device info via SNMP or HTTP banner
  const [deviceInfo, setDeviceInfo] = useState<{ sourceDescr?: string; destDescr?: string }>({});
  useEffect(() => {
    if (!selectedEntry) {
      setDeviceInfo({});
      return;
    }
    const srcIp = selectedPacketInfo?.sourceIp;
    const dstIp = selectedPacketInfo?.destinationIp;
    (async () => {
      try {
        const [srcRes, dstRes] = await Promise.all([
          fetch(`/api/snmp/info?ip=${encodeURIComponent(srcIp || '')}`),
          fetch(`/api/snmp/info?ip=${encodeURIComponent(dstIp || '')}`)
        ]);
        const srcData = srcRes.ok ? await srcRes.json() : {};
        const dstData = dstRes.ok ? await dstRes.json() : {};
        setDeviceInfo({ sourceDescr: srcData.sysDescr, destDescr: dstData.sysDescr });
      } catch (err) {
        console.error('Error fetching device info', err);
      }
    })();
  }, [selectedEntry]);
  
  // Pagination state and derived entries
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [rowsPerPage, setRowsPerPage] = useState<number>(10);
  const totalPages = Math.ceil(sortedEntries.length / rowsPerPage) || 1;
  const paginatedEntries = useMemo(() => {
    const start = (currentPage - 1) * rowsPerPage;
    return sortedEntries.slice(start, start + rowsPerPage);
  }, [sortedEntries, currentPage, rowsPerPage]);

  // Export / Reporting handlers
  const handleExportCSV = () => {
    const headers = ['ID','Hazard','Cause','Consequence','Safeguards','Severity','Likelihood','Risk'];
    const csvRows = [headers.join(',')];
    sortedEntries.forEach(e => {
      csvRows.push([e.id,e.hazard,e.cause,e.consequence,e.safeguards,e.severity,e.likelihood,e.risk].map(val => `"${val}"`).join(','));
    });
    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'hazop_report.csv'; a.click(); URL.revokeObjectURL(url);
  };
  const handleExportExcel = () => {
    const headers = ['ID','Hazard','Cause','Consequence','Safeguards','Severity','Likelihood','Risk'];
    const csvRows = [headers.join('\t')];
    sortedEntries.forEach(e => {
      csvRows.push([e.id,e.hazard,e.cause,e.consequence,e.safeguards,e.severity,e.likelihood,e.risk].join('\t'));
    });
    const blob = new Blob([csvRows.join('\n')], { type: 'application/vnd.ms-excel' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'hazop_report.xls'; a.click(); URL.revokeObjectURL(url);
  };
  const handleExportPDF = () => {
    window.print();
  };

  useEffect(() => {
    if (networkContainer.current && packetInfos.length > 0) {
      const nodesSet = new Set<string>();
      const nodes: any[] = [];
      const edgeSet = new Set<string>();
      const edges: any[] = [];
      packetInfos.forEach(p => {
        if (!nodesSet.has(p.sourceIp)) {
          nodesSet.add(p.sourceIp);
          nodes.push({ id: p.sourceIp, label: p.sourceIp });
        }
        if (!nodesSet.has(p.destinationIp)) {
          nodesSet.add(p.destinationIp);
          nodes.push({ id: p.destinationIp, label: p.destinationIp });
        }
        const edgeId = `${p.sourceIp}-${p.destinationIp}`;
        if (!edgeSet.has(edgeId)) {
          edgeSet.add(edgeId);
          edges.push({ id: edgeId, from: p.sourceIp, to: p.destinationIp, label: p.protocol });
        }
      });
      const net = new Network(
        networkContainer.current,
        { nodes: new DataSet(nodes), edges: new DataSet(edges) },
        { physics: { enabled: false }, autoResize: false }
      );
      return () => net.destroy();
    }
  }, [packetInfos]);

  // Geo mapping state for Network Map
  const [geoData, setGeoData] = useState<{ ip: string; lat: number; lon: number; count: number }[]>([]);
  useEffect(() => {
    // build unique IP list and fetch geolocation
    const ips = filteredEntries.flatMap(entry => {
      const pi = packetInfos[Number(entry.id)];
      return [pi.sourceIp, pi.destinationIp];
    });
    const uniqueIps = Array.from(new Set(ips));
    (async () => {
      const results = await Promise.all(uniqueIps.map(async ip => {
        try {
          const res = await fetch(`https://ipapi.co/${ip}/json/`);
          const json = await res.json();
          return { ip, lat: parseFloat(json.latitude), lon: parseFloat(json.longitude) };
        } catch {
          return null;
        }
      }));
      const valid = results.filter((r): r is { ip: string; lat: number; lon: number } => 
        r != null && !isNaN(r.lat) && !isNaN(r.lon)
      );
      const mapped = valid.map(v => ({
        ...v,
        count: filteredEntries.filter(entry => {
          const pi = packetInfos[Number(entry.id)];
          return pi.sourceIp === v.ip || pi.destinationIp === v.ip;
        }).length
      }));
      // Fallback to dummy data if no valid geolocation found
      if (mapped.length === 0) {
        setGeoData([
          { ip: '192.0.2.1', lat: 40.7128, lon: -74.0060, count: 1 },
          { ip: '198.51.100.2', lat: 51.5074, lon: -0.1278, count: 1 },
          { ip: '203.0.113.3', lat: 35.6895, lon: 139.6917, count: 1 }
        ]);
      } else {
        setGeoData(mapped);
      }
    })();
  }, [filteredEntries]);

  // Real-time HAZOP: inject anomalies from live packets
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${protocol}://${window.location.hostname}:8080/ws/livepackets`);
    ws.onmessage = event => {
      try {
        const pkt: PacketInfo = JSON.parse(event.data);
        // treat new High-severity packets as anomalies
        if (pkt.protocol === 'IEC104') {
          setPacketInfos(prev => {
            const exists = prev.some(p => p.timestamp === pkt.timestamp && p.sourceIp === pkt.sourceIp);
            if (!exists) {
              const updated = [...prev, pkt];
              localStorage.setItem('packetInfos', JSON.stringify(updated));
              return updated;
            }
            return prev;
          });
        }
      } catch (e) {
        console.error('Error in live HAZOP WS message:', e);
      }
    };
    return () => ws.close();
  }, []);

  return (
    <div className="space-y-6">
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
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            SAFETY &amp; HAZOP
          </div>
          <h1 className="text-3xl md:text-4xl font-bold leading-tight">
            HAZOP Analysis
            <span className="block text-violet-100/90 font-medium text-lg md:text-xl mt-2">
              Identify hazards, assess consequence and evaluate safeguard effectiveness.
            </span>
          </h1>
        </div>
      </div>

      <div>
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm ring-1 ring-slate-200/70 dark:border dark:border-gray-700 p-6">
          {/* KPI Panels */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
            <div className="bg-white dark:bg-gray-700 shadow rounded p-4">
              <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Hazards</h4>
              <p className="mt-1 text-2xl font-semibold text-gray-900 dark:text-gray-100">{totalHazards}</p>
            </div>
            <div className="bg-white dark:bg-gray-700 shadow rounded p-4">
              <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">High Severity</h4>
              <p className="mt-1 text-2xl font-semibold text-red-600 dark:text-red-400">{highSeverityCount}</p>
            </div>
            <div className="bg-white dark:bg-gray-700 shadow rounded p-4">
              <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Medium Severity</h4>
              <p className="mt-1 text-2xl font-semibold text-yellow-500 dark:text-yellow-400">{mediumSeverityCount}</p>
            </div>
          </div>
          <div ref={networkContainer} style={{ height: '300px', border: '1px solid #ccc', marginBottom: '24px' }} />
          <h3 className="text-xl font-semibold mb-2 text-gray-900 dark:text-gray-100">Identified Hazards</h3>
          {/* Filter & Sort Controls */}
          <div className="flex flex-wrap items-center gap-4 mb-4">
            <label className="flex items-center space-x-2">
              <span className="text-sm text-gray-700 dark:text-gray-300">Severity:</span>
              <select
                value={filters.severity}
                onChange={e => { setFilters(f => ({ ...f, severity: e.target.value })); setCurrentPage(1); }}
                className="ml-1 border rounded p-1 text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-gray-100"
              >
                {['All', 'High', 'Medium', 'Low'].map(level => <option key={level} value={level}>{level}</option>)}
              </select>
            </label>
            <label className="flex items-center space-x-2">
              <span className="text-sm text-gray-700 dark:text-gray-300">Likelihood:</span>
              <select
                value={filters.likelihood}
                onChange={e => { setFilters(f => ({ ...f, likelihood: e.target.value })); setCurrentPage(1); }}
                className="ml-1 border rounded p-1 text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-gray-100"
              >
                {['All', 'High', 'Medium', 'Low'].map(level => <option key={level} value={level}>{level}</option>)}
              </select>
            </label>
            <label className="flex items-center space-x-2">
              <span className="text-sm text-gray-700 dark:text-gray-300">Risk:</span>
              <select
                value={filters.risk}
                onChange={e => { setFilters(f => ({ ...f, risk: e.target.value })); setCurrentPage(1); }}
                className="ml-1 border rounded p-1 text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-gray-100"
              >
                {['All', 'High', 'Medium', 'Low'].map(level => <option key={level} value={level}>{level}</option>)}
              </select>
            </label>
          </div>
          {/* Export / Reporting Controls */}
          <div className="flex space-x-2 mb-4">
            <button onClick={handleExportCSV} className="px-3 py-1 bg-green-500 text-white rounded hover:bg-green-600">Export CSV</button>
            <button onClick={handleExportExcel} className="px-3 py-1 bg-blue-500 text-white rounded hover:bg-blue-600">Export Excel</button>
            <button onClick={handleExportPDF} className="px-3 py-1 bg-indigo-500 text-white rounded hover:bg-indigo-600">Export PDF</button>
          </div>
          <div className="flex flex-col md:flex-row md:space-x-6">
            <div className="flex-1 overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-700">
                  <tr>
                    <th onClick={() => handleSort('id')} className="px-4 py-2 cursor-pointer">ID {sortConfig.key === 'id' ? (sortConfig.direction === 'ascending' ? '↑' : '↓') : ''}</th>
                    <th onClick={() => handleSort('hazard')} className="px-4 py-2 cursor-pointer">Hazard {sortConfig.key === 'hazard' ? (sortConfig.direction === 'ascending' ? '↑' : '↓') : ''}</th>
                    <th onClick={() => handleSort('cause')} className="px-4 py-2 cursor-pointer">Cause {sortConfig.key === 'cause' ? (sortConfig.direction === 'ascending' ? '↑' : '↓') : ''}</th>
                    <th onClick={() => handleSort('consequence')} className="px-4 py-2 cursor-pointer">Consequence {sortConfig.key === 'consequence' ? (sortConfig.direction === 'ascending' ? '↑' : '↓') : ''}</th>
                    <th onClick={() => handleSort('safeguards')} className="px-4 py-2 cursor-pointer">Safeguards {sortConfig.key === 'safeguards' ? (sortConfig.direction === 'ascending' ? '↑' : '↓') : ''}</th>
                    <th onClick={() => handleSort('severity')} className="px-4 py-2 cursor-pointer">Severity {sortConfig.key === 'severity' ? (sortConfig.direction === 'ascending' ? '↑' : '↓') : ''}</th>
                    <th onClick={() => handleSort('likelihood')} className="px-4 py-2 cursor-pointer">Likelihood {sortConfig.key === 'likelihood' ? (sortConfig.direction === 'ascending' ? '↑' : '↓') : ''}</th>
                    <th onClick={() => handleSort('risk')} className="px-4 py-2 cursor-pointer">Risk {sortConfig.key === 'risk' ? (sortConfig.direction === 'ascending' ? '↑' : '↓') : ''}</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200 dark:bg-gray-800 dark:divide-gray-700">
                  {paginatedEntries.map(row => (
                    <tr
                      key={row.id}
                      onClick={() => setSelectedEntry(row)}
                      className={`hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer ${selectedEntry?.id === row.id ? 'bg-gray-200 dark:bg-gray-600' : ''}`}
                    >
                      <td className="px-4 py-2 text-sm text-gray-700 dark:text-gray-200">{row.id}</td>
                      <td className="px-4 py-2 text-sm text-gray-700 dark:text-gray-200">{row.hazard}</td>
                      <td className="px-4 py-2 text-sm text-gray-700 dark:text-gray-200">{row.cause}</td>
                      <td className="px-4 py-2 text-sm text-gray-700 dark:text-gray-200">{row.consequence}</td>
                      <td className="px-4 py-2 text-sm text-gray-700 dark:text-gray-200">{row.safeguards}</td>
                      <td className="px-4 py-2 text-sm text-gray-700 dark:text-gray-200">{row.severity}</td>
                      <td className="px-4 py-2 text-sm text-gray-700 dark:text-gray-200">{row.likelihood}</td>
                      <td className="px-4 py-2 text-sm text-gray-700 dark:text-gray-200">{row.risk}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {/* Drill-down detail panel */}
            {selectedEntry && (
              <aside className="md:w-1/3 p-4 border rounded bg-white dark:bg-gray-700">
                <h3 className="text-lg font-semibold mb-2 text-gray-900 dark:text-gray-100">Details for Hazard ID {selectedEntry.id}</h3>
                <p><strong>Timestamp:</strong> {selectedPacketInfo?.timestamp}</p>
                <p><strong>Source IP:</strong> {selectedPacketInfo?.sourceIp} ({selectedPacketInfo?.sourceLevel})</p>
                <p><strong>Destination IP:</strong> {selectedPacketInfo?.destinationIp} ({selectedPacketInfo?.destinationLevel})</p>
                <p><strong>Protocol:</strong> {selectedPacketInfo?.protocol}</p>
                <p><strong>Source Model:</strong> {selectedPacketInfo?.sourceModel}</p>
                <p><strong>Destination Model:</strong> {selectedPacketInfo?.destinationModel}</p>
                {deviceInfo.sourceDescr && (
                  <p><strong>Source SysDescr:</strong> {deviceInfo.sourceDescr}</p>
                )}
                {deviceInfo.destDescr && (
                  <p><strong>Destination SysDescr:</strong> {deviceInfo.destDescr}</p>
                )}
                <button onClick={() => setSelectedEntry(null)} className="mt-4 px-3 py-1 bg-blue-500 text-white rounded hover:bg-blue-600">Close Details</button>
              </aside>
            )}
          </div>
          {/* Pagination controls */}
          <div className="flex items-center justify-between mt-4">
            <div>
              <label className="text-sm text-gray-700 dark:text-gray-300">Rows per page:
                <select
                  value={rowsPerPage}
                  onChange={e => { setRowsPerPage(Number(e.target.value)); setCurrentPage(1); }}
                  className="ml-2 border rounded p-1 text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-gray-100"
                >
                  {[10, 25, 50].map(size => (
                    <option key={size} value={size}>{size}</option>
                  ))}
                </select>
              </label>
            </div>
            <div className="space-x-1">
              <button
                onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                disabled={currentPage === 1}
                className="px-2 py-1 border rounded disabled:opacity-50 dark:border-gray-600 dark:text-gray-300"
              >Prev</button>
              <span className="text-sm text-gray-700 dark:text-gray-300 px-2">Page {currentPage} of {totalPages}</span>
              <button
                onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                disabled={currentPage === totalPages}
                className="px-2 py-1 border rounded disabled:opacity-50 dark:border-gray-600 dark:text-gray-300"
              >Next</button>
            </div>
          </div>
          {/* Geographic / Network Map */}
          <div className="mt-8">
            <h3 className="text-xl font-semibold mb-2 text-gray-900 dark:text-gray-100">Network Geo Map</h3>
            {geoData.length > 0 ? (
              <div className="h-64">
                <MapContainer center={[geoData[0].lat, geoData[0].lon]} zoom={2} className="h-full w-full">
                  <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
                  {geoData.map(d => (
                    <Marker key={d.ip} position={[d.lat, d.lon]}>
                      <Popup>{d.ip} ({d.count} hazards)</Popup>
                    </Marker>
                  ))}
                </MapContainer>
              </div>
            ) : (
              <p className="text-sm text-gray-500">No geolocation data available for current entries.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Hazop; 