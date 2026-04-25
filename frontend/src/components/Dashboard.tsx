import React, { useState, useCallback, useEffect, useRef, useMemo, ReactElement } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import { Network, DataSet } from 'vis-network/standalone';
import api from '../services/api';
import { motion } from 'framer-motion';
import { SunIcon, MoonIcon, BellIcon } from '@heroicons/react/24/solid';
import { ExclamationCircleIcon, InformationCircleIcon, XMarkIcon, BugAntIcon, ShieldCheckIcon } from '@heroicons/react/24/outline';
import PulsingMarker from './PulsingMarker';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import L from 'leaflet';
import { Pie, Bar, Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js';
import { User, LoginResponse, ApiResponse } from '../types/user';
import MitreMatrix from './MitreMatrix'; // MitreMatrix bileşenini import et
import DpiDashboardWidget from './DpiDashboardWidget';
import NetworkTopology from './NetworkTopology';
import { Icon, PageHero, KpiCard, Panel } from './theme';

// Add ResizeObserver error handling
if (typeof window !== 'undefined') {
  const resizeObserverErrHandler = (err: Error) => {
    if (err.message.includes('ResizeObserver loop completed with undelivered notifications')) {
      return;
    }
    console.error(err);
  };
  window.addEventListener('error', (e) => resizeObserverErrHandler(e.error));
}

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

interface PacketInfo {
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  timestamp: string;
  packetLength: number;
  payloadInfo: string;
  sourceLevel: string;
  destinationLevel: string;
  communicationType: string;
  flags: string;
  sequenceNumber: number;
  acknowledgmentNumber: number;
  windowSize: number;
  packetType: string;
  packetSummary: string;
  manufacturer: string;
  model: string;
  sourceManufacturer: string;
  destinationManufacturer: string;
  sourceModel: string;
  destinationModel: string;
}

// Add IOA interface
interface IOA {
  id: string;
  type: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  evidence: string;
  protocol?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  mitreId?: string;
}

interface LevelNames {
    [key: string]: string;
}

interface NetworkNode {
  id: string;
  label: string;
  group?: string;
  title: string;
  color?: string;
  shape?: string;
  image?: string;
  size?: number;
}

interface NetworkEdge {
  id: string;
  from: string;
  to: string;
  label: string;
  arrows: string;
  color?: string;
}

// Interface for backend network device info
interface NetworkInterfaceInfo {
  name: string;
  description: string;
  addresses: string[];
}

// Constants from Honeypot needed for generation/map
const publicIPsForTesting = [
  '8.8.8.8', '1.1.1.1', '208.67.222.222', '198.51.100.1', '203.0.113.1', 
  '91.198.174.192', '172.217.160.142', '104.18.32.7', '142.250.184.174', '35.241.6.203',
  // Add more diverse IPs if desired
];
const destinationCoords: L.LatLngTuple = [39.9334, 32.8597]; // Ankara as placeholder destination
const protocolColors: Record<string, string> = {
  TCP: '#ff0000', // Red
  UDP: '#00ff00', // Lime
  ICMP: '#0000ff', // Blue
  HTTP: '#ffff00', // Yellow
  DNS: '#ff00ff', // Magenta
  DEFAULT: '#00ffff', // Cyan
};
const getProtocolColor = (protocol: string): string => {
  return protocolColors[protocol.toUpperCase()] || protocolColors.DEFAULT;
};

// Add MITRE ATT&CK mapping
const mapIOAToMitre = (ioa: IOA): IOA => {
  const mitreMapping: Record<string, { tactic: string; technique: string; id: string }> = {
    'Potential DDoS Attack': { tactic: 'Impact', technique: 'Network Denial of Service', id: 'T1498' },
    'Potential SYN Flood Attack': { tactic: 'Impact', technique: 'Network Denial of Service', id: 'T1498.001' },
    'Potential UDP Flood Attack': { tactic: 'Impact', technique: 'Network Denial of Service', id: 'T1498.002' },
    'Potential ICMP Flood Attack': { tactic: 'Impact', technique: 'Network Denial of Service', id: 'T1498.003' },
    'Port Scanning': { tactic: 'Discovery', technique: 'Network Service Scanning', id: 'T1046' },
    'Potential Data Exfiltration': { tactic: 'Exfiltration', technique: 'Exfiltration Over Alternative Protocol', id: 'T1048' },
    'Potential Command Injection': { tactic: 'Execution', technique: 'Command and Scripting Interpreter', id: 'T1059' },
    'Potential SQL Injection': { tactic: 'Execution', technique: 'Exploitation for Client Execution', id: 'T1203' },
    'Potential XSS Attack': { tactic: 'Initial Access', technique: 'Exploit Public-Facing Application', id: 'T1190' },
    'Potential Directory Traversal': { tactic: 'Initial Access', technique: 'Exploit Public-Facing Application', id: 'T1190' },
    'Potential SSH Brute Force': { tactic: 'Credential Access', technique: 'Brute Force', id: 'T1110' },
    'Potential RDP Brute Force': { tactic: 'Credential Access', technique: 'Brute Force', id: 'T1110' },
    'Potential ARP Spoofing': { tactic: 'Lateral Movement', technique: 'Exploitation of Remote Services', id: 'T1210' },
    'Potential DNS Tunneling': { tactic: 'Command and Control', technique: 'Application Layer Protocol', id: 'T1071' },
    'Potential HTTP Tunneling': { tactic: 'Command and Control', technique: 'Application Layer Protocol', id: 'T1071.001' },
    'Potential Buffer Overflow': { tactic: 'Execution', technique: 'Exploitation for Client Execution', id: 'T1203' },
    'Unusual Level Communication': { tactic: 'Lateral Movement', technique: 'Exploitation of Remote Services', id: 'T1210' }
  };

  const mapping = mitreMapping[ioa.type];
  if (mapping) {
    return {
      ...ioa,
      mitreTactic: mapping.tactic,
      mitreTechnique: mapping.technique,
      mitreId: mapping.id
    };
  }
  return ioa;
};

// First, let's define the correct type for activeTab
type TabType = 'analysis' | 'live' | 'ioa' | 'mitre' | 'dpi'; // 'dpi' tab added for Phase 3

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<TabType>('analysis'); // Başlangıç doğru mu?
  const [currentUser, setCurrentUser] = useState<User | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [uploadStatus, setUploadStatus] = useState<string>('');
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [uploadCompleted, setUploadCompleted] = useState<boolean>(false);
  const [packetInfos, setPacketInfos] = useState<PacketInfo[]>(() => {
    const saved = localStorage.getItem('packetInfos');
    return saved ? JSON.parse(saved) : [];
  });
  // Ensure we always have an array to loop over
  const safePacketInfos = Array.isArray(packetInfos) ? packetInfos : [];
  const networkContainer = useRef<HTMLDivElement>(null);
  const [network, setNetwork] = useState<Network | null>(null);
  const [filterText, setFilterText] = useState<string>('');
  const [sortConfig, setSortConfig] = useState<{ key: keyof PacketInfo; direction: 'asc' | 'desc' } | null>(null);
  // Theme (dark/light)
  const [darkMode, setDarkMode] = useState<boolean>(() => localStorage.getItem('theme') === 'dark');
  // User management state
  const [users, setUsers] = useState<User[]>([]);
  const [showUserModal, setShowUserModal] = useState(false);
  const [newUser, setNewUser] = useState<Partial<User>>({
    username: '',
    email: '',
    role: 'viewer'
  });
  // Real-time alerts
  interface Alert { id: string; message: string; timestamp: Date; severity: 'info' | 'warning' | 'critical'; }
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [showAlerts, setShowAlerts] = useState(false);
  const processedIds = useRef<Set<string>>(new Set());
  const [isListening, setIsListening] = useState(false);
  const [livePackets, setLivePackets] = useState<PacketInfo[]>([]);
  const liveIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const [liveMarkers, setLiveMarkers] = useState<{ ip: string; count: number; lat: number; lon: number; protocol: string }[]>([]);
  const livePacketBufferRef = useRef<PacketInfo[]>([]); // buffer for throttled live updates
  const [liveFilterText, setLiveFilterText] = useState<string>(''); // filter for live table
  // New state for live packet table sorting
  const [liveSortConfig, setLiveSortConfig] = useState<{ key: keyof PacketInfo; direction: 'asc' | 'desc' } | null>(null);
  const liveWebSocketRef = useRef<WebSocket | null>(null);
  const liveNodesDsRef = useRef<DataSet<NetworkNode> | null>(null);
  const liveEdgesDsRef = useRef<DataSet<NetworkEdge> | null>(null);
  const [networkInterfaces, setNetworkInterfaces] = useState<NetworkInterfaceInfo[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('');
  const [fetchInterfacesError, setFetchInterfacesError] = useState<string>('');
  const [liveStatusMessage, setLiveStatusMessage] = useState<string>('');
  const liveNetworkContainer = useRef<HTMLDivElement>(null);
  const [liveNetwork, setLiveNetwork] = useState<Network | null>(null);
  // Track which file was selected for upload
  const [selectedFileName, setSelectedFileName] = useState<string>('');
  const [totalPacketCount, setTotalPacketCount] = useState<number | null>(null);
  const [selectedPacket, setSelectedPacket] = useState<PacketInfo | null>(null);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [rowsPerPage, setRowsPerPage] = useState<number>(10);
  const [uploadPage, setUploadPage] = useState<number>(0);
  const [analysisSearch, setAnalysisSearch] = useState<string>('');
  const [analysisProtocolFilter, setAnalysisProtocolFilter] = useState<string>('');
  const uploadPageSize = 500;
  const [ioas, setIOAs] = useState<IOA[]>([]);

  // Function to convert IOA to Alert and send to backend
  const sendIOAsToBackend = useCallback(async (ioas: IOA[]) => {
    try {
      const alertPromises = ioas.map(async (ioa) => {
        // Map IOA severity to AlertSeverity
        const severityMap: Record<string, string> = {
          'critical': 'CRITICAL',
          'high': 'HIGH', 
          'medium': 'MEDIUM',
          'low': 'LOW'
        };

        // Map IOA type to AlertType
        const typeMap: Record<string, string> = {
          'Potential DDoS Attack': 'DDoS_ATTACK',
          'Potential SYN Flood Attack': 'DDoS_ATTACK',
          'Potential UDP Flood Attack': 'DDoS_ATTACK',
          'Potential ICMP Flood Attack': 'DDoS_ATTACK',
          'Port Scanning': 'PORT_SCAN',
          'Potential Data Exfiltration': 'DATA_LEAKAGE',
          'Potential Command Injection': 'COMMAND_INJECTION',
          'Potential SQL Injection': 'SQL_INJECTION',
          'Potential XSS Attack': 'XSS_ATTACK',
          'Potential Directory Traversal': 'PATH_TRAVERSAL',
          'Potential SSH Brute Force': 'BRUTE_FORCE',
          'Potential RDP Brute Force': 'BRUTE_FORCE',
          'Potential ARP Spoofing': 'INTRUSION_DETECTION',
          'Potential DNS Tunneling': 'MALWARE_DETECTION',
          'Potential HTTP Tunneling': 'MALWARE_DETECTION',
          'Potential Buffer Overflow': 'INTRUSION_DETECTION',
          'Unusual Level Communication': 'ANOMALY_DETECTION'
        };

        const alertData = {
          title: ioa.type,
          description: ioa.description,
          severity: severityMap[ioa.severity] || 'MEDIUM',
          type: typeMap[ioa.type] || 'ANOMALY_DETECTION',
          source: 'PCAP_Analysis',
          sourceIp: ioa.sourceIp,
          destinationIp: ioa.destinationIp,
          protocol: ioa.protocol || 'Unknown',
          rawData: JSON.stringify({
            evidence: ioa.evidence,
            mitreTactic: ioa.mitreTactic,
            mitreTechnique: ioa.mitreTechnique,
            mitreId: ioa.mitreId,
            timestamp: ioa.timestamp
          }),
          tags: [ioa.type, 'PCAP', 'IOA'],
          riskScore: ioa.severity === 'critical' ? 90 : 
                    ioa.severity === 'high' ? 70 :
                    ioa.severity === 'medium' ? 50 : 30,
          confidenceScore: 75
        };

        return api.post('/api/alerts', alertData);
      });

      const results = await Promise.allSettled(alertPromises);
      const successful = results.filter(result => result.status === 'fulfilled').length;
      const failed = results.filter(result => result.status === 'rejected').length;
      
      console.log(`Successfully created ${successful} alerts, ${failed} failed`);
      
      if (successful > 0) {
        setUploadStatus(`PCAP analysis completed. ${successful} security alerts created in database.`);
      }
      
    } catch (error) {
      console.error('Error sending IOAs to backend:', error);
      setUploadStatus('Error: Failed to save alerts to database.');
    }
  }, []);

  // Add useEffect to sync packetInfos with localStorage
  useEffect(() => {
    localStorage.setItem('packetInfos', JSON.stringify(packetInfos));
  }, [packetInfos]);

  // Framer Motion variants for table animation
  const containerVariants = {
    hidden: {},
    visible: { transition: { staggerChildren: 0.1 } }
  };
  const rowVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0 }
  };

  // KPI stats based on preview packetInfos
  const kpiStats = useMemo(() => {
    const ips = new Set<string>();
    const ports = new Set<number>();
    const protocols = new Set<string>();
    const protoCounts: Record<string, number> = {};
    // Purdue crossings & east-west vs north-south
    let purdueCrossings = 0;
    let eastWest = 0;
    let northSouth = 0;
    const itLevels = new Set(['Level 4', 'Level 5']);
    safePacketInfos.forEach(p => {
      ips.add(p.sourceIp);
      ips.add(p.destinationIp);
      ports.add(p.sourcePort);
      ports.add(p.destinationPort);
      protocols.add(p.protocol);
      protoCounts[p.protocol] = (protoCounts[p.protocol] || 0) + 1;
      const sL = p.sourceLevel || '';
      const dL = p.destinationLevel || '';
      if (sL && dL && sL !== dL) purdueCrossings++;
      const sIT = itLevels.has(sL);
      const dIT = itLevels.has(dL);
      if (sIT !== dIT) northSouth++;
      else eastWest++;
    });
    const topProtocol = Object.entries(protoCounts).sort((a, b) => b[1] - a[1])[0];
    const ewPct = (eastWest + northSouth) > 0 ? Math.round((eastWest / (eastWest + northSouth)) * 100) : 0;
    return {
      uniqueIpCount: ips.size,
      uniquePortCount: ports.size,
      protocolCount: protocols.size,
      purdueCrossings,
      eastWest,
      northSouth,
      eastWestPct: ewPct,
      topProtocol: topProtocol ? { name: topProtocol[0], count: topProtocol[1] } : null,
    };
  }, [safePacketInfos]);

  // Live rate: packets per second over the last ~60s window
  const liveRateStats = useMemo(() => {
    const buckets: number[] = new Array(20).fill(0);
    if (!livePackets || livePackets.length === 0) {
      return { perSec: 0, sparkline: buckets };
    }
    const now = Date.now();
    const windowMs = 60_000;
    const bucketMs = windowMs / buckets.length;
    let inWindow = 0;
    livePackets.forEach(p => {
      const t = p.timestamp ? new Date(p.timestamp).getTime() : NaN;
      if (!Number.isFinite(t)) return;
      const age = now - t;
      if (age >= 0 && age < windowMs) {
        inWindow++;
        const idx = Math.min(buckets.length - 1, Math.floor((windowMs - age) / bucketMs));
        buckets[idx]++;
      }
    });
    return { perSec: +(inWindow / (windowMs / 1000)).toFixed(1), sparkline: buckets };
  }, [livePackets]);

  // Fetch a specific page of packets for given file
  const fetchPage = useCallback(async (page: number, file: File) => {
    const formData = new FormData();
    formData.append('pcap', file);
    // Call paged endpoint
    const response = await api.post<{ total: number; packets: PacketInfo[] }>(
      `/upload/pcap?page=${page}&size=${uploadPageSize}`,
      formData
    );
    const { total, packets } = response.data;
    setTotalPacketCount(total);
    if (page === 0) {
      setPacketInfos(packets);
      setUploadStatus(`File analyzed: ${total} packets found, showing first ${packets.length}.`);
    } else {
      // Append new packets and update status with combined count
      setPacketInfos(prev => {
        const combined = [...prev, ...packets];
        setUploadStatus(
          `Loaded ${packets.length} more packets (showing ${combined.length}/${total}).`
        );
        return combined;
      });
    }
    setUploadCompleted(true);
    setUploadPage(page);
  }, []);

  // Fetch all packets at once
  const fetchAll = useCallback(async () => {
    if (!uploadedFile || totalPacketCount === null) return;
    setIsUploading(true);
    setUploadStatus('Loading all packets...');
    try {
      const formData = new FormData();
      formData.append('pcap', uploadedFile);
      const res = await api.post<{ total: number; packets?: PacketInfo[]; error?: string; ioas?: IOA[] }>(
        `/upload/pcap?page=0&size=${totalPacketCount}`,
        formData,
        {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        }
      );
      
      if (res.data.error) {
        setUploadStatus(`Error: ${res.data.error}`);
        return;
      }
      
      if (!res.data.packets || res.data.packets.length === 0) {
        setUploadStatus('No packets were parsed. Ensure the PCAP contains IP traffic and is in a supported format.');
        return;
      }
      
      const all = Array.isArray(res.data.packets) ? res.data.packets : [];
      setPacketInfos(all);
      
      // Process IOAs and send to backend
      const processedIOAs = res.data.ioas ? res.data.ioas.map(mapIOAToMitre) : [];
      setIOAs(processedIOAs);
      
      // Send IOAs to backend as alerts
      if (processedIOAs.length > 0) {
        await sendIOAsToBackend(processedIOAs);
      } else {
        setUploadStatus(`Showing all ${all.length} packets. No security threats detected.`);
      }
      
      setUploadCompleted(true);
    } catch (err: any) {
      console.error('Fetch all error:', err);
      setUploadStatus(`Error: ${err.message || String(err)}`);
    } finally {
      setIsUploading(false);
    }
  }, [uploadedFile, totalPacketCount]);

  // Handler for file drop/upload
  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) {
      setUploadStatus('Please select a file.');
      return;
    }

    setSelectedFileName(file.name);
    setPacketInfos([]);
    setTotalPacketCount(null);

    // Validate file type
    if (!file.name.toLowerCase().endsWith('.pcap') && !file.name.toLowerCase().endsWith('.pcapng')) {
      setUploadStatus('Please upload only .pcap or .pcapng files.');
      return;
    }

    setUploadedFile(file);
    setIsUploading(true);
    setUploadStatus('File is being uploaded and analyzed...');
    setUploadCompleted(false);

    try {
      const formData = new FormData();
      formData.append('pcap', file);

      const response = await api.post<{
        total: number;
        packets: PacketInfo[];
        ioas?: IOA[];
        assetDetection?: {
          assetsDetected: boolean;
          message: string;
        };
      }>(
        '/api/upload/pcap',
        formData,
        {
          headers: {
            'Content-Type': 'multipart/form-data'
          },
          timeout: 300000
        }
      );

      const { total, packets, ioas: detectedIoas, assetDetection } = response.data;
      setTotalPacketCount(total);
      setPacketInfos(packets || []);
      setIOAs(detectedIoas ? detectedIoas.map(mapIOAToMitre) : []);
      
      // Handle asset detection message
      let statusMessage = `File analyzed: ${total} packets found, showing first ${packets.length} packets.`;
      if (assetDetection?.assetsDetected) {
        statusMessage += ` ${assetDetection.message}`;
      }
      setUploadStatus(statusMessage);
      setUploadCompleted(true);

    } catch (error: any) {
      console.error('Upload error:', error);
      let errorMessage = 'Upload error: ';
      
      if (error.response) {
        // Backend returns error in 'error' field, not 'message'
        const backendError = error.response.data?.error || error.response.data?.message;
        if (backendError) {
          errorMessage += backendError;
        } else if (error.response.status === 413) {
          errorMessage += 'File too large. Maximum file size is 2GB.';
        } else if (error.response.status === 500) {
          errorMessage += 'Server error. Please check backend logs for details.';
        } else {
          errorMessage += error.response.statusText || 'Server error';
        }
      } else if (error.request) {
        errorMessage += 'Could not connect to server. Please make sure backend is running on http://localhost:8080';
      } else {
        errorMessage += error.message || 'Unknown error';
      }
      
      setUploadStatus(errorMessage);
      setUploadCompleted(false);
      setIOAs([]);
    } finally {
      setIsUploading(false);
    }
  }, []);

  // Initialize dropzone with both click and drag enabled
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.tcpdump.pcap': ['.pcap', '.pcapng']
    },
    maxFiles: 1,
    noClick: false  // Enable click to select file
  });

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    navigate('/login');
  };

  const getLevelColor = (level: string): string => {
    const colors: { [key: string]: string } = {
      'Level 0': '#FF6B6B', // Process
      'Level 1': '#4ECDC4', // Basic Control
      'Level 2': '#45B7D1', // Area Supervisory
      'Level 3': '#96CEB4', // Site Business
      'Level 4': '#FFEEAD', // DMZ
      'Level 5': '#D4A5A5'  // Enterprise
    };
    return colors[level] || '#666666';
  };

  const getDeviceIcon = (level: string) => {
    // Determine which icon to use based on device level
    if (level === 'Level 0') {
      return '/assets/devices/iot.svg';
    } else if (level === 'Level 1') {
      return '/assets/devices/plc.svg';
    } else if (level === 'Level 2') {
      return '/assets/devices/hmi.svg';
    } else if (level === 'Level 3' || level === 'Level 4' || level === 'Level 5') {
      return '/assets/devices/workstation.svg';
    }
    
    // Default icon based on level name
    if (level.toLowerCase().includes('dmz')) {
      return '/assets/devices/router.svg';
    }
    
    // Default icon
    return '/assets/devices/workstation.svg';
  };

  const requestSort = (key: keyof PacketInfo) => {
    let direction: 'asc' | 'desc' = 'asc';
    if (sortConfig && sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  // New sorting function for Live table
  const requestLiveSort = (key: keyof PacketInfo) => {
    let direction: 'asc' | 'desc' = 'asc';
    if (liveSortConfig && liveSortConfig.key === key && liveSortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setLiveSortConfig({ key, direction });
  };

  // Filter packets based on filterText
  const filteredPackets = useMemo(() => {
    const infos = Array.isArray(packetInfos) ? packetInfos : [];
    return infos.filter(packet => {
      const time = new Date(packet.timestamp).toLocaleTimeString();
      const source = `${packet.sourceIp} (${packet.sourceLevel})`;
      const dest = `${packet.destinationIp} (${packet.destinationLevel})`;
      return (
        time.includes(filterText) ||
        source.toLowerCase().includes(filterText.toLowerCase()) ||
        dest.toLowerCase().includes(filterText.toLowerCase()) ||
        packet.protocol.toLowerCase().includes(filterText.toLowerCase()) ||
        packet.communicationType.toLowerCase().includes(filterText.toLowerCase()) ||
        packet.packetLength.toString().includes(filterText)
      );
    });
  }, [packetInfos, filterText]);

  // Sort filtered packets
  const sortedPackets = useMemo(() => {
    const sortable = [...filteredPackets];
    if (sortConfig) {
      sortable.sort((a, b) => {
        const aVal = a[sortConfig.key];
        const bVal = b[sortConfig.key];
        if (typeof aVal === 'number' && typeof bVal === 'number') {
          return sortConfig.direction === 'asc' ? aVal - bVal : bVal - aVal;
        }
        const aStr = String(aVal).toLowerCase();
        const bStr = String(bVal).toLowerCase();
        return sortConfig.direction === 'asc' ? aStr.localeCompare(bStr) : bStr.localeCompare(aStr);
      });
    }
    return sortable;
  }, [filteredPackets, sortConfig]);

  // Pagination state (after sortedPackets)
  const [currentPage, setCurrentPage] = useState<number>(1);
  const totalPages = Math.ceil(sortedPackets.length / rowsPerPage) || 1;
  const paginatedPackets = useMemo(() => {
    const startIndex = (currentPage - 1) * rowsPerPage;
    return sortedPackets.slice(startIndex, startIndex + rowsPerPage);
  }, [sortedPackets, currentPage, rowsPerPage]);

  // Add filteredLivePackets before sorting
  const filteredLivePackets = useMemo(() => {
    return livePackets.filter(packet =>
      packet.sourceIp.includes(liveFilterText) ||
      packet.destinationIp.includes(liveFilterText) ||
      packet.protocol.toLowerCase().includes(liveFilterText.toLowerCase())
    );
  }, [livePackets, liveFilterText]);

  // Sort live packets based on liveSortConfig
  const sortedLivePackets = useMemo(() => {
    const sortable = [...filteredLivePackets];
    if (liveSortConfig) {
      sortable.sort((a, b) => {
        const aVal = a[liveSortConfig.key];
        const bVal = b[liveSortConfig.key];
        // Basic sort logic (can be enhanced like sortedPackets)
        if (typeof aVal === 'number' && typeof bVal === 'number') {
          return liveSortConfig.direction === 'asc' ? aVal - bVal : bVal - aVal;
        }
        const aStr = String(aVal).toLowerCase();
        const bStr = String(bVal).toLowerCase();
        return liveSortConfig.direction === 'asc' ? aStr.localeCompare(bStr) : bStr.localeCompare(aStr);
      });
    } else {
        // Default sort by timestamp descending if no sort config
        sortable.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    }
    return sortable;
  }, [filteredLivePackets, liveSortConfig]);

  // Add live pagination state and memo
  const [liveCurrentPage, setLiveCurrentPage] = useState<number>(1);
  const [liveRowsPerPage, setLiveRowsPerPage] = useState<number>(25);
  
  // Network map tool states
  const [networkLayout, setNetworkLayout] = useState<'hierarchical' | 'force'>('hierarchical');
  const [networkFilter, setNetworkFilter] = useState<string>('');
  const [networkView, setNetworkView] = useState<'detailed' | 'compact'>('detailed');
  
  // PCAP Network map tool states
  const [pcapNetworkLayout, setPcapNetworkLayout] = useState<'hierarchical' | 'force'>('hierarchical');
  const [pcapNetworkFilter, setPcapNetworkFilter] = useState<string>('');
  const [pcapNetworkView, setPcapNetworkView] = useState<'detailed' | 'compact'>('detailed');
  const [isNetworkRendered, setIsNetworkRendered] = useState<boolean>(false);
  const liveTotalPages = Math.ceil(sortedLivePackets.length / liveRowsPerPage) || 1;
  const livePaginatedPackets = useMemo(() => {
    const startIndex = (liveCurrentPage - 1) * liveRowsPerPage;
    return sortedLivePackets.slice(startIndex, startIndex + liveRowsPerPage);
  }, [sortedLivePackets, liveCurrentPage, liveRowsPerPage]);

  // Fetch network interfaces on component mount
  useEffect(() => {
    const fetchInterfaces = async () => {
      try {
        setFetchInterfacesError('');
        setLiveStatusMessage('Fetching network interfaces...');
        console.log('Fetching network interfaces from /pcap/interfaces...');
        const response = await api.get<NetworkInterfaceInfo[]>('/pcap/interfaces'); // Use correct endpoint
        console.log('Response received:', response);
        const interfaces = response.data || [];
        console.log('Interfaces found:', interfaces);
        setNetworkInterfaces(interfaces);
        setLiveStatusMessage(''); // Clear loading message

        if (interfaces.length > 0) {
          // Heuristic to find a default interface (e.g., non-loopback IPv4)
          const defaultInterface = 
            interfaces.find(iface => 
              !iface.name.toLowerCase().includes('loopback') && 
              !iface.description?.toLowerCase().includes('virtual') && 
              iface.addresses.some(addr => !addr.startsWith('127.') && !addr.startsWith('169.254.') && addr.includes('.'))
            ) || 
            interfaces.find(iface => 
               !iface.name.toLowerCase().includes('loopback') && 
               iface.addresses.some(addr => !addr.startsWith('127.'))
            ) || 
            interfaces[0]; // Fallback
            
          if (defaultInterface) {
             setSelectedInterface(defaultInterface.name);
          }
        } else {
            setFetchInterfacesError('No network interfaces found by the backend.');
        }
      } catch (error: any) {
        console.error("Error fetching network interfaces:", error);
        console.error("Error details:", {
          response: error.response,
          request: error.request,
          message: error.message,
          status: error.response?.status,
          data: error.response?.data
        });
        
        let message = 'Failed to fetch network interfaces.';
        // Construct detailed error message based on error type...
        if (error.response) {
            if (typeof error.response.data === 'string' && error.response.data.includes("No network interfaces found")) {
                 message = "No network interfaces found. Ensure backend has permissions and Npcap/libpcap is installed.";
             } else if (typeof error.response.data === 'string' && error.response.data.includes("Error accessing network interfaces")) {
                  message = "Backend permission or native library error accessing interfaces. Run backend as administrator/root.";
             } else { message = `Backend error: ${error.response.status} ${error.response.data || 'Unknown error'}`; }
        } else if (error.request) { message = 'Could not connect to backend to fetch interfaces.';
        } else { message = `Error: ${error.message}`; }
        setFetchInterfacesError(message);
        setNetworkInterfaces([]);
        setLiveStatusMessage('');
      }
    };
    fetchInterfaces();
  }, []); // Runs once on mount

  // WebSocket connection management
  const connectWebSocket = (interfaceName: string) => {
    if (liveWebSocketRef.current) {
      // close existing socket before reopening
      liveWebSocketRef.current.close();
    }
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.hostname}:8080/ws/livepackets`;
    // set status and open socket
    setLiveStatusMessage(`Connecting to ${wsUrl}...`);

    try {
      const socket = new WebSocket(wsUrl);
      liveWebSocketRef.current = socket;

      socket.onopen = () => {
        setLiveStatusMessage(`Connected. Capturing on ${interfaceName}...`);
        setIsListening(true);
        setLivePackets([]);
        setLiveMarkers([]);
        try {
           socket.send(JSON.stringify({ action: 'start', interfaceName }));
           // start capture
        } catch (err) {
          console.error("[LiveTraffic] Error sending START command:", err);
        }
      };

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          // Check if this is an error message from the backend
          if (data.error) {
            console.error("[LiveTraffic] Backend error:", data.error, data.message);
            
            // If the error is about interface not found, suggest refreshing the interface list
            if (data.message && data.message.includes("Network interface") && data.message.includes("not found")) {
              setLiveStatusMessage(`Backend error: ${data.message}. Please refresh the interface list and try again.`);
              // Clear the selected interface to force user to select a new one
              setSelectedInterface('');
            } else {
              setLiveStatusMessage(`Backend error: ${data.message}`);
            }
            
            setIsListening(false);
            liveWebSocketRef.current = null;
            return;
          }
          
          // Check if this is a packet data message
          const packetData: PacketInfo = data;
          if (packetData?.sourceIp && packetData?.timestamp) {
            livePacketBufferRef.current.push(packetData);
          } else {
            console.warn("[LiveTraffic] Received invalid packet data structure:", event.data);
          }
        } catch (error) {
          console.error("[LiveTraffic] Error parsing WebSocket message:", error, "Data:", event.data);
        }
      };

      socket.onerror = (error) => {
        console.error("[LiveTraffic] WebSocket error:", error);
        setLiveStatusMessage(`WebSocket error. Check backend & console.`);
        setIsListening(false);
        liveWebSocketRef.current = null;
      };

      socket.onclose = (event) => {
        console.log(`[LiveTraffic] WebSocket closed. Code: ${event.code}, Reason: ${event.reason}`);
        if (isListening) { setLiveStatusMessage(`WebSocket closed: ${event.reason || 'Connection ended'}. Code: ${event.code}`); }
        setIsListening(false);
        liveWebSocketRef.current = null;
      };
    } catch (error) { console.error("[LiveTraffic] Error creating WebSocket:", error); setLiveStatusMessage('Error creating WebSocket connection.'); }
  };

  const disconnectWebSocket = () => {
      if (liveWebSocketRef.current) {
          console.log("[LiveTraffic] Closing WebSocket connection intentionally.");
          setLiveStatusMessage('Stopping capture...');
          try { liveWebSocketRef.current.send(JSON.stringify({ action: 'stop' })); console.log("[LiveTraffic] Sent STOP command.");
          } catch (err) { console.error("[LiveTraffic] Error sending STOP command:", err); }
          liveWebSocketRef.current.close(1000, "User stopped capture");
          liveWebSocketRef.current = null;
          setLiveStatusMessage('Capture stopped.');
      } else { setLiveStatusMessage(''); }
      setIsListening(false);
  };
  
  // Handler for the start/stop button
  const toggleLiveCapture = () => {
    if (isListening) {
      disconnectWebSocket();
    } else {
      if (!selectedInterface) { setLiveStatusMessage('Please select a network interface first.'); return; }
      connectWebSocket(selectedInterface);
    }
  };

  // Cleanup WebSocket on component unmount
  useEffect(() => {
      return () => {
          if (liveWebSocketRef.current) {
              console.log("[LiveTraffic] Cleaning up WebSocket on component unmount.");
              liveWebSocketRef.current.close(1000, "Component unmounted");
              liveWebSocketRef.current = null;
          }
      };
  }, []);

  // Effect to geolocate live source IPs (Adapted from Honeypot)
  useEffect(() => {
    const isPrivateIP = (ip: string): boolean => {
      const parts = ip.split('.').map(Number);
      if (parts[0] === 10) return true;
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
      if (parts[0] === 192 && parts[1] === 168) return true;
      return false;
    };

    console.log('[LiveTraffic] Geolocation Effect Triggered. Listening:', isListening, 'Sources:', livePackets.length);

    // Only run if listening and have IPs
    if (!isListening || livePackets.length === 0) {
        console.log('[LiveTraffic] Clearing live markers (not listening or no sources).');
        setLiveMarkers([]); // Clear markers if not listening or no sources
        return;
    } 

    // Correctly map over livePackets, removing non-existent 'count'
    const ipsToGeolocate = livePackets.filter(({ sourceIp }) => !isPrivateIP(sourceIp));

    if (ipsToGeolocate.length === 0) {
        console.log('[LiveTraffic] No public IPs found to geolocate.');
        // Optionally clear markers if only private IPs were generated
        // setLiveMarkers([]); 
        return;
    }

    Promise.all(
      ipsToGeolocate
        // Remove 'count' from destructuring as it's not on PacketInfo
        .map(({ sourceIp, protocol }) => 
          fetch(`https://ipapi.co/${sourceIp}/json/`) // Using ipapi.co
            .then(res => res.json())
            .then((data: any) => {
              if (data && !data.error && data.latitude != null && data.longitude != null) {
                 // Pass protocol along if needed, or fetch it again if necessary
                 return { ip: sourceIp, protocol, lat: data.latitude, lon: data.longitude };
              } else {
                 return null;
              }
            })
            .catch((error) => {
                console.error(`[LiveTraffic] Geolocation FETCH ERROR for ${sourceIp}:`, error);
                return null;
            })
        )
    ).then(results => {
        const validMarkers = results.filter((m): m is any => m !== null);
        console.log('[LiveTraffic] Geolocation results (filtered):', validMarkers);
        // Update liveMarkers only if still listening to avoid race condition
        if (isListening) {
            console.log('[LiveTraffic] Updating liveMarkers state.');
            setLiveMarkers(validMarkers);
        } else {
            console.log('[LiveTraffic] Not updating state, listening stopped.');
        }
    });
  }, [livePackets, isListening]); // Rerun when sources change or listening stops

  // Add throttled update interval for live packets
  useEffect(() => {
    const timer = setInterval(() => {
      if (livePacketBufferRef.current.length > 0) {
        setLivePackets(prev => [...livePacketBufferRef.current, ...prev].slice(0, 500));
        livePacketBufferRef.current = [];
      }
    }, 200);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    console.log('Packet Infos:', packetInfos);
    // Reset network rendered state when re-rendering
    setIsNetworkRendered(false);
    if (networkContainer.current && safePacketInfos.length > 0) {
      // Create nodes and edges from packet information
      const nodes = new Set<string>();
      const nodeData: NetworkNode[] = [];
      const edgeIds = new Set<string>();
      const edgeData: NetworkEdge[] = [];
      
      safePacketInfos.forEach(packet => {
        // Apply protocol filter
        if (pcapNetworkFilter && packet.protocol !== pcapNetworkFilter) {
          return;
        }
        
        // Add source node if not exists
        if (!nodes.has(packet.sourceIp)) {
          nodes.add(packet.sourceIp);
          nodeData.push({
            id: packet.sourceIp,
            label: packet.sourceIp,
            group: packet.sourceLevel,
            title: `${packet.sourceIp}\n${packet.sourceLevel}`,
            color: getLevelColor(packet.sourceLevel),
            shape: 'image',
            image: getDeviceIcon(packet.sourceLevel),
            size: pcapNetworkView === 'detailed' ? 35 : 30
          });
        }
        
        // Add destination node if not exists
        if (!nodes.has(packet.destinationIp)) {
          nodes.add(packet.destinationIp);
          nodeData.push({
            id: packet.destinationIp,
            label: packet.destinationIp,
            group: packet.destinationLevel,
            title: `${packet.destinationIp}\n${packet.destinationLevel}`,
            color: getLevelColor(packet.destinationLevel),
            shape: 'image',
            image: getDeviceIcon(packet.destinationLevel),
            size: pcapNetworkView === 'detailed' ? 35 : 30
          });
        }
        
        // Add edge (deduplicated)
        const edgeId = `${packet.sourceIp}-${packet.destinationIp}-${packet.protocol}`;
        if (!edgeIds.has(edgeId)) {
          edgeIds.add(edgeId);
          edgeData.push({
            id: edgeId,
            from: packet.sourceIp,
            to: packet.destinationIp,
            label: packet.protocol,
            arrows: 'to',
            color: getProtocolColor(packet.protocol)
          });
        }
      });

      console.log('Node Data:', nodeData);

      // Configure network options
      const options = {
        nodes: {
          shape: 'image',
          size: pcapNetworkView === 'detailed' ? 35 : 30,
          font: {
            size: pcapNetworkView === 'detailed' ? 14 : 12,
            color: '#333333',
            face: 'arial',
            background: 'white'
          },
          borderWidth: 2,
          // Add node animations
          animation: {
            duration: 1000,
            easingFunction: 'easeInOutQuad'
          },
          // Enhanced hover effects
          hover: {
            enabled: true,
            scale: 1.1,
            borderWidth: 3,
            shadow: true
          },
          // Click effects
          click: {
            enabled: true,
            scale: 1.05
          },
          // Add glow effects
          shadow: {
            enabled: true,
            color: 'rgba(0,0,0,0.3)',
            size: 10,
            x: 5,
            y: 5
          },
          // Smooth scaling
          scaling: {
            min: 20,
            max: 50,
            label: {
              enabled: true,
              min: 12,
              max: 20,
              maxVisible: 20
            }
          }
        },
        edges: {
          width: 2,
          color: {
            inherit: false,
            color: '#666666'
          },
          font: {
            size: 10,
            color: '#666666',
            background: 'white'
          },
          smooth: {
            enabled: true,
            type: 'straightCross',
            forceDirection: 'none',
            roundness: 0.5
          },
          // Add edge animations
          animation: {
            duration: 800,
            easingFunction: 'easeInOutCubic'
          },
          // Enhanced hover effects
          hover: {
            enabled: true,
            width: 4,
            color: '#3B82F6'
          },
          // Edge drawing animation
          drawTime: 1000,
          // Edge selection effects
          selectionWidth: 3,
          selectionColor: '#EF4444',
          // Smooth edge transitions
          transition: {
            duration: 300,
            easingFunction: 'easeInOutCubic'
          },
          // Enhanced edge styling
          shadow: {
            enabled: true,
            color: 'rgba(0,0,0,0.2)',
            size: 5,
            x: 2,
            y: 2
          },
          // Edge scaling
          scaling: {
            min: 1,
            max: 5,
            label: {
              enabled: true,
              min: 8,
              max: 12,
              maxVisible: 15
            }
          }
        },
        physics: {
          enabled: pcapNetworkLayout === 'force',
          // Enhanced physics for more dynamic movement
          solver: 'forceAtlas2Based',
          forceAtlas2Based: {
            gravitationalConstant: -50,
            centralGravity: 0.01,
            springLength: 100,
            springConstant: 0.08,
            damping: 0.4,
            avoidOverlap: 0.5
          },
          // Smooth physics transitions
          stabilization: {
            enabled: true,
            iterations: 1000,
            updateInterval: 100,
            fit: true
          },
          // Physics animation settings
          minVelocity: 0.75,
          maxVelocity: 30,
          // Smooth movement
          timestep: 0.5,
          // Add bouncing effects
          barnesHut: {
            gravitationalConstant: -2000,
            centralGravity: 0.3,
            springLength: 95,
            springConstant: 0.04,
            damping: 0.09,
            avoidOverlap: 0.5
          }
        },
        layout: {
          hierarchical: {
            enabled: pcapNetworkLayout === 'hierarchical',
            direction: 'LR',
            sortMethod: 'directed',
            nodeSpacing: 200,
            levelSeparation: 300,
            parentCentralization: true,
            edgeMinimization: true,
            blockShifting: true,
            // Add hierarchical animation
            animation: {
              duration: 1000,
              easingFunction: 'easeInOutQuart'
            },
            // Enhanced hierarchical settings
            treeSpacing: 200,
            // Smooth transitions
            transition: {
              duration: 800,
              easingFunction: 'easeInOutQuart'
            }
          }
        },
        // Global animation settings
        animation: {
          duration: 1000,
          easingFunction: 'easeInOutQuad'
        },
        // Interaction animations
        interaction: {
          hover: true,
          tooltipDelay: 200,
          zoomView: true,
          dragView: true,
          // Smooth zoom and pan
          zoomSpeed: 0.5,
          dragSpeed: 0.5
        },
        // Smooth rendering
        smoothCurves: {
          enabled: true,
          type: 'continuous',
          forceDirection: 'none',
          roundness: 0.5
        },
        // Enhanced animation settings
        animationRedraw: true,
        animationEasing: 'easeInOutQuad',
        // Smooth node transitions
        nodeTransition: {
          duration: 500,
          easingFunction: 'easeInOutQuad'
        },
        // Smooth edge transitions
        edgeTransition: {
          duration: 300,
          easingFunction: 'easeInOutCubic'
        },
        groups: {
          'Level 0': { color: '#FF6B6B' },
          'Level 1': { color: '#4ECDC4' },
          'Level 2': { color: '#45B7D1' },
          'Level 3': { color: '#96CEB4' },
          'Level 4': { color: '#FFEEAD' },
          'Level 5': { color: '#D4A5A5' }
        }
      };

      // Create network
      const networkInstance = new Network(
        networkContainer.current,
        { nodes: nodeData, edges: edgeData },
        options
      );

      // Add enhanced animation event listeners
      networkInstance.on('stabilizationProgress', (params) => {
        // Show stabilization progress with animation
        if (params.iterations > 0) {
          const progress = Math.round((params.iterations / 1000) * 100);
          console.log(`Network stabilizing: ${progress}%`);
        }
      });

      networkInstance.on('stabilizationIterationsDone', () => {
        console.log('Network stabilization complete');
        // Add a subtle animation effect when stabilization is complete
        networkInstance.fit({ animation: { duration: 800, easingFunction: 'easeInOutQuart' } });
        // Mark network as fully rendered
        setIsNetworkRendered(true);
      });

      // Add error handling for ResizeObserver
      const originalErrorHandler = window.onerror;
      window.onerror = function(
        event: Event | string,
        source?: string,
        lineno?: number,
        colno?: number,
        error?: Error
      ): boolean {
        if (typeof event === 'string' && event.includes('ResizeObserver loop completed with undelivered notifications')) {
          return true;
        }
        if (originalErrorHandler) {
          return originalErrorHandler.call(window, event, source, lineno, colno, error);
        }
        return false;
      };

      setNetwork(networkInstance);

      return () => {
        if (networkInstance) {
          networkInstance.destroy();
        }
        window.onerror = originalErrorHandler;
      };
    }
  }, [safePacketInfos, pcapNetworkLayout, pcapNetworkFilter, pcapNetworkView]);

  useEffect(() => {
    if (darkMode) document.documentElement.classList.add('dark');
    else document.documentElement.classList.remove('dark');
    localStorage.setItem('theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  // Generate alerts from packetInfos
  useEffect(() => {
    safePacketInfos.forEach(packet => {
      const key = `${packet.timestamp}-${packet.sourceIp}-${packet.destinationIp}`;
      if (!processedIds.current.has(key)) {
        processedIds.current.add(key);
        let severity: Alert['severity'] = 'info';
        if (packet.packetLength > 1000) severity = 'critical';
        else if (packet.protocol === 'ICMP') severity = 'warning';
        const message = `${packet.protocol} packet (${packet.packetLength} bytes) from ${packet.sourceIp}`;
        setAlerts(prev => [{ id: key, message, timestamp: new Date(packet.timestamp), severity }, ...prev]);
      }
    });
  }, [safePacketInfos]);

  // Manually dismiss alerts; no auto-dismiss

  // Network map tool functions
  const initializeLiveNetworkMap = useCallback(() => {
    if (liveNetworkContainer.current && livePackets.length > 0) {
      const options = {
        nodes: { 
          shape: 'dot', 
          size: networkView === 'detailed' ? 25 : 20, 
          font: { size: networkView === 'detailed' ? 14 : 12, color: '#333333' }, 
          borderWidth: 2, 
          shadow: true 
        },
        edges: { 
          width: 2, 
          font: { size: 10, color: '#666666' }, 
          shadow: true 
        },
        physics: { 
          enabled: networkLayout === 'force',
          hierarchicalRepulsion: networkLayout === 'hierarchical' ? { nodeDistance: 150 } : undefined
        }
      };
      
      if (liveNetwork) {
        liveNetwork.destroy();
      }
      
      liveNodesDsRef.current = new DataSet<NetworkNode>([]);
      liveEdgesDsRef.current = new DataSet<NetworkEdge>([]);
      
      const networkInstance = new Network(
        liveNetworkContainer.current,
        { nodes: liveNodesDsRef.current, edges: liveEdgesDsRef.current },
        options
      );
      
      setLiveNetwork(networkInstance);
      
      // Update network data
      const nodesSet = new Set<string>();
      const nodesArr: NetworkNode[] = [];
      const edgeIds = new Set<string>();
      const edgesArr: NetworkEdge[] = [];
      
      livePackets.forEach(packet => {
        // Apply protocol filter
        if (networkFilter && packet.protocol !== networkFilter) {
          return;
        }
        
        if (!nodesSet.has(packet.sourceIp)) {
          nodesSet.add(packet.sourceIp);
          nodesArr.push({ 
            id: packet.sourceIp, 
            label: packet.sourceIp, 
            group: packet.sourceLevel, 
            title: `${packet.sourceIp}\n${packet.sourceLevel}`, 
            color: getLevelColor(packet.sourceLevel), 
            shape: 'image', 
            image: getDeviceIcon(packet.sourceLevel), 
            size: networkView === 'detailed' ? 35 : 30 
          });
        }
        if (!nodesSet.has(packet.destinationIp)) {
          nodesSet.add(packet.destinationIp);
          nodesArr.push({ 
            id: packet.destinationIp, 
            label: packet.destinationIp, 
            group: packet.destinationLevel, 
            title: `${packet.destinationIp}\n${packet.destinationLevel}`, 
            color: getLevelColor(packet.destinationLevel), 
            shape: 'image', 
            image: getDeviceIcon(packet.destinationLevel), 
            size: networkView === 'detailed' ? 35 : 30 
          });
        }
        const edgeId = `${packet.sourceIp}-${packet.destinationIp}-${packet.protocol}`;
        if (!edgeIds.has(edgeId)) {
          edgeIds.add(edgeId);
          edgesArr.push({ 
            id: edgeId, 
            from: packet.sourceIp, 
            to: packet.destinationIp, 
            label: packet.protocol, 
            arrows: 'to', 
            color: getProtocolColor(packet.protocol) 
          });
        }
      });
      
      liveNodesDsRef.current.clear();
      liveEdgesDsRef.current.clear();
      liveNodesDsRef.current.add(nodesArr);
      liveEdgesDsRef.current.add(edgesArr);
      
      // Freeze layout after initial render for hierarchical layout
      if (networkLayout === 'hierarchical') {
        setTimeout(() => {
          networkInstance.setOptions({ physics: false });
        }, 1000);
      }
    }
  }, [livePackets, networkLayout, networkFilter, networkView, liveNetwork]);

  const handleNetworkZoom = useCallback((action: 'in' | 'out' | 'fit') => {
    if (liveNetwork) {
      switch (action) {
        case 'in':
          liveNetwork.moveTo({ scale: 1.2 });
          break;
        case 'out':
          liveNetwork.moveTo({ scale: 0.8 });
          break;
        case 'fit':
          liveNetwork.fit();
          break;
      }
    }
  }, [liveNetwork]);

  const handleNetworkLayout = useCallback((layout: 'hierarchical' | 'force') => {
    setNetworkLayout(layout);
    // Reinitialize network with new layout
    if (liveNetworkContainer.current && livePackets.length > 0) {
      initializeLiveNetworkMap();
    }
  }, [livePackets.length, initializeLiveNetworkMap]);

  const toggleNetworkView = useCallback((view: 'detailed' | 'compact') => {
    setNetworkView(view);
    // Update network display based on view mode
    if (liveNetwork) {
      // This would update the network visualization
      console.log(`Switched to ${view} view`);
    }
  }, [liveNetwork]);

  // PCAP Network map functions
  const handlePCAPNetworkZoom = useCallback((action: 'in' | 'out' | 'fit') => {
    if (network) {
      switch (action) {
        case 'in':
          network.moveTo({ scale: 1.2 });
          break;
        case 'out':
          network.moveTo({ scale: 0.8 });
          break;
        case 'fit':
          network.fit();
          break;
      }
    }
  }, [network]);

  const handlePCAPNetworkLayout = useCallback((layout: 'hierarchical' | 'force') => {
    setPcapNetworkLayout(layout);
    // Reinitialize network with new layout
    if (networkContainer.current && safePacketInfos.length > 0) {
      // Force re-render by updating a dependency
      setPcapNetworkLayout(layout);
    }
  }, [safePacketInfos.length]);

  const togglePCAPNetworkView = useCallback((view: 'detailed' | 'compact') => {
    setPcapNetworkView(view);
    // Update network display based on view mode
    if (network) {
      // This would update the network visualization
      console.log(`Switched to ${view} view`);
    }
  }, [network]);

  // Initialize live network map when capturing starts
  useEffect(() => {
    if (isListening && liveNetworkContainer.current && !liveNetwork) {
      initializeLiveNetworkMap();
    }
  }, [isListening, liveNetworkContainer.current, initializeLiveNetworkMap]);

  // Update live network on new packets or settings changes
  useEffect(() => {
    if (liveNetwork && liveNodesDsRef.current && liveEdgesDsRef.current) {
      const nodesSet = new Set<string>();
      const nodesArr: NetworkNode[] = [];
      const edgeIds = new Set<string>(); // to dedupe edges
      const edgesArr: NetworkEdge[] = [];
      
      livePackets.forEach(packet => {
        // Apply protocol filter
        if (networkFilter && packet.protocol !== networkFilter) {
          return;
        }
        
        if (!nodesSet.has(packet.sourceIp)) {
          nodesSet.add(packet.sourceIp);
          nodesArr.push({ 
            id: packet.sourceIp, 
            label: packet.sourceIp, 
            group: packet.sourceLevel, 
            title: `${packet.sourceIp}\n${packet.sourceLevel}`, 
            color: getLevelColor(packet.sourceLevel), 
            shape: 'image', 
            image: getDeviceIcon(packet.sourceLevel), 
            size: networkView === 'detailed' ? 35 : 30 
          });
        }
        if (!nodesSet.has(packet.destinationIp)) {
          nodesSet.add(packet.destinationIp);
          nodesArr.push({ 
            id: packet.destinationIp, 
            label: packet.destinationIp, 
            group: packet.destinationLevel, 
            title: `${packet.destinationIp}\n${packet.destinationLevel}`, 
            color: getLevelColor(packet.destinationLevel), 
            shape: 'image', 
            image: getDeviceIcon(packet.destinationIp), 
            size: networkView === 'detailed' ? 35 : 30 
          });
        }
        const edgeId = `${packet.sourceIp}-${packet.destinationIp}-${packet.protocol}`;
        if (!edgeIds.has(edgeId)) {
          edgeIds.add(edgeId);
          edgesArr.push({ 
            id: edgeId, 
            from: packet.sourceIp, 
            to: packet.destinationIp, 
            label: packet.protocol, 
            arrows: 'to', 
            color: getProtocolColor(packet.protocol) 
          });
        }
      });
      
      liveNodesDsRef.current.clear();
      liveEdgesDsRef.current.clear();
      liveNodesDsRef.current.add(nodesArr);
      liveEdgesDsRef.current.add(edgesArr);
      
      // Update network options based on current settings
      if (liveNetwork) {
        liveNetwork.setOptions({
          physics: { 
            enabled: networkLayout === 'force',
            hierarchicalRepulsion: networkLayout === 'hierarchical' ? { nodeDistance: 150 } : undefined
          }
        });
      }
    }
  }, [livePackets, networkFilter, networkView, networkLayout, liveNetwork]);

  const protocolData = useMemo(() => {
    const counts: Record<string, number> = {};
    safePacketInfos.forEach(p => counts[p.protocol] = (counts[p.protocol] || 0) + 1);
    const labels = Object.keys(counts);
    return { labels, datasets: [{ data: labels.map(l => counts[l]), backgroundColor: labels.map(l => getProtocolColor(l)), }] };
  }, [safePacketInfos]);

  const ipData = useMemo(() => {
    const counts: Record<string, number> = {};
    safePacketInfos.forEach(p => {
      counts[p.sourceIp] = (counts[p.sourceIp] || 0) + 1;
      counts[p.destinationIp] = (counts[p.destinationIp] || 0) + 1;
    });
    const entries = Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0,5);
    const labels = entries.map(e => e[0]);
    const data = entries.map(e => e[1]);
    return { labels, datasets: [{ label: 'Packets', data, backgroundColor: '#4F46E5' }] };
  }, [safePacketInfos]);

  const portData = useMemo(() => {
    const counts: Record<number, number> = {};
    safePacketInfos.forEach(p => {
      counts[p.sourcePort] = (counts[p.sourcePort] || 0) + 1;
      counts[p.destinationPort] = (counts[p.destinationPort] || 0) + 1;
    });
    const entries = Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0,5);
    const labels = entries.map(e => e[0]);
    const data = entries.map(e => e[1]);
    return { labels, datasets: [{ label: 'Packets', data, backgroundColor: '#10B981' }] };
  }, [safePacketInfos]);

  const packetCount = safePacketInfos.length;

  // Add IOA detection logic
  const detectIOAs = useCallback((packets: PacketInfo[]) => {
    const detectedIOAs: IOA[] = [];
    const recentPackets = new Map<string, number>();
    const portScanAttempts = new Map<string, Set<number>>();
    const suspiciousPayloads = new Set<string>();
    const unusualProtocols = new Set<string>();
    const packetRates = new Map<string, number>();
    const protocolRates = new Map<string, number>();
    const timeWindow = 1000; // 1 second window
    const highRateThreshold = 100;
    const protocolThreshold = 50;
    const sourceIPCounts = new Map<string, number>();
    const destinationIPCounts = new Map<string, number>();
    let hasActualAttacks = false;
    
    packets.forEach(packet => {
      // Update source and destination IP counts
      sourceIPCounts.set(packet.sourceIp, (sourceIPCounts.get(packet.sourceIp) || 0) + 1);
      destinationIPCounts.set(packet.destinationIp, (destinationIPCounts.get(packet.destinationIp) || 0) + 1);

      const sourceKey = `${packet.sourceIp}-${packet.destinationIp}`;
      const currentCount = recentPackets.get(sourceKey) || 0;
      recentPackets.set(sourceKey, currentCount + 1);

      // Update packet rates for DDoS detection
      const currentTime = new Date(packet.timestamp).getTime();
      const rateKey = `${packet.sourceIp}-${currentTime}`;
      const currentRate = packetRates.get(rateKey) || 0;
      packetRates.set(rateKey, currentRate + 1);

      // Update protocol rates
      const protocolKey = `${packet.protocol}-${currentTime}`;
      const currentProtocolRate = protocolRates.get(protocolKey) || 0;
      protocolRates.set(protocolKey, currentProtocolRate + 1);

      // DDoS Detection Rules with MITRE mapping
      if (currentRate > highRateThreshold) {
        detectedIOAs.push({
          id: `${packet.timestamp}-${packet.sourceIp}-ddos-rate-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: packet.timestamp,
          sourceIp: packet.sourceIp,
          destinationIp: packet.destinationIp,
          type: 'Potential DDoS Attack (High Packet Rate)',
          severity: 'critical',
          description: 'Extremely high packet rate detected from source IP',
          evidence: `Packet rate of ${currentRate} packets per second from ${packet.sourceIp}`,
          mitreTactic: 'Impact',
          mitreTechnique: 'Network Denial of Service',
          mitreId: 'T1498'
        });
      }

      // Protocol-Specific Flood Detection
      if (currentProtocolRate > protocolThreshold && currentProtocolRate > 0) {
        hasActualAttacks = true;
        let mitreInfo = {
          tactic: 'Impact',
          technique: 'Network Denial of Service'
        };

        if (packet.protocol === 'TCP' && packet.flags.includes('S')) {
          mitreInfo = {
            tactic: 'Impact',
            technique: 'Network Denial of Service'
          };
        } else if (packet.protocol === 'UDP') {
          mitreInfo = {
            tactic: 'Impact',
            technique: 'Network Denial of Service'
          };
        } else if (packet.protocol === 'ICMP') {
          mitreInfo = {
            tactic: 'Impact',
            technique: 'Network Denial of Service'
          };
        }

        detectedIOAs.push({
          id: `${packet.timestamp}-${packet.protocol}-ddos-protocol-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: packet.timestamp,
          sourceIp: packet.sourceIp,
          destinationIp: packet.destinationIp,
          type: `Potential ${packet.protocol} Flood Attack`,
          severity: 'high',
          description: `High rate of ${packet.protocol} packets detected`,
          evidence: `${packet.protocol} packet rate of ${currentProtocolRate} packets per second`,
          mitreTactic: mitreInfo.tactic,
          mitreTechnique: mitreInfo.technique,
          mitreId: packet.protocol === 'TCP' && packet.flags.includes('S') ? 'T1498.001' :
                  packet.protocol === 'UDP' ? 'T1498.002' :
                  packet.protocol === 'ICMP' ? 'T1498.003' : 'T1498'
        });
      }

      // Port Scanning Detection
      if (packet.destinationPort >= 0 && packet.destinationPort <= 1024 && 
          packet.protocol === 'TCP' && packet.flags.includes('S')) {
        detectedIOAs.push({
          id: `${packet.timestamp}-${packet.sourceIp}-scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: packet.timestamp,
          sourceIp: packet.sourceIp,
          destinationIp: packet.destinationIp,
          type: 'Port Scanning',
          severity: 'medium',
          description: 'Potential port scanning activity detected',
          evidence: `TCP SYN packet to well-known port ${packet.destinationPort}`,
          mitreTactic: 'Discovery',
          mitreTechnique: 'Network Service Scanning',
          mitreId: 'T1046'
        });
      }

      // Data Exfiltration Detection
      if (packet.packetLength > 10000 && 
          (packet.destinationPort === 80 || packet.destinationPort === 443)) {
        detectedIOAs.push({
          id: `${packet.timestamp}-${packet.sourceIp}-exfil-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: packet.timestamp,
          sourceIp: packet.sourceIp,
          destinationIp: packet.destinationIp,
          type: 'Potential Data Exfiltration',
          severity: 'critical',
          description: 'Large data transfer to web ports detected',
          evidence: `Large packet (${packet.packetLength} bytes) to port ${packet.destinationPort}`,
          mitreTactic: 'Exfiltration',
          mitreTechnique: 'Exfiltration Over Alternative Protocol',
          mitreId: 'T1048'
        });
      }

      // Command Injection Detection
      if (packet.payloadInfo && 
          (packet.payloadInfo.includes(';') || 
           packet.payloadInfo.includes('|') || 
           packet.payloadInfo.includes('&&'))) {
        detectedIOAs.push({
          id: `${packet.timestamp}-${packet.sourceIp}-cmd-inj-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: packet.timestamp,
          sourceIp: packet.sourceIp,
          destinationIp: packet.destinationIp,
          type: 'Potential Command Injection',
          severity: 'critical',
          description: 'Command injection attempt detected in payload',
          evidence: `Suspicious characters found in payload: ${packet.payloadInfo.substring(0, 50)}...`,
          mitreTactic: 'Execution',
          mitreTechnique: 'Command and Scripting Interpreter',
          mitreId: 'T1059'
        });
      }

      // SQL Injection Detection
      if (packet.payloadInfo && 
          (packet.payloadInfo.toLowerCase().includes('select') || 
           packet.payloadInfo.toLowerCase().includes('insert') || 
           packet.payloadInfo.toLowerCase().includes('update') || 
           packet.payloadInfo.toLowerCase().includes('delete'))) {
        detectedIOAs.push({
          id: `${packet.timestamp}-${packet.sourceIp}-sql-inj-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: packet.timestamp,
          sourceIp: packet.sourceIp,
          destinationIp: packet.destinationIp,
          type: 'Potential SQL Injection',
          severity: 'critical',
          description: 'SQL injection attempt detected in payload',
          evidence: `SQL keywords found in payload: ${packet.payloadInfo.substring(0, 50)}...`,
          mitreTactic: 'Execution',
          mitreTechnique: 'Exploitation for Client Execution',
          mitreId: 'T1203'
        });
      }

      // XSS Attack Detection
      if (packet.payloadInfo && 
          (packet.payloadInfo.includes('<script>') || 
           packet.payloadInfo.includes('javascript:') || 
           packet.payloadInfo.includes('onerror='))) {
        detectedIOAs.push({
          id: `${packet.timestamp}-${packet.sourceIp}-xss-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: packet.timestamp,
          sourceIp: packet.sourceIp,
          destinationIp: packet.destinationIp,
          type: 'Potential XSS Attack',
          severity: 'high',
          description: 'XSS attack attempt detected in payload',
          evidence: `XSS patterns found in payload: ${packet.payloadInfo.substring(0, 50)}...`,
          mitreTactic: 'Initial Access',
          mitreTechnique: 'Exploit Public-Facing Application',
          mitreId: 'T1190'
        });
      }

      // Brute Force Detection
      if ((packet.destinationPort === 22 || packet.destinationPort === 3389) && 
          currentCount > 10) {
        const service = packet.destinationPort === 22 ? 'SSH' : 'RDP';
        detectedIOAs.push({
          id: `${packet.timestamp}-${packet.sourceIp}-${service.toLowerCase()}-brute-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: packet.timestamp,
          sourceIp: packet.sourceIp,
          destinationIp: packet.destinationIp,
          type: `Potential ${service} Brute Force`,
          severity: 'high',
          description: `Multiple ${service} connection attempts detected`,
          evidence: `Over 10 ${service} connection attempts from ${packet.sourceIp}`,
          mitreTactic: 'Credential Access',
          mitreTechnique: 'Brute Force',
          mitreId: 'T1110'
        });
      }

      // ARP Spoofing Detection
      if (packet.protocol === 'ARP' && packet.sourceIp !== packet.destinationIp) {
        detectedIOAs.push({
          id: `${packet.timestamp}-${packet.sourceIp}-arp-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: packet.timestamp,
          sourceIp: packet.sourceIp,
          destinationIp: packet.destinationIp,
          type: 'Potential ARP Spoofing',
          severity: 'high',
          description: 'Suspicious ARP traffic detected',
          evidence: `ARP packet from ${packet.sourceIp} to ${packet.destinationIp}`,
          mitreTactic: 'Lateral Movement',
          mitreTechnique: 'Exploitation of Remote Services',
          mitreId: 'T1210'
        });
      }

      // DNS Tunneling Detection
      if (packet.protocol === 'UDP' && 
          packet.destinationPort === 53 && 
          packet.packetLength > 1000) {
        detectedIOAs.push({
          id: `${packet.timestamp}-${packet.sourceIp}-dns-tunnel-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: packet.timestamp,
          sourceIp: packet.sourceIp,
          destinationIp: packet.destinationIp,
          type: 'Potential DNS Tunneling',
          severity: 'high',
          description: 'Large DNS query suggesting possible tunneling',
          evidence: `DNS query of size ${packet.packetLength} bytes`,
          mitreTactic: 'Command and Control',
          mitreTechnique: 'Application Layer Protocol',
          mitreId: 'T1071'
        });
      }

      // Unusual Level Communication Detection
      if (packet.sourceLevel === 'Level 0' && packet.destinationLevel === 'Level 4') {
        detectedIOAs.push({
          id: `${packet.timestamp}-${packet.sourceIp}-level-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: packet.timestamp,
          sourceIp: packet.sourceIp,
          destinationIp: packet.destinationIp,
          type: 'Unusual Level Communication',
          severity: 'high',
          description: 'Direct communication between Level 0 and Level 4 detected',
          evidence: `Direct communication from ${packet.sourceLevel} to ${packet.destinationLevel}`,
          mitreTactic: 'Lateral Movement',
          mitreTechnique: 'Exploitation of Remote Services',
          mitreId: 'T1210'
        });
      }
    });

    setIOAs(prev => [...detectedIOAs, ...prev].slice(0, 100)); // Keep last 100 IOAs
  }, []);



  // Add useEffect to detect IOAs when packets change
  useEffect(() => {
    if (packetInfos.length > 0) {
      detectIOAs(packetInfos);
    }
  }, [packetInfos, detectIOAs]);

  // Add useEffect to detect IOAs for live packets
  useEffect(() => {
    if (livePackets.length > 0) {
      detectIOAs(livePackets);
    }
  }, [livePackets, detectIOAs]);

  // Add useEffect to sync IOAs with localStorage
  useEffect(() => {
    localStorage.setItem('ioas', JSON.stringify(ioas));
    
    // Dispatch custom event to notify other components (like Alerts) that IOAs have been updated
    if (ioas.length > 0) {
      window.dispatchEvent(new CustomEvent('ioa-updated', { detail: { count: ioas.length } }));
    }
  }, [ioas]);

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const token = localStorage.getItem('token');
        if (!token) {
          navigate('/login');
          return;
        }

        const response = await api.get<User>('/api/users/me');
        setCurrentUser(response.data);
        setError(null);
      } catch (err) {
        console.error('Error fetching user data:', err);
        setError('Failed to load user data. Please try again.');
        navigate('/login');
      } finally {
        setLoading(false);
      }
    };

    fetchUserData();
  }, [navigate]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await api.post<LoginResponse>('/api/auth/login', {
        username,
        password,
      });
      const { token, user } = response.data;
      const userData: User = {
        ...user,
        fullName: user.fullName || user.username
      };
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(userData));
      setCurrentUser(userData);
      navigate('/dashboard');
    } catch (error: any) {
      setError(error.response?.data?.message || 'Login failed');
    }
  };

  // Filter packets for the PCAP analysis table (search + protocol dropdown)
  const analysisFilteredPackets = useMemo(() => {
    const q = analysisSearch.trim().toLowerCase();
    return safePacketInfos.filter(p => {
      if (analysisProtocolFilter && p.protocol !== analysisProtocolFilter) return false;
      if (!q) return true;
      return (
        (p.sourceIp || '').toLowerCase().includes(q) ||
        (p.destinationIp || '').toLowerCase().includes(q) ||
        (p.sourceManufacturer || '').toLowerCase().includes(q) ||
        (p.destinationManufacturer || '').toLowerCase().includes(q) ||
        (p.sourceModel || '').toLowerCase().includes(q) ||
        (p.destinationModel || '').toLowerCase().includes(q) ||
        (p.protocol || '').toLowerCase().includes(q) ||
        (p.payloadInfo || '').toLowerCase().includes(q)
      );
    });
  }, [safePacketInfos, analysisSearch, analysisProtocolFilter]);

  // Add pagination helpers (rename to avoid conflict)
  const uploadTotalPages = Math.max(Math.ceil(analysisFilteredPackets.length / rowsPerPage), 1);
  const uploadCurrentPackets = analysisFilteredPackets.slice(
    uploadPage * rowsPerPage,
    (uploadPage + 1) * rowsPerPage
  );

  // 1) Compute protocol distribution counts
  const protocolCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    safePacketInfos.forEach(p => {
      counts[p.protocol] = (counts[p.protocol] || 0) + 1;
    });
    return counts;
  }, [safePacketInfos]);

  /**
   * House palette for the dashboard charts. Four tones pulled from the
   * violet/fuchsia/pink/rose hero gradient, plus two high-contrast
   * accents (amber, emerald) so a pie slice for a minor protocol is
   * still readable. Grey is reserved for chart chrome (grid lines,
   * axis ticks) rather than data.
   */
  const chartPalette = {
    violet:   '#8B5CF6',
    fuchsia:  '#D946EF',
    pink:     '#EC4899',
    rose:     '#F43F5E',
    amber:    '#F59E0B',
    emerald:  '#10B981',
    slate200: '#E2E8F0',
    slate500: '#64748B',
    slate700: '#334155',
  } as const;

  /**
   * Tooltip + grid styling shared across the dashboard charts so
   * Chart.js defaults don't clash with the violet/fuchsia surface.
   * Kept as a plain object with a loose typing because Chart.js
   * option shapes vary per chart type.
   */
  const chartChrome = {
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#0F172A',
        titleColor: '#FFFFFF',
        bodyColor: '#E2E8F0',
        borderColor: chartPalette.violet,
        borderWidth: 1,
        cornerRadius: 8,
        padding: 10,
        titleFont: { weight: 'bold' as const, size: 12 },
        bodyFont: { size: 12 },
      },
    },
  };

  const protocolChartData = {
    labels: Object.keys(protocolCounts),
    datasets: [
      {
        data: Object.values(protocolCounts),
        backgroundColor: [
          chartPalette.violet,
          chartPalette.fuchsia,
          chartPalette.pink,
          chartPalette.rose,
          chartPalette.amber,
          chartPalette.emerald,
        ],
        borderColor: '#FFFFFF',
        borderWidth: 2,
        hoverOffset: 8,
      },
    ],
  };

  // 2) Compute top IP addresses (source+dest)
  const topIpData = useMemo(() => {
    const counts: Record<string, number> = {};
    safePacketInfos.forEach(p => {
      counts[p.sourceIp] = (counts[p.sourceIp] || 0) + 1;
      counts[p.destinationIp] = (counts[p.destinationIp] || 0) + 1;
    });
    const entries = Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
    return { labels: entries.map(e => e[0]), data: entries.map(e => e[1]) };
  }, [safePacketInfos]);

  const ipChartData = {
    labels: topIpData.labels,
    datasets: [
      {
        label: 'Packet Count',
        data: topIpData.data,
        backgroundColor: chartPalette.violet,
        hoverBackgroundColor: chartPalette.fuchsia,
        borderRadius: 6,
        borderSkipped: false as const,
        maxBarThickness: 18,
      },
    ],
  };

  // 3) Compute top port usage (source+dest)
  const topPortData = useMemo(() => {
    const counts: Record<number, number> = {};
    safePacketInfos.forEach(p => {
      counts[p.sourcePort] = (counts[p.sourcePort] || 0) + 1;
      counts[p.destinationPort] = (counts[p.destinationPort] || 0) + 1;
    });
    const entries = Object.entries(counts)
      .map(([port, cnt]) => [port, cnt] as [string, number])
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
    return { labels: entries.map(e => e[0]), data: entries.map(e => e[1]) };
  }, [safePacketInfos]);

  const portChartData = {
    labels: topPortData.labels,
    datasets: [
      {
        label: 'Packet Count',
        data: topPortData.data,
        backgroundColor: chartPalette.fuchsia,
        hoverBackgroundColor: chartPalette.pink,
        borderRadius: 6,
        borderSkipped: false as const,
        maxBarThickness: 18,
      },
    ],
  };

  // IOA'lardan MITRE ID'lerini çıkar
  const detectedMitreIds = useMemo(() => {
    return Array.from(new Set(ioas.map(ioa => ioa.mitreId).filter((id): id is string => !!id)));
  }, [ioas]);

  if (loading) {
    return (
      <div className="flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center">
        <div className="text-red-600">{error}</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHero
        eyebrow="NETWORK ANALYSIS"
        icon={<Icon.Network className="w-3.5 h-3.5" />}
        title="OT Network Dashboard"
        subtitle="Capture, analyze and investigate traffic across your industrial environment. Purdue-aware flow inspection, DPI drill-down and live IOA detection from one pane."
        stats={[
          { label: 'Captured packets', value: safePacketInfos.length.toLocaleString(), sub: `${kpiStats.protocolCount} protocol(s) seen` },
          { label: 'Live rate', value: `${liveRateStats.perSec}/s`, sub: isListening ? 'Capture active' : 'Capture idle' },
          { label: 'IOAs detected', value: ioas.length, sub: ioas.length > 0 ? `${ioas.filter(i => i.severity === 'critical' || i.severity === 'high').length} high severity` : 'All clear' },
        ]}
        actions={
          <button
            onClick={() => window.location.reload()}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-white bg-white/10 hover:bg-white/20 ring-1 ring-white/20 backdrop-blur-sm"
          >
            <Icon.Refresh className="w-4 h-4" /> Refresh
          </button>
        }
      />

      {/* --- KPI Şeridi --- */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          label="Total Packets"
          value={safePacketInfos.length.toLocaleString()}
          hint={totalPacketCount ? `of ${totalPacketCount.toLocaleString()} in PCAP` : 'from uploaded PCAP'}
          icon={<Icon.Activity />}
          color="violet"
        />
        <KpiCard
          label="Unique IPs"
          value={kpiStats.uniqueIpCount}
          hint={`${kpiStats.uniquePortCount} distinct ports`}
          icon={<Icon.Server />}
          color="fuchsia"
        />
        <KpiCard
          label="Purdue Crossings"
          value={kpiStats.purdueCrossings}
          hint={`${kpiStats.eastWestPct}% east-west · ${100 - kpiStats.eastWestPct}% N-S`}
          icon={<Icon.Layers />}
          color="rose"
          progress={kpiStats.eastWestPct}
        />
        <KpiCard
          label="Live Rate"
          value={`${liveRateStats.perSec}`}
          hint={<LiveRateSparkline values={liveRateStats.sparkline} active={isListening} />}
          icon={<Icon.Bolt />}
          color="pink"
        />
      </div>

      {/* --- 1) En Üst: PCAP Upload & Live Capture Panelleri --- */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Upload PCAP File Panel */}
        <Panel
          title="Upload PCAP File"
          subtitle="Drop a capture here to analyze protocols, IOAs, Purdue flows & MITRE coverage."
          icon={<Icon.Layers className="w-5 h-5" />}
        >
          <div
            {...getRootProps()}
            className="border-2 border-dashed border-violet-200 rounded-xl p-6 text-center hover:border-violet-400 hover:bg-violet-50/40 cursor-pointer transition-colors"
          >
            <input {...getInputProps()} />
            <div className="flex flex-col items-center gap-2">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white flex items-center justify-center">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 0115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
              </div>
              <p className="text-sm font-semibold text-slate-800">Drag &amp; drop PCAP, or click</p>
              <p className="text-xs text-slate-500">Max 500MB · .pcap / .pcapng</p>
            </div>
          </div>
          {selectedFileName && (
            <p className="mt-3 text-sm text-slate-700">
              <span className="font-semibold">Selected:</span> {selectedFileName}
            </p>
          )}
          {uploadStatus && (
            <div
              className={`mt-3 text-sm rounded-lg px-3 py-2 ring-1 ${
                uploadStatus.includes('error')
                  ? 'bg-rose-50 text-rose-700 ring-rose-200'
                  : 'bg-emerald-50 text-emerald-700 ring-emerald-200'
              }`}
            >
              {uploadStatus.includes('File is being uploaded and analyzed') ? (
                <div className="flex items-center space-x-2">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-violet-500"></div>
                  <span>{uploadStatus}</span>
                </div>
              ) : (
                uploadStatus
              )}
            </div>
          )}
        </Panel>

        {/* Live Network Capture Panel */}
        <div className="bg-white rounded-2xl shadow-sm ring-1 ring-slate-200/70 p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Live Network Capture</h2>
              <p className="text-xs text-slate-500 mt-0.5">Tap the OT network directly - IOA detection runs in real time.</p>
            </div>
            <span className={`inline-flex items-center gap-1.5 text-[10px] uppercase tracking-wider font-semibold px-2 py-1 rounded-full ring-1 ${
              isListening ? 'bg-emerald-50 text-emerald-700 ring-emerald-200' : 'bg-slate-100 text-slate-500 ring-slate-200'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${isListening ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}`} />
              {isListening ? 'Live' : 'Idle'}
            </span>
          </div>
          <div className="flex items-center justify-between mb-2">
            <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider">
              Network Interface
            </label>
            <button
              onClick={() => {
                setSelectedInterface('');
                setFetchInterfacesError('');
                setLiveStatusMessage('Refreshing interfaces...');
                // Re-fetch interfaces
                const fetchInterfaces = async () => {
                  try {
                    const response = await api.get<NetworkInterfaceInfo[]>('/pcap/interfaces');
                    const interfaces = response.data || [];
                    setNetworkInterfaces(interfaces);
                    setLiveStatusMessage('');
                    if (interfaces.length > 0) {
                      const defaultInterface = interfaces.find(iface =>
                        !iface.name.toLowerCase().includes('loopback') &&
                        !iface.description?.toLowerCase().includes('virtual')
                      ) || interfaces[0];
                      if (defaultInterface) {
                        setSelectedInterface(defaultInterface.name);
                      }
                    }
                  } catch (error: any) {
                    console.error("Error refreshing interfaces:", error);
                    setLiveStatusMessage('Failed to refresh interfaces');
                  }
                };
                fetchInterfaces();
              }}
              className="text-xs font-semibold text-violet-600 hover:text-violet-800"
              disabled={isListening}
            >
              Refresh
            </button>
          </div>
          <select
            value={selectedInterface}
            onChange={(e) => setSelectedInterface(e.target.value)}
            className="block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:ring-2 focus:ring-violet-500 focus:border-violet-500"
            disabled={isListening}
          >
            <option value="">Select interface</option>
            {networkInterfaces.map((iface) => (
              <option key={iface.name} value={iface.name}>
                {iface.name} ({iface.description})
              </option>
            ))}
          </select>
          {liveStatusMessage && (
            <div className="mt-2 text-xs text-slate-500">
              {liveStatusMessage}
            </div>
          )}
          {fetchInterfacesError && (
            <div className="mt-2 text-xs text-rose-600">
              {fetchInterfacesError}
            </div>
          )}
          <button
            onClick={toggleLiveCapture}
            className={`mt-4 w-full py-2.5 text-sm font-semibold text-white rounded-xl transition ${
              isListening
                ? 'bg-gradient-to-r from-rose-500 to-pink-600 hover:from-rose-600 hover:to-pink-700'
                : 'bg-gradient-to-r from-violet-600 to-fuchsia-600 hover:from-violet-700 hover:to-fuchsia-700'
            } disabled:opacity-40 disabled:cursor-not-allowed`}
            disabled={!selectedInterface}
          >
            {isListening ? '⏹ Stop Live Capture' : '▶ Start Live Capture'}
          </button>
        </div>
      </div>

      {/* --- 1a) KPI Grafları + Purdue Flow Ribbon --- */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <Panel
          title="Protocol Distribution"
          subtitle="Share of captured traffic per protocol"
          icon={<Icon.Activity className="w-5 h-5" />}
          className="lg:col-span-1"
        >
          <div className="h-40">
            {isUploading ? (
              <ChartLoading />
            ) : Object.keys(protocolCounts).length > 0 ? (
              <Pie
                data={protocolChartData}
                options={{
                  maintainAspectRatio: false,
                  // Donut-style cutout lifts the chart away from the
                  // solid-filled look the default Pie has; keeps the
                  // palette feeling airy next to the violet hero.
                  ...chartChrome,
                  plugins: {
                    ...chartChrome.plugins,
                    legend: {
                      display: true,
                      position: 'right' as const,
                      labels: {
                        boxWidth: 10,
                        boxHeight: 10,
                        font: { size: 11 },
                        color: chartPalette.slate700,
                      },
                    },
                  },
                }}
              />
            ) : (
              <ChartEmpty hint="Upload a PCAP to see protocol share" />
            )}
          </div>
        </Panel>
        <Panel
          title="Top Talker IPs"
          subtitle="Highest volume endpoints"
          icon={<Icon.Server className="w-5 h-5" />}
          className="lg:col-span-1"
        >
          <div className="h-40">
            {isUploading ? (
              <ChartLoading />
            ) : topIpData.labels.length > 0 ? (
              <Bar
                data={ipChartData}
                options={{
                  indexAxis: 'y' as const,
                  maintainAspectRatio: false,
                  ...chartChrome,
                  scales: {
                    x: {
                      ticks: { display: false },
                      grid: { color: chartPalette.slate200 },
                      border: { display: false },
                    },
                    y: {
                      ticks: {
                        autoSkip: false,
                        color: chartPalette.slate500,
                        font: { size: 11 },
                      },
                      grid: { display: false },
                      border: { display: false },
                    },
                  },
                }}
              />
            ) : (
              <ChartEmpty hint="Upload a PCAP to see top IPs" />
            )}
          </div>
        </Panel>
        <Panel
          title="Top Ports"
          subtitle="Services seen most often"
          icon={<Icon.Bolt className="w-5 h-5" />}
          className="lg:col-span-1"
        >
          <div className="h-40">
            {isUploading ? (
              <ChartLoading />
            ) : topPortData.labels.length > 0 ? (
              <Bar
                data={portChartData}
                options={{
                  indexAxis: 'y' as const,
                  maintainAspectRatio: false,
                  ...chartChrome,
                  scales: {
                    x: {
                      ticks: { display: false },
                      grid: { color: chartPalette.slate200 },
                      border: { display: false },
                    },
                    y: {
                      ticks: {
                        autoSkip: false,
                        color: chartPalette.slate500,
                        font: { size: 11 },
                      },
                      grid: { display: false },
                      border: { display: false },
                    },
                  },
                }}
              />
            ) : (
              <ChartEmpty hint="Upload a PCAP to see top ports" />
            )}
          </div>
        </Panel>
        <Panel
          title="Purdue Flow Mix"
          subtitle="East-West vs North-South traffic"
          icon={<Icon.Layers className="w-5 h-5" />}
          className="lg:col-span-1"
        >
          <PurdueFlowWidget stats={kpiStats} />
        </Panel>
      </div>

      {/* --- 2) Sekme Navigasyonu --- */}
      <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-2">
        <nav className="flex flex-wrap gap-1" aria-label="Tabs">
          {[
            { key: 'analysis', label: 'PCAP Analysis', badge: safePacketInfos.length },
            { key: 'live', label: 'Live Traffic', badge: livePackets.length },
            { key: 'ioa', label: 'Indicators of Attack', badge: ioas.length, danger: ioas.length > 0 },
            { key: 'mitre', label: 'MITRE ATT&CK', badge: detectedMitreIds.length },
            { key: 'dpi', label: 'DPI Activity' },
          ].map(tab => {
            const active = activeTab === tab.key;
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key as TabType)}
                className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold transition ${
                  active
                    ? 'bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white shadow-sm'
                    : 'text-slate-600 hover:bg-violet-50 hover:text-violet-700'
                }`}
              >
                {tab.label}
                {typeof tab.badge === 'number' && tab.badge > 0 && (
                  <span className={`inline-flex items-center justify-center min-w-[20px] h-[20px] px-1.5 rounded-full text-[10px] font-bold ${
                    active
                      ? 'bg-white/25 text-white'
                      : tab.danger
                        ? 'bg-rose-100 text-rose-700'
                        : 'bg-violet-100 text-violet-700'
                  }`}>
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* --- 3) Sekme İçeriği --- */}
      <div className="space-y-6">
        {/* a) PCAP Analysis: artık sadece harita + tablo */}
        {activeTab === 'analysis' && (
          <div className="space-y-4">
            {/* Network Topology, zone-aware embedded view.
                Replaces the old pcap-only Network Map. The full /topology
                page is still available via "Open full view →". */}
            <Panel
              title="Network Topology"
              subtitle="Purdue-aware view of captured endpoints and flows"
              icon={<Icon.Network className="w-5 h-5" />}
              actions={
                <button
                  onClick={() => navigate('/network-topology')}
                  className="text-xs font-semibold text-violet-600 hover:text-violet-800"
                >
                  Open full view →
                </button>
              }
            >
              <NetworkTopology embedded />
            </Panel>
            {/* PCAP Packet Table (Panel-wrapped, design-system aligned) */}
            <Panel
              title="PCAP Packets"
              subtitle={
                safePacketInfos.length
                  ? `${analysisFilteredPackets.length.toLocaleString()} of ${safePacketInfos.length.toLocaleString()} packet(s) • ${kpiStats.protocolCount} protocol${kpiStats.protocolCount === 1 ? '' : 's'} detected`
                  : 'Upload a capture to see parsed packets, devices and payloads.'
              }
              icon={<Icon.Activity className="w-5 h-5" />}
              actions={
                <div className="flex flex-wrap items-center gap-2">
                  {/* Search */}
                  <div className="relative">
                    <svg className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-5.2-5.2M10 18a8 8 0 100-16 8 8 0 000 16z" />
                    </svg>
                    <input
                      type="text"
                      placeholder="Search IP, vendor, protocol…"
                      value={analysisSearch}
                      onChange={(e) => { setAnalysisSearch(e.target.value); setUploadPage(0); }}
                      className="pl-7 pr-2 py-1.5 text-xs rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-400 focus:outline-none bg-white w-48"
                    />
                  </div>
                  {/* Protocol filter */}
                  <select
                    value={analysisProtocolFilter}
                    onChange={(e) => { setAnalysisProtocolFilter(e.target.value); setUploadPage(0); }}
                    className="px-2 py-1.5 text-xs rounded-lg ring-1 ring-slate-200 bg-white focus:ring-2 focus:ring-violet-400 focus:outline-none"
                  >
                    <option value="">All protocols</option>
                    {Object.keys(protocolCounts).sort().map(proto => (
                      <option key={proto} value={proto}>{proto} ({protocolCounts[proto]})</option>
                    ))}
                  </select>
                  {/* Rows per page */}
                  <div className="flex items-center gap-1.5 text-xs text-slate-600">
                    <span className="uppercase tracking-wider text-[10px] font-semibold text-slate-500">Show</span>
                    <select
                      value={rowsPerPage}
                      onChange={(e) => { setRowsPerPage(Number(e.target.value)); setUploadPage(0); }}
                      className="px-2 py-1.5 text-xs rounded-lg ring-1 ring-slate-200 bg-white focus:ring-2 focus:ring-violet-400 focus:outline-none"
                    >
                      {[10, 25, 50, 100].map((size) => (
                        <option key={size} value={size}>{size}</option>
                      ))}
                    </select>
                  </div>
                </div>
              }
            >
              <div className="overflow-x-auto max-h-[520px] overflow-y-auto rounded-xl ring-1 ring-slate-200/70">
                <table className="min-w-full text-sm">
                  <thead className="sticky top-0 z-10 bg-gradient-to-r from-violet-50 to-fuchsia-50">
                    <tr>
                      <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-wider text-violet-700">#</th>
                      <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-wider text-violet-700">Source</th>
                      <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-wider text-violet-700">Src Device</th>
                      <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-wider text-violet-700">Destination</th>
                      <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-wider text-violet-700">Dst Device</th>
                      <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-wider text-violet-700">Protocol</th>
                      <th className="px-3 py-2.5 text-right text-[10px] font-bold uppercase tracking-wider text-violet-700">Len</th>
                      <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-wider text-violet-700">Payload</th>
                      <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-wider text-violet-700">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-slate-100">
                    {uploadCurrentPackets.length === 0 ? (
                      <tr>
                        <td colSpan={9} className="px-3 py-10 text-center text-sm text-slate-500">
                          {safePacketInfos.length === 0
                            ? 'No packets to show yet. Upload a .pcap/.pcapng file above to get started.'
                            : 'No packets match the current filter.'}
                        </td>
                      </tr>
                    ) : (
                      uploadCurrentPackets.map((pkt, idx) => (
                        <tr key={idx} className="hover:bg-violet-50/40 transition-colors">
                          <td className="px-3 py-2 text-xs text-slate-500 font-mono">
                            {uploadPage * rowsPerPage + idx + 1}
                          </td>
                          <td className="px-3 py-2 text-xs text-slate-900 font-mono">
                            {pkt.sourceIp}
                          </td>
                          <td className="px-3 py-2">
                            <DeviceBadge manufacturer={pkt.sourceManufacturer} model={pkt.sourceModel} />
                          </td>
                          <td className="px-3 py-2 text-xs text-slate-900 font-mono">
                            {pkt.destinationIp}
                          </td>
                          <td className="px-3 py-2">
                            <DeviceBadge manufacturer={pkt.destinationManufacturer} model={pkt.destinationModel} />
                          </td>
                          <td className="px-3 py-2">
                            <ProtocolBadge protocol={pkt.protocol} />
                          </td>
                          <td className="px-3 py-2 text-xs text-slate-700 text-right font-mono">
                            {pkt.packetLength}
                          </td>
                          <td
                            className="px-3 py-2 text-xs text-slate-700 max-w-xs truncate"
                            title={pkt.payloadInfo || ''}
                          >
                            {pkt.payloadInfo ? (
                              <span className="font-mono text-[11px]">{pkt.payloadInfo}</span>
                            ) : (
                              <span className="text-slate-300">-</span>
                            )}
                          </td>
                          <td className="px-3 py-2 text-xs text-slate-600 font-mono whitespace-nowrap">
                            {pkt.timestamp}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              {/* Modern pagination bar */}
              <div className="flex items-center justify-between pt-3 mt-1 text-xs">
                <span className="text-slate-500">
                  {analysisFilteredPackets.length === 0
                    ? 'No results'
                    : <>Showing <span className="font-semibold text-slate-700">{uploadPage * rowsPerPage + 1}</span>–<span className="font-semibold text-slate-700">{Math.min((uploadPage + 1) * rowsPerPage, analysisFilteredPackets.length)}</span> of <span className="font-semibold text-slate-700">{analysisFilteredPackets.length.toLocaleString()}</span></>}
                </span>
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => setUploadPage(0)}
                    disabled={uploadPage === 0}
                    className="px-2 py-1 rounded-lg ring-1 ring-slate-200 text-slate-600 hover:bg-violet-50 hover:text-violet-700 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent"
                    title="First page"
                  >
                    «
                  </button>
                  <button
                    onClick={() => setUploadPage((p) => Math.max(p - 1, 0))}
                    disabled={uploadPage === 0}
                    className="px-2.5 py-1 rounded-lg ring-1 ring-slate-200 text-slate-600 hover:bg-violet-50 hover:text-violet-700 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent"
                  >
                    Prev
                  </button>
                  <span className="px-2.5 py-1 rounded-lg bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white font-semibold">
                    {uploadPage + 1} / {uploadTotalPages}
                  </span>
                  <button
                    onClick={() => setUploadPage((p) => Math.min(p + 1, uploadTotalPages - 1))}
                    disabled={uploadPage + 1 >= uploadTotalPages}
                    className="px-2.5 py-1 rounded-lg ring-1 ring-slate-200 text-slate-600 hover:bg-violet-50 hover:text-violet-700 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent"
                  >
                    Next
                  </button>
                  <button
                    onClick={() => setUploadPage(uploadTotalPages - 1)}
                    disabled={uploadPage + 1 >= uploadTotalPages}
                    className="px-2 py-1 rounded-lg ring-1 ring-slate-200 text-slate-600 hover:bg-violet-50 hover:text-violet-700 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent"
                    title="Last page"
                  >
                    »
                  </button>
                </div>
              </div>
            </Panel>
          </div>
        )}

        {/* b) Live Network Traffic */}
        {activeTab === 'live' && (
          <div className="space-y-4">
            {/* Live header strip: status + rate sparkline + quick controls */}
            <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-4 flex flex-wrap items-center gap-4">
              <div className="flex items-center gap-2">
                <span className={`inline-flex items-center gap-1.5 text-[10px] uppercase tracking-wider font-bold px-2.5 py-1 rounded-full ring-1 ${
                  isListening ? 'bg-emerald-50 text-emerald-700 ring-emerald-200' : 'bg-slate-100 text-slate-500 ring-slate-200'
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${isListening ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}`} />
                  {isListening ? 'Live capture' : 'Idle'}
                </span>
                <span className="text-xs text-slate-500">
                  {isListening
                    ? <>on <span className="font-mono text-slate-700">{selectedInterface || 'any'}</span></>
                    : 'start a capture from the panel above or select an interface'}
                </span>
              </div>
              <div className="h-5 w-px bg-slate-200" />
              <div className="flex items-center gap-2">
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Rate 60s</span>
                <LiveRateSparkline values={liveRateStats.sparkline} active={isListening} />
                <span className="text-[12px] font-bold text-violet-700">{liveRateStats.perSec}/s</span>
              </div>
              <div className="h-5 w-px bg-slate-200" />
              <div className="flex items-center gap-2">
                <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Packets</span>
                <span className="text-[12px] font-bold text-fuchsia-700">{livePackets.length.toLocaleString()}</span>
              </div>
              <div className="ml-auto flex items-center gap-2">
                <button
                  onClick={toggleLiveCapture}
                  disabled={!selectedInterface}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                    isListening
                      ? 'bg-rose-50 text-rose-700 ring-1 ring-rose-200 hover:bg-rose-100'
                      : 'bg-violet-600 text-white hover:bg-violet-700 shadow-sm'
                  } disabled:opacity-40 disabled:cursor-not-allowed`}
                >
                  {isListening ? '⏹ Stop' : '▶ Start'}
                </button>
              </div>
            </div>

            {/* Live Network Map */}
            <Panel
              title="Live Network Map"
              subtitle="Streaming topology of active endpoints and flows"
              icon={<Icon.Network className="w-5 h-5" />}
              actions={
                <div className="flex items-center gap-1">
                  {/* Zoom group */}
                  <div className="inline-flex items-center rounded-lg ring-1 ring-slate-200 bg-slate-50 overflow-hidden">
                    <button
                      onClick={() => handleNetworkZoom('in')}
                      className="p-1.5 text-slate-600 hover:text-violet-700 hover:bg-violet-50 transition"
                      title="Zoom In"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v6m3-3H7" />
                      </svg>
                    </button>
                    <button
                      onClick={() => handleNetworkZoom('out')}
                      className="p-1.5 text-slate-600 hover:text-violet-700 hover:bg-violet-50 border-l border-slate-200 transition"
                      title="Zoom Out"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 13H7v3m0-3h3" />
                      </svg>
                    </button>
                    <button
                      onClick={() => handleNetworkZoom('fit')}
                      className="p-1.5 text-slate-600 hover:text-violet-700 hover:bg-violet-50 border-l border-slate-200 transition"
                      title="Fit to Screen"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
                      </svg>
                    </button>
                  </div>
                  {/* Layout group */}
                  <div className="inline-flex items-center rounded-lg ring-1 ring-slate-200 bg-slate-50 overflow-hidden">
                    <button
                      onClick={() => handleNetworkLayout('hierarchical')}
                      className={`px-2.5 py-1 text-[11px] font-semibold transition ${
                        networkLayout === 'hierarchical'
                          ? 'bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white'
                          : 'text-slate-600 hover:text-violet-700 hover:bg-violet-50'
                      }`}
                      title="Hierarchical Layout"
                    >
                      Hierarchical
                    </button>
                    <button
                      onClick={() => handleNetworkLayout('force')}
                      className={`px-2.5 py-1 text-[11px] font-semibold border-l border-slate-200 transition ${
                        networkLayout === 'force'
                          ? 'bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white'
                          : 'text-slate-600 hover:text-violet-700 hover:bg-violet-50'
                      }`}
                      title="Force Layout"
                    >
                      Force
                    </button>
                  </div>
                  {/* Protocol filter */}
                  <select
                    value={networkFilter}
                    onChange={(e) => setNetworkFilter(e.target.value)}
                    className="px-2 py-1 text-[11px] font-medium rounded-lg border border-slate-200 bg-slate-50 text-slate-700 focus:ring-2 focus:ring-violet-500 focus:border-violet-500"
                    title="Filter by Protocol"
                  >
                    <option value="">All Protocols</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                    <option value="HTTP">HTTP</option>
                    <option value="HTTPS">HTTPS</option>
                    <option value="Modbus">Modbus</option>
                    <option value="DNP3">DNP3</option>
                  </select>
                  {/* View toggle */}
                  <div className="inline-flex items-center rounded-lg ring-1 ring-slate-200 bg-slate-50 overflow-hidden">
                    <button
                      onClick={() => toggleNetworkView('detailed')}
                      className={`p-1.5 transition ${
                        networkView === 'detailed'
                          ? 'bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white'
                          : 'text-slate-600 hover:text-violet-700 hover:bg-violet-50'
                      }`}
                      title="Detailed View"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                    </button>
                    <button
                      onClick={() => toggleNetworkView('compact')}
                      className={`p-1.5 border-l border-slate-200 transition ${
                        networkView === 'compact'
                          ? 'bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white'
                          : 'text-slate-600 hover:text-violet-700 hover:bg-violet-50'
                      }`}
                      title="Compact View"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
                      </svg>
                    </button>
                  </div>
                </div>
              }
            >
              {livePackets.length === 0 && !isListening ? (
                <div className="h-64 flex flex-col items-center justify-center text-center">
                  <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-violet-100 to-fuchsia-100 flex items-center justify-center mb-3">
                    <Icon.Network className="w-6 h-6" />
                  </div>
                  <p className="text-sm font-semibold text-slate-700">No live packets yet</p>
                  <p className="text-xs text-slate-500 mt-1">Start a capture to stream flows into the topology.</p>
                </div>
              ) : (
                <div
                  ref={liveNetworkContainer}
                  className="w-full h-72 rounded-xl ring-1 ring-slate-200/70 bg-slate-50/40"
                />
              )}
            </Panel>

            {/* Live Packet Table */}
            <Panel
              title="Live Packets"
              subtitle={`${livePackets.length.toLocaleString()} streamed · ${liveRateStats.perSec}/s over last 60s`}
              icon={<Icon.Activity className="w-5 h-5" />}
              actions={
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <svg className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    <input
                      type="text"
                      placeholder="Filter packets…"
                      value={liveFilterText}
                      onChange={(e) => setLiveFilterText(e.target.value)}
                      className="pl-8 pr-3 py-1.5 text-xs rounded-lg border border-slate-200 bg-slate-50 focus:ring-2 focus:ring-violet-500 focus:border-violet-500 w-44"
                    />
                  </div>
                  <select
                    value={liveRowsPerPage}
                    onChange={(e) => setLiveRowsPerPage(Number(e.target.value))}
                    className="rounded-lg border border-slate-200 bg-slate-50 px-2 py-1.5 text-xs font-medium text-slate-700 focus:ring-2 focus:ring-violet-500 focus:border-violet-500"
                  >
                    {[10, 25, 50, 100].map((size) => (
                      <option key={size} value={size}>{size}/page</option>
                    ))}
                  </select>
                </div>
              }
            >
              <div className="overflow-hidden rounded-xl ring-1 ring-slate-200/70">
                <div className="overflow-x-auto max-h-[calc(100vh-28rem)]">
                  <table className="min-w-full divide-y divide-slate-200">
                    <thead className="bg-violet-50 sticky top-0 z-10">
                      <tr>
                        <th className="px-3 py-2.5 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">#</th>
                        <th className="px-3 py-2.5 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Source</th>
                        <th className="px-3 py-2.5 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Source Device</th>
                        <th className="px-3 py-2.5 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Destination</th>
                        <th className="px-3 py-2.5 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Dest Device</th>
                        <th className="px-3 py-2.5 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Protocol</th>
                        <th className="px-3 py-2.5 text-right text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Len</th>
                        <th className="px-3 py-2.5 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Details</th>
                        <th className="px-3 py-2.5 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">When</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-slate-100">
                      {livePaginatedPackets.length === 0 && (
                        <tr>
                          <td colSpan={9} className="px-6 py-10 text-center text-sm text-slate-500">
                            {isListening ? 'Waiting for packets…' : 'No packets captured yet.'}
                          </td>
                        </tr>
                      )}
                      {livePaginatedPackets.map((pkt, idx) => (
                        <tr key={idx} className="hover:bg-violet-50/40 transition">
                          <td className="px-3 py-2 whitespace-nowrap text-[11px] text-slate-400 font-mono">
                            {(liveCurrentPage - 1) * liveRowsPerPage + idx + 1}
                          </td>
                          <td className="px-3 py-2 whitespace-nowrap text-[11.5px] font-mono text-slate-800">
                            {pkt.sourceIp}
                          </td>
                          <td className="px-3 py-2 whitespace-nowrap">
                            <DeviceBadge manufacturer={pkt.sourceManufacturer} model={pkt.sourceModel} />
                          </td>
                          <td className="px-3 py-2 whitespace-nowrap text-[11.5px] font-mono text-slate-800">
                            {pkt.destinationIp}
                          </td>
                          <td className="px-3 py-2 whitespace-nowrap">
                            <DeviceBadge manufacturer={pkt.destinationManufacturer} model={pkt.destinationModel} />
                          </td>
                          <td className="px-3 py-2 whitespace-nowrap">
                            <ProtocolBadge protocol={pkt.protocol} />
                          </td>
                          <td className="px-3 py-2 whitespace-nowrap text-right text-[11.5px] text-slate-700 font-mono">
                            {pkt.packetLength}
                          </td>
                          <td
                            className="px-3 py-2 text-[11px] text-slate-700 max-w-xs truncate"
                            title={pkt.payloadInfo || ''}
                          >
                            {pkt.payloadInfo ? (
                              <span className="font-mono">{pkt.payloadInfo}</span>
                            ) : (
                              <span className="text-slate-300">-</span>
                            )}
                          </td>
                          <td className="px-3 py-2 whitespace-nowrap text-[11px] text-slate-500">
                            {pkt.timestamp}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {/* Live Pagination Controls */}
                <div className="flex items-center justify-between py-2 px-3 bg-slate-50 border-t border-slate-200">
                  <button
                    onClick={() => setLiveCurrentPage((p) => Math.max(p - 1, 1))}
                    disabled={liveCurrentPage === 1}
                    className="px-3 py-1 text-xs font-semibold text-violet-700 rounded-lg bg-white ring-1 ring-violet-200 hover:bg-violet-50 disabled:opacity-40 disabled:cursor-not-allowed transition"
                  >
                    ← Previous
                  </button>
                  <span className="text-[11.5px] text-slate-600">
                    Page <span className="font-bold text-slate-900">{liveCurrentPage}</span> of{' '}
                    <span className="font-bold text-slate-900">{Math.max(1, liveTotalPages)}</span>
                  </span>
                  <button
                    onClick={() =>
                      setLiveCurrentPage((p) => Math.min(p + 1, liveTotalPages))
                    }
                    disabled={liveCurrentPage >= liveTotalPages}
                    className="px-3 py-1 text-xs font-semibold text-violet-700 rounded-lg bg-white ring-1 ring-violet-200 hover:bg-violet-50 disabled:opacity-40 disabled:cursor-not-allowed transition"
                  >
                    Next →
                  </button>
                </div>
              </div>
            </Panel>
          </div>
        )}

        {/* c) Indicators of Attack */}
        {activeTab === 'ioa' && (
          <div className="space-y-4">
            {/* Severity breakdown ribbon */}
            <IoaSeverityBreakdown ioas={ioas} />
            <Panel
              title="Indicators of Attack (IOA)"
              subtitle="Behavior-based detections mapped to MITRE ATT&CK"
              icon={<Icon.Alert className="w-5 h-5" />}
              actions={
                ioas.length > 0 ? (
                  <button
                    onClick={() => navigate('/mitre-matrix')}
                    className="text-xs font-semibold text-violet-600 hover:text-violet-800"
                  >
                    View in MITRE matrix →
                  </button>
                ) : null
              }
            >
              <div className="overflow-hidden rounded-xl ring-1 ring-slate-200/70">
                {ioas.length === 0 ? (
                  <div className="flex flex-col items-center justify-center p-12 text-center bg-gradient-to-br from-emerald-50 to-white">
                    <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-emerald-500 to-teal-500 flex items-center justify-center mb-3">
                      <ShieldCheckIcon className="h-7 w-7 text-white" />
                    </div>
                    <p className="font-semibold text-slate-800">No indicators of attack detected</p>
                    <p className="text-xs text-slate-500 mt-1">The analyzed traffic appears clean based on current patterns.</p>
                  </div>
                ) : (
                  <div className="overflow-x-auto max-h-[calc(100vh-24rem)]">
                    <table className="min-w-full divide-y divide-slate-200">
                      <thead className="bg-violet-50 sticky top-0 z-10">
                        <tr>
                          <th className="px-4 py-3 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Sev</th>
                          <th className="px-4 py-3 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Type</th>
                          <th className="px-4 py-3 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Description</th>
                          <th className="px-4 py-3 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">When</th>
                          <th className="px-4 py-3 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Source</th>
                          <th className="px-4 py-3 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Destination</th>
                          <th className="px-4 py-3 text-left text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">MITRE</th>
                          <th className="px-4 py-3 text-right text-[10.5px] font-bold text-violet-700 uppercase tracking-wider">Action</th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-slate-100">
                        {ioas.map((ioa) => (
                          <tr key={ioa.id} className="hover:bg-violet-50/40 transition">
                            <td className="px-4 py-3 whitespace-nowrap">
                              <span className={`px-2 py-0.5 inline-flex text-[11px] leading-5 font-bold rounded-full ring-1 ${
                                ioa.severity === 'critical' ? 'bg-rose-100 text-rose-700 ring-rose-200' :
                                ioa.severity === 'high' ? 'bg-orange-100 text-orange-700 ring-orange-200' :
                                ioa.severity === 'medium' ? 'bg-amber-100 text-amber-700 ring-amber-200' :
                                'bg-blue-100 text-blue-700 ring-blue-200'
                              }`}>
                                {ioa.severity.toUpperCase()}
                              </span>
                            </td>
                            <td className="px-4 py-3 whitespace-nowrap text-sm font-semibold text-slate-900">{ioa.type}</td>
                            <td className="px-4 py-3 text-sm text-slate-600 max-w-sm">{ioa.description}</td>
                            <td className="px-4 py-3 whitespace-nowrap text-xs text-slate-500">{new Date(ioa.timestamp).toLocaleString()}</td>
                            <td className="px-4 py-3 whitespace-nowrap text-xs font-mono text-slate-700">{ioa.sourceIp}</td>
                            <td className="px-4 py-3 whitespace-nowrap text-xs font-mono text-slate-700">{ioa.destinationIp}</td>
                            <td className="px-4 py-3 whitespace-nowrap text-xs">
                              {ioa.mitreTactic ? (
                                <div>
                                  <div className="text-slate-700 font-semibold">{ioa.mitreTactic}</div>
                                  <div className="text-slate-500 font-mono text-[10.5px]">{ioa.mitreId}</div>
                                </div>
                              ) : (
                                <span className="text-slate-400">-</span>
                              )}
                            </td>
                            <td className="px-4 py-3 whitespace-nowrap text-right">
                              <button
                                onClick={() => navigate(`/network-topology?ip=${encodeURIComponent(ioa.sourceIp)}`)}
                                className="text-[11px] font-semibold text-violet-600 hover:text-violet-800"
                              >
                                Investigate →
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </Panel>
          </div>
        )}

        {activeTab === 'mitre' && (
          <Panel
            title="MITRE ATT&CK for ICS"
            subtitle="Techniques observed in this capture highlighted across the kill chain"
            icon={<Icon.Target className="w-5 h-5" />}
            className="h-[calc(100vh-15rem)] overflow-y-auto"
          >
            <MitreMatrix highlightedTechniqueIds={detectedMitreIds} />
          </Panel>
        )}

        {activeTab === 'dpi' && (
          <Panel
            title="Deep Packet Inspection"
            subtitle="Function codes & payload-level anomalies across industrial protocols"
            icon={<Icon.Bolt className="w-5 h-5" />}
          >
            <DpiDashboardWidget />
          </Panel>
        )}
      </div>
    </div>
  );
};

// ---------- Dashboard helper sub-components ----------

const LiveRateSparkline: React.FC<{ values: number[]; active: boolean }> = ({ values, active }) => {
  const max = Math.max(1, ...values);
  const w = 100;
  const h = 18;
  const step = values.length > 1 ? w / (values.length - 1) : w;
  const pts = values.map((v, i) => {
    const x = i * step;
    const y = h - (v / max) * h;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return (
    <span className="inline-flex items-center gap-2 text-[10.5px] text-slate-500">
      <svg viewBox={`0 0 ${w} ${h}`} width={w} height={h} className="overflow-visible">
        <polyline
          fill="none"
          stroke={active ? '#a855f7' : '#cbd5e1'}
          strokeWidth={1.5}
          points={pts}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <span>{active ? 'live · 60s' : 'idle'}</span>
    </span>
  );
};

const PurdueFlowWidget: React.FC<{ stats: { eastWest: number; northSouth: number; eastWestPct: number; purdueCrossings: number; topProtocol: { name: string; count: number } | null } }> = ({ stats }) => {
  const total = stats.eastWest + stats.northSouth;
  if (total === 0) {
    return (
      <div className="h-40 flex flex-col items-center justify-center text-center">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-100 to-fuchsia-100 flex items-center justify-center mb-2">
          <Icon.Layers className="w-5 h-5" />
        </div>
        <p className="text-xs text-slate-500">Upload a PCAP to see Purdue-level flows</p>
      </div>
    );
  }
  return (
    <div className="h-40 flex flex-col justify-between">
      <div className="text-[11px] text-slate-500">Of {total.toLocaleString()} inspected flows</div>

      {/* EW/NS bar */}
      <div>
        <div className="flex items-center justify-between text-[11px] font-semibold mb-1">
          <span className="text-violet-700">East-West · L2↔L3 internal</span>
          <span className="text-rose-600">North-South · OT↔IT</span>
        </div>
        <div className="h-3 rounded-full overflow-hidden bg-slate-100 flex">
          <div
            className="bg-gradient-to-r from-violet-500 to-fuchsia-500"
            style={{ width: `${stats.eastWestPct}%` }}
            title={`${stats.eastWest.toLocaleString()} flows`}
          />
          <div
            className="bg-gradient-to-r from-rose-500 to-pink-500"
            style={{ width: `${100 - stats.eastWestPct}%` }}
            title={`${stats.northSouth.toLocaleString()} flows`}
          />
        </div>
        <div className="flex items-center justify-between text-[10.5px] text-slate-500 mt-1">
          <span>{stats.eastWest.toLocaleString()}</span>
          <span>{stats.northSouth.toLocaleString()}</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 text-center">
        <div className="rounded-lg bg-violet-50 ring-1 ring-violet-200 py-1.5">
          <div className="text-[10px] uppercase tracking-wider text-violet-700 font-semibold">Zone Crossings</div>
          <div className="text-base font-bold text-slate-900">{stats.purdueCrossings.toLocaleString()}</div>
        </div>
        <div className="rounded-lg bg-fuchsia-50 ring-1 ring-fuchsia-200 py-1.5">
          <div className="text-[10px] uppercase tracking-wider text-fuchsia-700 font-semibold">Top Proto</div>
          <div className="text-base font-bold text-slate-900 truncate">
            {stats.topProtocol ? stats.topProtocol.name : '-'}
          </div>
        </div>
      </div>
    </div>
  );
};

const ChartLoading: React.FC = () => (
  <div className="flex items-center justify-center h-full">
    <div className="text-center text-slate-400">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-violet-500 mx-auto mb-2" />
      <p className="text-xs">Processing data…</p>
    </div>
  </div>
);

const ChartEmpty: React.FC<{ hint: string }> = ({ hint }) => (
  <div className="flex items-center justify-center h-full">
    <div className="text-center text-slate-400">
      <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-100 to-fuchsia-100 flex items-center justify-center mx-auto mb-2">
        <svg className="w-5 h-5 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zm12-3c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2z" />
        </svg>
      </div>
      <p className="text-xs">{hint}</p>
    </div>
  </div>
);

const IoaSeverityBreakdown: React.FC<{ ioas: IOA[] }> = ({ ioas }) => {
  const buckets = useMemo(() => {
    const b = { critical: 0, high: 0, medium: 0, low: 0 };
    ioas.forEach(i => { if (i.severity in b) (b as any)[i.severity]++; });
    return b;
  }, [ioas]);
  const total = buckets.critical + buckets.high + buckets.medium + buckets.low;
  const items = [
    { key: 'critical', label: 'Critical', count: buckets.critical, className: 'from-rose-500 to-rose-600', text: 'text-rose-700', ring: 'ring-rose-200', bg: 'bg-rose-50' },
    { key: 'high', label: 'High', count: buckets.high, className: 'from-orange-500 to-orange-600', text: 'text-orange-700', ring: 'ring-orange-200', bg: 'bg-orange-50' },
    { key: 'medium', label: 'Medium', count: buckets.medium, className: 'from-amber-500 to-amber-600', text: 'text-amber-700', ring: 'ring-amber-200', bg: 'bg-amber-50' },
    { key: 'low', label: 'Low', count: buckets.low, className: 'from-blue-500 to-blue-600', text: 'text-blue-700', ring: 'ring-blue-200', bg: 'bg-blue-50' },
  ];
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {items.map(it => {
        const pct = total > 0 ? Math.round((it.count / total) * 100) : 0;
        return (
          <div key={it.key} className={`rounded-2xl p-4 ring-1 ${it.ring} ${it.bg}`}>
            <div className="flex items-center justify-between">
              <span className={`text-[10.5px] uppercase tracking-wider font-bold ${it.text}`}>{it.label}</span>
              <span className={`text-[10.5px] font-bold ${it.text}`}>{pct}%</span>
            </div>
            <div className="text-3xl font-bold text-slate-900 mt-1 leading-none">{it.count}</div>
            <div className="mt-2 h-1.5 rounded-full bg-white/70 overflow-hidden">
              <div className={`h-full bg-gradient-to-r ${it.className}`} style={{ width: `${pct}%` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
};

const DeviceBadge: React.FC<{ manufacturer?: string; model?: string }> = ({ manufacturer, model }) => {
  const tone = (v?: string) => {
    if (!v || v === 'Unknown') return 'bg-slate-100 text-slate-600 ring-slate-200';
    if (v.includes('Siemens') || v.includes('SIMATIC')) return 'bg-blue-50 text-blue-700 ring-blue-200';
    if (v.includes('Rockwell') || v.includes('ControlLogix') || v.includes('Allen-Bradley')) return 'bg-emerald-50 text-emerald-700 ring-emerald-200';
    if (v.includes('Schneider') || v.includes('Modicon')) return 'bg-violet-50 text-violet-700 ring-violet-200';
    if (v.includes('Cisco')) return 'bg-orange-50 text-orange-700 ring-orange-200';
    if (v.includes('IEC') || v.includes('ABB')) return 'bg-amber-50 text-amber-700 ring-amber-200';
    if (v.includes('GE') || v.includes('General Electric')) return 'bg-teal-50 text-teal-700 ring-teal-200';
    return 'bg-indigo-50 text-indigo-700 ring-indigo-200';
  };
  return (
    <div className="flex flex-col gap-0.5">
      <span
        className={`inline-flex w-fit px-1.5 py-0.5 text-[10.5px] font-semibold rounded ring-1 ${tone(manufacturer)}`}
        title={manufacturer || 'Unknown manufacturer'}
      >
        {manufacturer || 'Unknown'}
      </span>
      <span
        className={`inline-flex w-fit px-1.5 py-0.5 text-[10px] font-mono rounded ring-1 ${tone(model)}`}
        title={model || 'Unknown model'}
      >
        {model || '-'}
      </span>
    </div>
  );
};

const ProtocolBadge: React.FC<{ protocol: string }> = ({ protocol }) => {
  const p = (protocol || '').toUpperCase();
  const tone =
    p === 'MODBUS' || p === 'MODBUS/TCP' ? 'bg-amber-100 text-amber-800 ring-amber-200' :
    p === 'S7COMM' || p === 'S7' ? 'bg-violet-100 text-violet-800 ring-violet-200' :
    p === 'IEC104' || p === 'IEC-104' ? 'bg-cyan-100 text-cyan-800 ring-cyan-200' :
    p === 'DNP3' ? 'bg-fuchsia-100 text-fuchsia-800 ring-fuchsia-200' :
    p === 'OPCUA' || p === 'OPC-UA' ? 'bg-indigo-100 text-indigo-800 ring-indigo-200' :
    p === 'ETHERNETIP' || p === 'ENIP' ? 'bg-emerald-100 text-emerald-800 ring-emerald-200' :
    p === 'PROFINET' ? 'bg-blue-100 text-blue-800 ring-blue-200' :
    p === 'BACNET' ? 'bg-rose-100 text-rose-800 ring-rose-200' :
    p === 'TCP' ? 'bg-slate-100 text-slate-700 ring-slate-200' :
    p === 'UDP' ? 'bg-slate-100 text-slate-600 ring-slate-200' :
    p === 'HTTP' || p === 'HTTPS' ? 'bg-sky-100 text-sky-800 ring-sky-200' :
    'bg-slate-100 text-slate-700 ring-slate-200';
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 text-[10.5px] font-bold font-mono rounded ring-1 ${tone}`}>
      {protocol || '-'}
    </span>
  );
};

export default Dashboard;
