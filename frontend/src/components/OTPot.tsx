import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { Bar, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import { MapContainer, TileLayer, Marker, Popup, Polyline, useMap } from 'react-leaflet';
import PulsingMarker from './PulsingMarker';
import SensorDisplay from './SensorDisplay';

// Define honeypot event structure
interface HoneypotEvent {
  timestamp: string;
  sourceIp: string;
  protocol: string;
  eventType: 'Login Attempt' | 'Scan' | 'Read' | 'Write' | 'Request' | 'Command' | 'Exploit' | 'Data Exfiltration' | 'Configuration Change' | 'System Access' | 'Malware Detection' | 'Anomaly' | 'Brute Force' | 'SQL Injection' | 'XSS Attack' | 'DDoS Attack';
  details: string;
  targetPort?: number;
  usernameAttempt?: string;
  passwordAttempt?: string;
  modbusDetails?: { functionCode: number; address?: number; value?: number | number[]; count?: number };
  dnp3Details?: { functionCode: number; objectGroup?: number; pointIndex?: number };
  s7commDetails?: { pduType: string; functionCode: number; area?: string; dbNumber?: number; startAddress?: number; length?: number };
  bacnetDetails?: { serviceChoice: string; objectType?: string; objectInstance?: number; propertyIdentifier?: string; value?: any };
  httpDetails?: { method: 'GET' | 'POST' | 'PUT'; path: string; userAgent?: string; body?: string };
  snmpDetails?: { command: 'GET' | 'SET' | 'GETNEXT' | 'GETBULK'; oid: string; value?: string };
}

const protocols = ['MODBUS', 'DNP3', 'S7COMM', 'BACNET', 'HTTP', 'SNMP', 'SSH', 'TELNET', 'OPC UA'];
const modbusFunctions = [1, 2, 3, 4, 5, 6, 15, 16];
const dnp3Functions = [1, 2, 129, 130];
const s7Functions = [4, 5];
const s7PduTypes = ['Job', 'Ack_Data'];
const s7Areas = ['DB', 'MK', 'PE', 'PA', 'CT'];
const bacnetServices = ['ReadProperty', 'WriteProperty', 'WhoIs', 'IAm'];
const bacnetObjectTypes = ['analog-input', 'binary-output', 'device', 'file'];
const snmpCommands = ['GET', 'SET', 'GETNEXT', 'GETBULK'];
const commonOIDs = ['1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.5.0', '1.3.6.1.4.1.2021.4.6.0'];
const commonHttpPaths = ['/login', '/index.html', '/api/status', '/config', '/setup.php', '/Login.asp'];
const commonHttpUserAgents = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15',
  'Nmap Scripting Engine',
  'python-requests/2.28.1',
  'masscan/1.3.2',
  'ShodanBot',
];
const commonUsernames = ['root', 'admin', 'user', 'test', 'guest', 'cyberark'];
const commonPasswords = ['password', '123456', 'admin', 'root', '12345678', 'test'];
const baseEventTypes: HoneypotEvent['eventType'][] = ['Login Attempt', 'Scan', 'Read', 'Write', 'Request', 'Command'];

// Predefined list of public IPs for testing geolocation
const publicIPsForTesting = [
  '8.8.8.8',       // Google DNS (USA)
  '1.1.1.1',       // Cloudflare DNS (USA)
  '208.67.222.222',// OpenDNS (USA)
  '198.51.100.1',  // Example IP (Often documentation)
  '203.0.113.1',   // Example IP (Often documentation)
  '91.198.174.192',// Wikipedia (Netherlands)
  '172.217.160.142',// Google.com (USA)
  '104.18.32.7',   // Example CDN IP (Cloudflare)
  '142.250.184.174',// Google.com (USA)
  '35.241.6.203',  // Google Cloud (Belgium)
];

// Define destination coordinates (e.g., Ankara, Turkey)
const destinationCoords: L.LatLngTuple = [39.9334, 32.8597];

// Protocol color mapping
const protocolColors: Record<string, string> = {
  MODBUS: '#ff0000', // Red
  DNP3: '#00ff00', // Lime
  'OPC UA': '#0000ff', // Blue
  SSH: '#ffff00', // Yellow
  TELNET: '#ff00ff', // Magenta
  DEFAULT: '#00ffff', // Cyan
};

const getProtocolColor = (protocol: string): string => {
  return protocolColors[protocol] || protocolColors.DEFAULT;
};

// register once
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

const OTPot: React.FC = () => {
  const navigate = useNavigate();
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [active, setActive] = useState(false);
  const [events, setEvents] = useState<HoneypotEvent[]>([
    // Add some initial sample events to show the new event types
    {
      timestamp: new Date().toISOString(),
      sourceIp: '192.168.1.100',
      protocol: 'HTTP',
      eventType: 'Exploit',
      details: 'Exploit attempt detected: HTTP vulnerability exploitation',
      targetPort: 80
    },
    {
      timestamp: new Date().toISOString(),
      sourceIp: '10.0.0.50',
      protocol: 'MODBUS',
      eventType: 'Data Exfiltration',
      details: 'Data exfiltration attempt: MODBUS data extraction detected',
      targetPort: 502
    },
    {
      timestamp: new Date().toISOString(),
      sourceIp: '172.16.0.25',
      protocol: 'SSH',
      eventType: 'Brute Force',
      details: 'Brute force attack: SSH repeated authentication attempts',
      targetPort: 22
    },
    {
      timestamp: new Date().toISOString(),
      sourceIp: '203.0.113.10',
      protocol: 'HTTP',
      eventType: 'SQL Injection',
      details: 'SQL injection attempt: HTTP malicious SQL query detected',
      targetPort: 80
    },
    {
      timestamp: new Date().toISOString(),
      sourceIp: '198.51.100.75',
      protocol: 'HTTP',
      eventType: 'XSS Attack',
      details: 'XSS attack attempt: HTTP cross-site scripting detected',
      targetPort: 80
    },
    {
      timestamp: new Date().toISOString(),
      sourceIp: '192.0.2.30',
      protocol: 'DNP3',
      eventType: 'Configuration Change',
      details: 'Configuration change: DNP3 system settings modification',
      targetPort: 20000
    },
    {
      timestamp: new Date().toISOString(),
      sourceIp: '203.0.113.45',
      protocol: 'S7COMM',
      eventType: 'System Access',
      details: 'System access attempt: S7COMM unauthorized access',
      targetPort: 102
    },
    {
      timestamp: new Date().toISOString(),
      sourceIp: '198.51.100.90',
      protocol: 'BACNET',
      eventType: 'Malware Detection',
      details: 'Malware detected: BACNET suspicious code execution',
      targetPort: 47808
    },
    {
      timestamp: new Date().toISOString(),
      sourceIp: '192.0.2.15',
      protocol: 'SNMP',
      eventType: 'Anomaly',
      details: 'Anomaly detected: SNMP unusual behavior pattern',
      targetPort: 161
    },
    {
      timestamp: new Date().toISOString(),
      sourceIp: '203.0.113.60',
      protocol: 'HTTP',
      eventType: 'DDoS Attack',
      details: 'DDoS attack detected: HTTP flood attack',
      targetPort: 80
    }
  ]);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const [markers, setMarkers] = useState<{ ip: string; count: number; lat: number; lon: number; protocol: string }[]>([]);

  // Add event type descriptions
  const eventTypeDescriptions: Record<string, string> = {
    'Login Attempt': 'Authentication and user login attempts to the system',
    'Scan': 'Port scanning and service discovery attempts',
    'Read': 'Sensor data and system state reading operations',
    'Write': 'System configuration modification attempts',
    'Request': 'General API and service requests',
    'Command': 'System control and command execution attempts',
    'Exploit': 'Exploitation attempts using known vulnerabilities',
    'Data Exfiltration': 'Attempts to extract sensitive data from the system',
    'Configuration Change': 'Unauthorized system configuration modifications',
    'System Access': 'Unauthorized system access attempts',
    'Malware Detection': 'Malware or suspicious code execution attempts',
    'Anomaly': 'Unusual behavior patterns detected',
    'Brute Force': 'Repeated authentication attempts with different credentials',
    'SQL Injection': 'SQL injection attack attempts',
    'XSS Attack': 'Cross-site scripting attack attempts',
    'DDoS Attack': 'Distributed denial of service attack attempts'
  };

  // Add event type data with enhanced information
  const eventTypeData = useMemo(() => {
    const eventTypeCounts = events.reduce((acc, event) => {
      acc[event.eventType] = (acc[event.eventType] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const labels = Object.keys(eventTypeCounts);
    const data = Object.values(eventTypeCounts);
    const total = data.reduce((sum, val) => sum + val, 0);

    const backgroundColors = [
      'rgba(255, 99, 132, 0.8)',   // Red - Login Attempts
      'rgba(54, 162, 235, 0.8)',   // Blue - Scans
      'rgba(255, 206, 86, 0.8)',   // Yellow - Reads
      'rgba(75, 192, 192, 0.8)',   // Turquoise - Writes
      'rgba(153, 102, 255, 0.8)',  // Purple - Requests
      'rgba(255, 159, 64, 0.8)',   // Orange - Commands
      'rgba(255, 0, 0, 0.8)',      // Dark Red - Exploit
      'rgba(139, 0, 139, 0.8)',    // Dark Magenta - Data Exfiltration
      'rgba(0, 128, 128, 0.8)',    // Teal - Configuration Change
      'rgba(128, 0, 128, 0.8)',    // Purple - System Access
      'rgba(255, 20, 147, 0.8)',   // Deep Pink - Malware Detection
      'rgba(255, 165, 0, 0.8)',    // Orange - Anomaly
      'rgba(220, 20, 60, 0.8)',    // Crimson - Brute Force
      'rgba(0, 255, 127, 0.8)',    // Spring Green - SQL Injection
      'rgba(255, 69, 0, 0.8)',     // Red Orange - XSS Attack
      'rgba(128, 0, 0, 0.8)',      // Maroon - DDoS Attack
    ];

    return {
      labels: labels.map(label => `${label} (${((eventTypeCounts[label] / total) * 100).toFixed(1)}%)`),
      datasets: [
        {
          data,
          backgroundColor: backgroundColors.slice(0, labels.length),
          borderWidth: 1,
          borderColor: backgroundColors.map(color => color.replace('0.8', '1')),
        },
      ],
    };
  }, [events]);

  // Enhanced chart options
  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right' as const,
        labels: {
          font: {
            size: 12
          },
          padding: 20
        }
      },
      title: {
        display: true,
        text: 'Event Type Distribution',
        font: {
          size: 16,
          weight: 'bold' as const
        }
      },
      tooltip: {
        callbacks: {
          label: (context: any) => {
            const label = context.label || '';
            const value = context.raw || 0;
            const baseEventType = label.split(' (')[0];
            const description = eventTypeDescriptions[baseEventType] || '';
            return [
              `Count: ${value}`,
              `Description: ${description}`
            ];
          }
        }
      }
    }
  };

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

  // Generate random SCADA/ICS event with more Conpot-like details
  const generateRandomEvent = (): HoneypotEvent => {
    const protocol = protocols[Math.floor(Math.random() * protocols.length)];
    const src = publicIPsForTesting[Math.floor(Math.random() * publicIPsForTesting.length)];
    const timestamp = new Date().toISOString();
    
    // Base event object, will be populated further
    let baseEvent: Partial<HoneypotEvent> = { timestamp, sourceIp: src, protocol }; 
    let specificDetails: any = {};
    let eventType: HoneypotEvent['eventType'] = 'Request'; // Default
    let details = '';
    let targetPort: number | undefined = undefined;
    let usernameAttempt: string | undefined = undefined;
    let passwordAttempt: string | undefined = undefined;

    switch (protocol) {
      case 'MODBUS':
        targetPort = 502;
        const mbFunc = modbusFunctions[Math.floor(Math.random() * modbusFunctions.length)];
        const mbAddr = 40001 + Math.floor(Math.random() * 100);
        const mbCount = 1 + Math.floor(Math.random() * 10);
        specificDetails = { functionCode: mbFunc, address: mbAddr, count: mbCount };
        if ([1, 2, 3, 4].includes(mbFunc)) { // Read functions
          eventType = 'Read';
          details = `MODBUS FC${mbFunc} Read ${mbFunc <= 2 ? 'Coils/Inputs' : 'Registers'} Addr=${mbAddr} Count=${mbCount}`;
        } else if ([5, 6, 15, 16].includes(mbFunc)) { // Write functions
          eventType = 'Write';
          specificDetails.value = mbFunc === 5 || mbFunc === 15 ? (Math.random() > 0.5 ? 1 : 0) : Math.floor(Math.random() * 1000);
          details = `MODBUS FC${mbFunc} Write ${mbFunc <= 6 ? 'Single' : 'Multiple'} ${mbFunc === 5 || mbFunc === 15 ? 'Coil' : 'Register'} Addr=${mbAddr} Value=${specificDetails.value}`;
        }
        break;

      case 'DNP3':
        targetPort = 20000;
        const dnp3Func = dnp3Functions[Math.floor(Math.random() * dnp3Functions.length)];
        specificDetails = { functionCode: dnp3Func, objectGroup: 60, pointIndex: Math.floor(Math.random() * 5) }; // Example group/index
        eventType = [1, 2].includes(dnp3Func) ? 'Read' : 'Write';
        details = `DNP3 FC${dnp3Func} ${eventType === 'Read' ? 'Read Data' : 'Direct Operate'} Group=${specificDetails.objectGroup} Index=${specificDetails.pointIndex}`;
        break;

      case 'S7COMM':
        targetPort = 102;
        const s7Pdu = s7PduTypes[Math.floor(Math.random() * s7PduTypes.length)];
        const s7Func = s7Functions[Math.floor(Math.random() * s7Functions.length)];
        const s7Area = s7Areas[Math.floor(Math.random() * s7Areas.length)];
        specificDetails = { pduType: s7Pdu, functionCode: s7Func, area: s7Area, dbNumber: s7Area === 'DB' ? (1 + Math.floor(Math.random() * 10)) : undefined, startAddress: Math.floor(Math.random() * 100), length: 4 + Math.floor(Math.random() * 12) }; 
        eventType = s7Func === 4 ? 'Read' : 'Write';
        details = `S7COMM PDU=${s7Pdu} Func=${eventType} Area=${s7Area} ${specificDetails.dbNumber ? 'DB='+specificDetails.dbNumber : ''} Addr=${specificDetails.startAddress} Len=${specificDetails.length}`;
        break;

      case 'BACNET':
        targetPort = 47808;
        const bacSvc = bacnetServices[Math.floor(Math.random() * bacnetServices.length)];
        const bacObj = bacnetObjectTypes[Math.floor(Math.random() * bacnetObjectTypes.length)];
        const bacInst = 1 + Math.floor(Math.random() * 5);
        specificDetails = { serviceChoice: bacSvc, objectType: bacObj, objectInstance: bacInst, propertyIdentifier: 'present-value' };
        eventType = bacSvc.startsWith('Read') || bacSvc.startsWith('Who') ? 'Read' : 'Write';
        if (bacSvc === 'WriteProperty') specificDetails.value = Math.random().toFixed(2);
        details = `BACNET ${bacSvc} ${bacObj}-${bacInst} property=${specificDetails.propertyIdentifier}` + (specificDetails.value ? ` Value=${specificDetails.value}` : '');
        break;

      case 'HTTP':
        targetPort = 80;
        const httpMethod = Math.random() > 0.7 ? 'POST' : 'GET';
        const httpPath = commonHttpPaths[Math.floor(Math.random() * commonHttpPaths.length)];
        const httpUA = commonHttpUserAgents[Math.floor(Math.random() * commonHttpUserAgents.length)];
        specificDetails = { method: httpMethod, path: httpPath, userAgent: httpUA };
        eventType = 'Request';
        if (httpMethod === 'POST' && httpPath.includes('login')) {
          const user = commonUsernames[Math.floor(Math.random() * commonUsernames.length)];
          const pass = commonPasswords[Math.floor(Math.random() * commonPasswords.length)];
          specificDetails.body = `user=${user}&pass=${pass}`;
          eventType = 'Login Attempt';
          details = `HTTP ${httpMethod} Login Attempt Path=${httpPath} User=${user}`;
        } else {
          details = `HTTP ${httpMethod} Path=${httpPath} UA=${httpUA}`;
        }
        break;

      case 'SNMP':
        targetPort = 161;
        const snmpCmd = snmpCommands[Math.floor(Math.random() * snmpCommands.length)];
        const snmpOid = commonOIDs[Math.floor(Math.random() * commonOIDs.length)];
        specificDetails = { command: snmpCmd, oid: snmpOid };
        eventType = snmpCmd === 'SET' ? 'Write' : 'Read';
        if (snmpCmd === 'SET') specificDetails.value = 'TestValue';
        details = `SNMP ${snmpCmd} OID=${snmpOid}` + (specificDetails.value ? ` Value=${specificDetails.value}` : '');
        break;

      case 'SSH':
      case 'TELNET':
        targetPort = protocol === 'SSH' ? 22 : 23;
        eventType = 'Login Attempt';
        const sshUser = commonUsernames[Math.floor(Math.random() * commonUsernames.length)];
        const sshPass = commonPasswords[Math.floor(Math.random() * commonPasswords.length)];
        usernameAttempt = sshUser; // Assign to local var
        passwordAttempt = sshPass; // Assign to local var
        details = `${protocol} Login Attempt: user=${sshUser} pass=${sshPass}`;
        break;

      case 'OPC UA':
        targetPort = 4840;
        eventType = 'Request';
        details = `OPC UA Connection Request`; // Keep simple for now
        break;

      default:
        // Fallback for unhandled protocols or add generic scan/command
        if (Math.random() > 0.5) {
            eventType = 'Scan';
            targetPort = 1 + Math.floor(Math.random() * 10000);
            details = `${protocol} Port Scan Detected on port ${targetPort}`;
        } else {
            eventType = 'Command';
            details = `${protocol} Unknown Command/Request`;
        }
        break;
    }

    // Ensure all base properties are defined before adding specifics
    const constructedEvent: Partial<HoneypotEvent> = {
      ...baseEvent,
      eventType,
      details,
      targetPort,
      usernameAttempt,
      passwordAttempt,
    };

    // Add specific details safely
    if (protocol === 'MODBUS') constructedEvent.modbusDetails = specificDetails;
    else if (protocol === 'DNP3') constructedEvent.dnp3Details = specificDetails;
    else if (protocol === 'S7COMM') constructedEvent.s7commDetails = specificDetails;
    else if (protocol === 'BACNET') constructedEvent.bacnetDetails = specificDetails;
    else if (protocol === 'HTTP') constructedEvent.httpDetails = specificDetails;
    else if (protocol === 'SNMP') constructedEvent.snmpDetails = specificDetails;

    // Perform validation and type assertion *after* full construction
    const finalEvent = constructedEvent as HoneypotEvent;

    // Validation
    if (!finalEvent.timestamp || !finalEvent.sourceIp || !finalEvent.protocol || !finalEvent.eventType || !finalEvent.details) {
      console.error("Generated incomplete event:", finalEvent);
      return generateRandomEvent(); // Retry
    }

    return finalEvent; // Return validated, fully typed event
  };

  // Start honeypot event generation
  const startHoneypot = () => {
    if (!active) {
      setActive(true);
      intervalRef.current = setInterval(() => setEvents(prev => [generateRandomEvent(), ...prev].slice(0, 500)), 1500);
    }
  };

  // Stop honeypot
  const stopHoneypot = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
      setActive(false);
    }
  };

  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  // Inject CSS for custom pulsing icons
  useEffect(() => {
    const styleEl = document.createElement('style');
    styleEl.innerHTML = `
      /* Ensure marker containers can show overflow for pulsing */
      .leaflet-marker-icon, .leaflet-marker-pane {
        position: relative !important;
        overflow: visible !important;
      }
      .custom-pulse-icon {
        position: relative;
        width: 0;
        height: 0;
        overflow: visible !important;
      }
      .pulsing-dot {
        position: absolute;
        transform: translate(-50%, -50%); /* Center the dot */
        width: 8px;
        height: 8px;
        background-color: red;
        border-radius: 50%;
        box-shadow: 0 0 3px 1px rgba(255, 0, 0, 0.7);
        z-index: 2; /* Ensure dot is above ring */
      }
      .pulsing-ring {
        position: absolute;
        transform: translate(-50%, -50%); /* Center the ring */
        width: 8px; /* Start same size as dot */
        height: 8px;
        border: 2px solid red;
        border-radius: 50%;
        animation: pulsate 1.2s ease-out infinite !important;
        opacity: 0;
        box-sizing: border-box; /* Include border in size */
        z-index: 1; /* Ring behind dot */
      }
      @keyframes pulsate {
        0% {
          width: 8px;
          height: 8px;
          opacity: 0.8;
        }
        50% {
          opacity: 0.5;
        }
        100% {
          width: 30px; /* Expand size */
          height: 30px;
          opacity: 0; /* Fade out */
        }
      }
      .destination-marker {
        /* Add any specific styles if needed, e.g., background */
      }
    `;
    document.head.appendChild(styleEl);
    return () => { document.head.removeChild(styleEl); };
  }, []);

  // Log markers state for debugging
  console.log('Current markers:', markers);

  // Calculate data for charts and tables
  const gaugeData = useMemo(() => {
    const counts = events.reduce((acc, evt) => { acc[evt.protocol] = (acc[evt.protocol] || 0) + 1; return acc; }, {} as Record<string, number>);
    const topProtocols = Object.entries(counts).sort(([, a], [, b]) => b - a).slice(0, 5).map(([label, value]) => ({ label, value }));
    while (topProtocols.length < 5) topProtocols.push({ label: `Proto ${topProtocols.length + 1}`, value: 0 });
    return topProtocols;
  }, [events]);

  const barChartData = useMemo(() => {
    const lastHour = Array.from({ length: 12 }, (_, i) => new Date(Date.now() - (11 - i) * 5 * 60000));
    const labels = lastHour.map(d => d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }));
    const data = lastHour.map((start, i) => {
      const end = i === 11 ? new Date() : lastHour[i + 1];
      return events.filter(evt => new Date(evt.timestamp) >= start && new Date(evt.timestamp) < end).length;
    });
    return { labels, datasets: [{ label: 'Events per 5 min', data, backgroundColor: '#4ade80' }] };
  }, [events]);

  const topSourceIPsWithProtocol = useMemo(() => {
    const ipData = events.reduce((acc, evt) => {
      if (!acc[evt.sourceIp]) {
        acc[evt.sourceIp] = { count: 0, protocol: evt.protocol };
      }
      acc[evt.sourceIp].count += 1;
      return acc;
    }, {} as Record<string, { count: number; protocol: string }>);
    return Object.entries(ipData)
      .sort(([, a], [, b]) => b.count - a.count)
      .slice(0, 10)
      .map(([ip, data]) => ({ ip, ...data }));
  }, [events]);

  const topEvents = useMemo(() => Object.entries(events.reduce((acc, evt) => { acc[evt.details] = (acc[evt.details] || 0) + 1; return acc; }, {} as Record<string, number>)).sort(([, a], [, b]) => b - a).slice(0, 10), [events]);

  useEffect(() => {
    const isPrivateIP = (ip: string): boolean => {
      const parts = ip.split('.').map(Number);
      if (parts[0] === 10) return true;
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
      if (parts[0] === 192 && parts[1] === 168) return true;
      return false;
    };

    Promise.all(
      topSourceIPsWithProtocol
        .filter(({ ip }) => !isPrivateIP(ip))
        .map(({ ip, count, protocol }) =>
          fetch(`http://ip-api.com/json/${ip}`)
            .then(res => res.json())
            .then((data: any) => {
              if (data.lat != null && data.lon != null) {
                return { ip, count, protocol, lat: data.lat, lon: data.lon };
              } else {
                return null;
              }
            })
            .catch(() => null)
        )
    ).then(results => setMarkers(results.filter((m): m is any => m !== null)));
  }, [topSourceIPsWithProtocol]);

  // --- OWASP Top 10 mapping & stats ---
  const OWASP_CATEGORIES = [
    { label: 'Broken Access Control',        filter: (ev: HoneypotEvent) => ev.eventType === 'Write' },
    { label: 'Sensitive Data Exposure',      filter: (ev: HoneypotEvent) => ev.eventType === 'Read' },
    { label: 'Injection',                    filter: (ev: HoneypotEvent) => ev.protocol === 'SNMP' && ev.snmpDetails?.command === 'SET' },
    { label: 'Security Misconfiguration',    filter: (ev: HoneypotEvent) => ev.eventType === 'Scan' },
    { label: 'Broken Authentication',        filter: (ev: HoneypotEvent) => ev.eventType === 'Login Attempt' },
    // placeholders for the other OWASP‐10 categories
    { label: 'Insecure Design',              filter: () => false },
    { label: 'Vulnerable Components',        filter: () => false },
    { label: 'Integrity Failures',           filter: () => false },
    { label: 'Logging/Monitoring Failures',  filter: () => false },
    { label: 'SSRF',                         filter: () => false },
  ];

  const owaspStats = useMemo(() => {
    const labels = OWASP_CATEGORIES.map(c => c.label);
    const data = OWASP_CATEGORIES.map(c => events.filter(c.filter).length);
    return {
      labels,
      datasets: [{
        label: 'Event Count',
        data,
        backgroundColor: [
          '#4dc9f6', '#f67019', '#f53794', '#537bc4', '#acc236',
          '#166a8f', '#00a950', '#58595b', '#8549ba', '#b620e0'
        ]
      }]
    };
  }, [events]);

  const owaspOptions = {
    responsive: true,
    plugins: {
      legend: { position: 'bottom' as const },
      title: { display: true, text: 'OWASP Top 10 Event Distribution' }
    }
  };

  return (
    <div className="space-y-6 pt-16">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="mb-4 flex justify-between items-center">
          <h1 className="text-2xl font-bold">OTPot - Industrial Control System Honeypot</h1>
          <button
            onClick={() => setActive(!active)}
            className={`px-4 py-2 rounded-lg font-semibold ${
              active
                ? 'bg-red-500 hover:bg-red-600 text-white'
                : 'bg-green-500 hover:bg-green-600 text-white'
            }`}
          >
            {active ? 'Stop OTPot' : 'Start OTPot'}
          </button>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
          <div className="col-span-1">
            <SensorDisplay />
          </div>
          <div className="col-span-1">
            <div className="bg-white p-4 rounded-lg shadow-md h-full flex flex-col">
              <div className="flex items-center justify-between mb-2">
                <h2 className="text-lg font-semibold">Event Type Distribution</h2>
                <div className="text-sm text-gray-500 bg-gray-100 px-2 py-1 rounded">
                  Total Events: {events.length}
                </div>
              </div>
              <div className="flex-grow" style={{ minHeight: '250px', maxHeight: '300px' }}>
                <Doughnut 
                  data={eventTypeData} 
                  options={{
                    ...chartOptions,
                    maintainAspectRatio: false,
                    layout: {
                      padding: {
                        left: 10,
                        right: 10,
                        top: 10,
                        bottom: 10
                      }
                    }
                  }} 
                />
              </div>
              <div className="mt-2 text-sm text-gray-600 bg-gray-50 p-2 rounded">
                <p className="font-medium mb-1">Event Types:</p>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-[rgb(255,99,132)] mr-2"></div>
                    <span>Login Attempt</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-[rgb(54,162,235)] mr-2"></div>
                    <span>Scan</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-[rgb(255,206,86)] mr-2"></div>
                    <span>Read</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-[rgb(75,192,192)] mr-2"></div>
                    <span>Write</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-[rgb(153,102,255)] mr-2"></div>
                    <span>Request</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-[rgb(255,159,64)] mr-2"></div>
                    <span>Command</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Top Row: Gauges + Bar Chart */}
          <div className="col-span-1 md:col-span-2 grid grid-cols-2 md:grid-cols-6 gap-6 bg-gray-100 p-4 rounded-lg shadow">
            {/* Gauges */}
            {gaugeData.map((item, idx) => (
              <div key={idx} className="text-center">
                <div className="h-24 w-24 mx-auto mb-1">
                  <Doughnut
                    data={{
                      labels: [item.label, 'Remaining'],
                      datasets: [{
                        data: [item.value, (events.length || 1) - item.value], // Value vs Max (Total Events)
                        backgroundColor: ['#4ade80', '#374151'], // Green vs Dark Gray
                        circumference: 180,
                        rotation: -90,
                        borderWidth: 0,
                      }]
                    }}
                    options={{ cutout: '70%', plugins: { legend: { display: false }, tooltip: { enabled: false } }, maintainAspectRatio: false }}
                  />
                </div>
                <p className="text-sm font-medium text-gray-300">{item.label}</p>
                <p className="text-xs text-gray-400">{item.value}</p>
              </div>
            ))}
            {/* Bar Chart */}
            <div className="col-span-2 md:col-span-1 bg-gray-100 p-4 rounded-lg h-40">
              <Bar data={barChartData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#9ca3af' } }, y: { beginAtZero: true, ticks: { color: '#9ca3af' } } } }} />
            </div>
          </div>

          {/* Mid Row: Placeholder for Word Clouds */}
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Top Usernames (Placeholder)</h3>
            {/* Placeholder: List top usernames */}
            <ul>
              {events.filter(e => e.usernameAttempt).slice(0, 5).map((e, i) => <li key={i} className="text-sm">{e.usernameAttempt}</li>)}
            </ul>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Top Passwords (Placeholder)</h3>
            {/* Placeholder: List top passwords */}
            <ul>
              {events.filter(e => e.passwordAttempt).slice(0, 5).map((e, i) => <li key={i} className="text-sm">{e.passwordAttempt}</li>)}
            </ul>
          </div>

          {/* Bottom Row: Tables */}
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow overflow-hidden">
            <h3 className="text-lg font-semibold mb-2">Top Source IPs</h3>
            <div className="overflow-y-auto max-h-48">
              <table className="min-w-full">
                <tbody>
                  {topSourceIPsWithProtocol.map(({ ip, count }) => (
                    <tr key={ip} className="border-b border-gray-700">
                      <td className="py-1 px-2 text-sm">{ip}</td>
                      <td className="py-1 px-2 text-sm text-right">{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow overflow-hidden">
            <h3 className="text-lg font-semibold mb-2">Top Events</h3>
            <div className="overflow-y-auto max-h-48">
              <table className="min-w-full">
                <tbody>
                  {topEvents.map(([details, count]) => (
                    <tr key={details} className="border-b border-gray-700">
                      <td className="py-1 px-2 text-sm">{details}</td>
                      <td className="py-1 px-2 text-sm text-right">{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
        <div className="mt-6">
          <h3 className="text-lg font-semibold mb-2">Attack Simulation Map</h3>
          <MapContainer center={[20, 0]} zoom={2} style={{ height: '400px', width: '100%' }}>
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            />
            {/* Destination Marker */}
            <Marker position={destinationCoords} icon={L.divIcon({ className: 'destination-marker', html: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-6 h-6 text-blue-500"><path fill-rule="evenodd" d="M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25Zm-.53 14.03a.75.75 0 0 0 1.414 0l3-3a.75.75 0 1 0-1.414-1.414l-1.72 1.72V8.25a.75.75 0 0 0-1.5 0v5.69l-1.72-1.72a.75.75 0 0 0-1.06 1.06l3 3Z" clip-rule="evenodd" /></svg>', iconSize: [24, 24], iconAnchor: [12, 12] })}> 
              <Popup>OTPot Location</Popup>
            </Marker>

            {markers.map(m => {
              return (
                <React.Fragment key={m.ip}>
                  {/* Use the custom component for pulsing markers */}
                  <PulsingMarker 
                    position={[m.lat, m.lon]}
                    ip={m.ip}
                    count={m.count}
                    protocol={m.protocol}
                  />
                  {/* Connection Line */}
                  <Polyline 
                    positions={[[m.lat, m.lon], destinationCoords]}
                    pathOptions={{ color: getProtocolColor(m.protocol), weight: 1.5, opacity: 0.7 }}
                  />
                </React.Fragment>
              );
            })}
          </MapContainer>
        </div>

        {/* OWASP Top 10 chart */}
        <section style={{ marginTop: 40 }}>
          <h2>OWASP Top 10 Statistics</h2>
          <Bar data={owaspStats} options={owaspOptions} />
        </section>
      </div>
    </div>
  );
};

export default OTPot; 