import React, { useEffect, useState } from 'react';
import api from '../services/api';
import { User } from '../types/user';
import { PageHero, Panel, Icon, pageContainer, pageItem } from './theme';
import { motion } from 'framer-motion';

interface Detection {
  id: string;
  timestamp: string;
  tacticName: string;
  techniqueName: string;
  severity: 'low' | 'medium' | 'high';
  description: string;
}

interface MitreMatrixProps {
  highlightedTechniqueIds?: string[];
}

// Technique arayüzünü tanımla
interface Technique {
  name: string;
  id: string;       // ID özelliğini ekle
  highlighted: boolean; // Bu hala kullanılabilir veya kaldırılabilir
}

// Matrix'in tipini daha belirgin hale getir (opsiyonel ama önerilir)
interface MatrixData {
  description: string;
  techniques: Technique[]; // Tanımladığımız arayüzü kullan
}

type MatrixStructure = Record<string, MatrixData>;

const MitreMatrix: React.FC<MitreMatrixProps> = ({ highlightedTechniqueIds = [] }) => {
  const [currentUser, setCurrentUser] = useState<User | undefined>(undefined);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Fetch current user from local storage
    const userStr = localStorage.getItem('user');
    if (userStr) {
      try {
        setCurrentUser(JSON.parse(userStr) as User);
      } catch {
        setCurrentUser(undefined);
      }
    }

    // Define async function to fetch data
    const fetchData = async () => {
      setLoading(true); // Start loading
      try {
        const res = await api.get<Detection[]>('/api/vulnerabilities?manufacturer=all');
        setDetections(res.data);
        setError(null); // Clear previous errors on success
      } catch (err: any) {
        setError(err.response?.data?.message || 'Failed to load data');
      } finally {
        setLoading(false); // Stop loading regardless of success or failure
      }
    };

    fetchData(); // Call the async function
  }, []); // Empty dependency array means this runs once on mount

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

  // Statik matrix verisi (ID'lerin eklendiğinden emin olun)
  const matrix: MatrixStructure = {
    'Initial Access': {
      description: '13 techniques',
      techniques: [
        { name: 'Data Historian Compromise', id: 'T0811', highlighted: false },
        { name: 'Drive-by Compromise', id: 'T1189', highlighted: false },
        { name: 'Engineering Workstation Compromise', id: 'TXXXX_IA_3', highlighted: false },
        { name: 'Exploit Public-Facing Application', id: 'TXXXX_IA_4', highlighted: false },
        { name: 'External Remote Services', id: 'TXXXX_IA_5', highlighted: false },
        { name: 'Internet Accessible Device', id: 'TXXXX_IA_6', highlighted: false },
        { name: 'Remote Services', id: 'TXXXX_IA_7', highlighted: false },
        { name: 'Replication Through Removable Media', id: 'TXXXX_IA_8', highlighted: false },
        { name: 'Rogue Master', id: 'TXXXX_IA_9', highlighted: false },
        { name: 'Supply Chain Compromise', id: 'TXXXX_IA_10', highlighted: false },
        { name: 'Wireless Compromise', id: 'TXXXX_IA_11', highlighted: false }
      ]
    },
    'Execution': {
      description: '7 techniques',
      techniques: [
        { name: 'Change Operating Mode', id: 'TXXXX_EX_1', highlighted: false },
        { name: 'Command-Line Interface', id: 'TXXXX_EX_2', highlighted: false },
        { name: 'Execution through API', id: 'TXXXX_EX_3', highlighted: false },
        { name: 'Graphical User Interface', id: 'TXXXX_EX_4', highlighted: false },
        { name: 'Hooking', id: 'TXXXX_EX_5', highlighted: false },
        { name: 'Native API', id: 'TXXXX_EX_6', highlighted: false },
        { name: 'Scripting', id: 'TXXXX_EX_7', highlighted: false },
        { name: 'User Execution', id: 'TXXXX_EX_8', highlighted: false }
      ]
    },
    'Persistence': {
      description: '3 techniques',
      techniques: [
        { name: 'Modify Program', id: 'TXXXX_PE_1', highlighted: false },
        { name: 'Module Firmware', id: 'TXXXX_PE_2', highlighted: false },
        { name: 'Project File Infection', id: 'TXXXX_PE_3', highlighted: false },
        { name: 'System Firmware', id: 'TXXXX_PE_4', highlighted: false },
        { name: 'Valid Accounts', id: 'TXXXX_PE_5', highlighted: false }
      ]
    },
    'Privilege Escalation': {
      description: '2 techniques',
      techniques: [
        { name: 'Exploitation for Privilege Escalation', id: 'TXXXX_PR_1', highlighted: false },
        { name: 'Hooking', id: 'TXXXX_PR_2', highlighted: false }
      ]
    },
    'Evasion': {
      description: '6 techniques',
      techniques: [
        { name: 'Change Operating Mode', id: 'TXXXX_EV_1', highlighted: false },
        { name: 'Exploitation for Evasion', id: 'TXXXX_EV_2', highlighted: false },
        { name: 'Indicator Removal on Host', id: 'TXXXX_EV_3', highlighted: false },
        { name: 'Masquerading', id: 'TXXXX_EV_4', highlighted: false },
        { name: 'Rootkit', id: 'TXXXX_EV_5', highlighted: false },
        { name: 'Spoof Reporting Message', id: 'TXXXX_EV_6', highlighted: false }
      ]
    },
    'Discovery': {
      description: '7 techniques',
      techniques: [
        { name: 'Network Connection Enumeration', id: 'T1049', highlighted: false },
        { name: 'Network Sniffing', id: 'TXXXX_DI_3', highlighted: false },
        { name: 'Remote System Discovery', id: 'TXXXX_DI_4', highlighted: false },
        { name: 'Remote System Information Discovery', id: 'TXXXX_DI_5', highlighted: false },
        { name: 'Wireless Sniffing', id: 'TXXXX_DI_6', highlighted: false },
        { name: 'Network Service Scanning', id: 'T1046', highlighted: false }
      ]
    },
    'Lateral Movement': {
      description: '6 techniques',
      techniques: [
        { name: 'Default Credentials', id: 'TXXXX_LM_1', highlighted: false },
        { name: 'Exploitation of Remote Services', id: 'TXXXX_LM_2', highlighted: false },
        { name: 'Lateral Tool Transfer', id: 'TXXXX_LM_3', highlighted: false },
        { name: 'Program Download', id: 'TXXXX_LM_4', highlighted: false },
        { name: 'Remote Services', id: 'TXXXX_LM_5', highlighted: false },
        { name: 'Valid Accounts', id: 'TXXXX_LM_6', highlighted: false }
      ]
    },
    'Collection': {
      description: '10 techniques',
      techniques: [
        { name: 'Automated Collection', id: 'TXXXX_CO_1', highlighted: false },
        { name: 'Detect Operating Mode', id: 'TXXXX_CO_2', highlighted: false },
        { name: 'I/O Image', id: 'TXXXX_CO_3', highlighted: false },
        { name: 'Man in the Middle', id: 'TXXXX_CO_4', highlighted: false },
        { name: 'Monitor Process State', id: 'TXXXX_CO_5', highlighted: false },
        { name: 'Point & Tag Identification', id: 'TXXXX_CO_6', highlighted: false },
        { name: 'Program Upload', id: 'TXXXX_CO_7', highlighted: false },
        { name: 'Screen Capture', id: 'TXXXX_CO_8', highlighted: false },
        { name: 'Wireless Sniffing', id: 'TXXXX_CO_9', highlighted: false }
      ]
    },
    'Command and Control': {
      description: '3 techniques',
      techniques: [
        { name: 'Commonly Used Port', id: 'TXXXX_CC_1', highlighted: false },
        { name: 'Connection Proxy', id: 'TXXXX_CC_2', highlighted: false },
        { name: 'Standard Application Layer Protocol', id: 'TXXXX_CC_3', highlighted: false }
      ]
    },
    'Inhibit Response Function': {
      description: '3 techniques',
      techniques: [
        { name: 'Activate Firmware Update Mode', id: 'TXXXX_IR_1', highlighted: false },
        { name: 'Alarm Suppression', id: 'TXXXX_IR_2', highlighted: false },
        { name: 'Block Command Message', id: 'TXXXX_IR_3', highlighted: false },
        { name: 'Block Reporting Message', id: 'TXXXX_IR_4', highlighted: false },
        { name: 'Block Serial COM', id: 'TXXXX_IR_5', highlighted: false }
      ]
    },
    'Impair Process Control': {
      description: '13 techniques',
      techniques: [
        { name: 'Brute Force I/O', id: 'TXXXX_IP_1', highlighted: false },
        { name: 'Modify Parameter', id: 'TXXXX_IP_2', highlighted: false },
        { name: 'Module Firmware', id: 'TXXXX_IP_3', highlighted: false },
        { name: 'Spoof Reporting Message', id: 'TXXXX_IP_4', highlighted: false },
        { name: 'Unauthorized Command Message', id: 'TXXXX_IP_5', highlighted: false }
      ]
    },
    'Impact': {
      description: '12 techniques',
      techniques: [
        { name: 'Damage to Property', id: 'TXXXX_IM_1', highlighted: false },
        { name: 'Denial of Control', id: 'TXXXX_IM_2', highlighted: false },
        { name: 'Denial of View', id: 'TXXXX_IM_3', highlighted: false },
        { name: 'Loss of Availability', id: 'TXXXX_IM_4', highlighted: false },
        { name: 'Loss of Control', id: 'TXXXX_IM_5', highlighted: false },
        { name: 'Loss of Productivity and Revenue', id: 'TXXXX_IM_6', highlighted: false },
        { name: 'Loss of Protection', id: 'TXXXX_IM_7', highlighted: false },
        { name: 'Loss of Safety', id: 'TXXXX_IM_8', highlighted: false },
        { name: 'Loss of View', id: 'TXXXX_IM_9', highlighted: false },
        { name: 'Manipulation of Control', id: 'TXXXX_IM_10', highlighted: false },
        { name: 'Manipulation of View', id: 'TXXXX_IM_11', highlighted: false },
        { name: 'Theft of Operational Information', id: 'TXXXX_IM_12', highlighted: false }
      ]
    }
  };

  const totalTechniques = Object.values(matrix).reduce((sum, t) => sum + t.techniques.length, 0);
  const totalTactics = Object.keys(matrix).length;
  const highlightedCount = Object.values(matrix).reduce(
    (sum, t) => sum + t.techniques.filter(tech => highlightedTechniqueIds.includes(tech.id)).length,
    0,
  );

  return (
    <motion.div variants={pageContainer} initial="hidden" animate="visible" className="space-y-6">
      <PageHero
        eyebrow="THREAT FRAMEWORK"
        icon={<Icon.Target className="w-4 h-4" />}
        title="MITRE ATT&CK for ICS"
        subtitle="Adversary tactics and techniques observed across OT environments."
        stats={[
          { label: 'Tactics', value: totalTactics },
          { label: 'Techniques', value: totalTechniques },
          { label: 'Observed', value: highlightedCount },
        ]}
      />

      <motion.div variants={pageItem}>
        <Panel
          title="ICS Kill Chain Matrix"
          subtitle="Highlighted cells indicate techniques detected in your environment"
          icon={<Icon.Layers className="w-5 h-5" />}
        >
          <div className="overflow-x-auto rounded-xl ring-1 ring-slate-200/70">
            <table className="min-w-full border-collapse">
              <thead>
                <tr>
                  {Object.entries(matrix).map(([tactic, data]) => (
                    <th
                      key={tactic}
                      className="bg-gradient-to-b from-slate-50 to-slate-100 border-b border-r border-slate-200 p-3 text-center align-top min-w-[140px]"
                    >
                      <div className="text-xs font-bold text-slate-900 uppercase tracking-wide">
                        {tactic}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-1">{data.description}</div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(() => {
                  const maxTechniques = Math.max(...Object.values(matrix).map(t => t.techniques.length));
                  const rows = [];
                  for (let i = 0; i < maxTechniques; i++) {
                    rows.push(
                      <tr key={i}>
                        {Object.entries(matrix).map(([tactic, data]) => {
                          const technique = data.techniques[i];
                          const isHighlighted = technique && (highlightedTechniqueIds.includes(technique.id));
                          return (
                            <td
                              key={`${tactic}-${i}`}
                              className={`border-b border-r border-slate-200/70 p-1.5 text-xs align-top ${
                                technique ? '' : 'bg-slate-50/50'
                              }`}
                            >
                              {technique && (
                                <div
                                  className={`rounded-lg px-2 py-1.5 transition-all duration-150 cursor-default ${
                                    isHighlighted
                                      ? 'bg-gradient-to-r from-rose-500 to-fuchsia-500 text-white font-semibold shadow-md ring-1 ring-rose-400/60'
                                      : 'bg-white text-slate-700 hover:bg-violet-50 hover:text-violet-900 ring-1 ring-slate-100'
                                  }`}
                                  title={`${technique.name} (${technique.id})`}
                                >
                                  {technique.name}
                                </div>
                              )}
                            </td>
                          );
                        })}
                      </tr>
                    );
                  }
                  return rows;
                })()}
              </tbody>
            </table>
          </div>
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