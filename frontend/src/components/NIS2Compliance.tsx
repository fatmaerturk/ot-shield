import React, { useState } from 'react';
import PDFReportGenerator from './PDFReportGenerator';
import AdvancedAnalytics from './AdvancedAnalytics';
import EmailNotifications from './EmailNotifications';
import MultiLanguageSupport from './MultiLanguageSupport';

interface NIS2Requirement {
  id: string;
  category: string;
  requirement: string;
  description: string;
  status: 'compliant' | 'non-compliant' | 'partially-compliant' | 'not-assessed';
  evidence?: string;
  lastAssessed?: string;
  priority: 'high' | 'medium' | 'low';
  riskScore?: number;
  remediationCost?: string;
  estimatedTime?: string;
}

interface ComplianceReport {
  id: string;
  title: string;
  date: string;
  status: 'draft' | 'final' | 'archived';
  score: number;
  findings: number;
  recommendations: number;
}

interface AssetCompliance {
  id: string;
  name: string;
  type: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  complianceScore: number;
  lastAssessment: string;
  vulnerabilities: number;
  recommendations: string[];
}

const NIS2Compliance: React.FC = () => {
  const [requirements, setRequirements] = useState<NIS2Requirement[]>([
    {
      id: 'NIS2-001',
      category: 'Risk Management',
      requirement: 'Risk Assessment',
      description: 'Conduct regular risk assessments of network and information systems',
      status: 'not-assessed',
      priority: 'high'
    },
    {
      id: 'NIS2-002',
      category: 'Risk Management',
      requirement: 'Security Policies',
      description: 'Implement security policies and procedures',
      status: 'not-assessed',
      priority: 'high'
    },
    {
      id: 'NIS2-003',
      category: 'Incident Handling',
      requirement: 'Incident Response',
      description: 'Establish incident response capabilities',
      status: 'not-assessed',
      priority: 'high'
    },
    {
      id: 'NIS2-004',
      category: 'Incident Handling',
      requirement: 'Incident Reporting',
      description: 'Report significant incidents to competent authorities',
      status: 'not-assessed',
      priority: 'high'
    },
    {
      id: 'NIS2-005',
      category: 'Business Continuity',
      requirement: 'Business Continuity',
      description: 'Ensure business continuity and disaster recovery',
      status: 'not-assessed',
      priority: 'medium'
    },
    {
      id: 'NIS2-006',
      category: 'Supply Chain Security',
      requirement: 'Supply Chain Security',
      description: 'Manage security risks in the supply chain',
      status: 'not-assessed',
      priority: 'medium'
    },
    {
      id: 'NIS2-007',
      category: 'Access Control',
      requirement: 'Access Control',
      description: 'Implement appropriate access controls',
      status: 'not-assessed',
      priority: 'high'
    },
    {
      id: 'NIS2-008',
      category: 'Asset Management',
      requirement: 'Asset Inventory',
      description: 'Maintain inventory of critical assets',
      status: 'not-assessed',
      priority: 'medium'
    },
    {
      id: 'NIS2-009',
      category: 'Monitoring',
      requirement: 'Security Monitoring',
      description: 'Implement continuous security monitoring',
      status: 'not-assessed',
      priority: 'high'
    },
    {
      id: 'NIS2-010',
      category: 'Training',
      requirement: 'Security Awareness',
      description: 'Provide security awareness training',
      status: 'not-assessed',
      priority: 'medium'
    }
  ]);

  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [activeTab, setActiveTab] = useState<'overview' | 'requirements' | 'assets' | 'reports' | 'remediation' | 'analytics' | 'notifications' | 'language'>('overview');

  const categories = ['all', ...Array.from(new Set(requirements.map(r => r.category)))];
  const statuses = ['all', 'compliant', 'non-compliant', 'partially-compliant', 'not-assessed'];

  // Sample data for new features
  const [complianceReports] = useState<ComplianceReport[]>([
    {
      id: '1',
      title: 'Q4 2024 NIS2 Assessment',
      date: '2024-12-15',
      status: 'final',
      score: 78,
      findings: 12,
      recommendations: 8
    },
    {
      id: '2',
      title: 'Q3 2024 NIS2 Assessment',
      date: '2024-09-30',
      status: 'archived',
      score: 65,
      findings: 18,
      recommendations: 15
    }
  ]);

  const [assetCompliance] = useState<AssetCompliance[]>([
    {
      id: '1',
      name: 'SCADA System - Production Line 1',
      type: 'SCADA',
      criticality: 'critical',
      complianceScore: 85,
      lastAssessment: '2024-12-10',
      vulnerabilities: 3,
      recommendations: ['Implement network segmentation', 'Update access controls', 'Enable audit logging']
    },
    {
      id: '2',
      name: 'PLC - Boiler Control System',
      type: 'PLC',
      criticality: 'high',
      complianceScore: 72,
      lastAssessment: '2024-12-08',
      vulnerabilities: 5,
      recommendations: ['Patch firmware', 'Implement change management', 'Add monitoring']
    },
    {
      id: '3',
      name: 'HMI - Operator Station 1',
      type: 'HMI',
      criticality: 'medium',
      complianceScore: 90,
      lastAssessment: '2024-12-12',
      vulnerabilities: 1,
      recommendations: ['Regular security updates']
    }
  ]);

  const filteredRequirements = requirements.filter(req => {
    const categoryMatch = selectedCategory === 'all' || req.category === selectedCategory;
    const statusMatch = selectedStatus === 'all' || req.status === selectedStatus;
    return categoryMatch && statusMatch;
  });

  const updateRequirement = (id: string, updates: Partial<NIS2Requirement>) => {
    setRequirements(prev => prev.map(req => 
      req.id === id ? { ...req, ...updates } : req
    ));
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant': return 'bg-green-100 text-green-800';
      case 'non-compliant': return 'bg-red-100 text-red-800';
      case 'partially-compliant': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'high': return 'bg-red-100 text-red-800';
      case 'medium': return 'bg-yellow-100 text-yellow-800';
      case 'low': return 'bg-green-100 text-green-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const complianceScore = () => {
    const total = requirements.length;
    const compliant = requirements.filter(r => r.status === 'compliant').length;
    const partiallyCompliant = requirements.filter(r => r.status === 'partially-compliant').length;
    return Math.round(((compliant + (partiallyCompliant * 0.5)) / total) * 100);
  };

  const getCriticalityColor = (criticality: string) => {
    switch (criticality) {
      case 'critical': return 'bg-red-100 text-red-800';
      case 'high': return 'bg-orange-100 text-orange-800';
      case 'medium': return 'bg-yellow-100 text-yellow-800';
      case 'low': return 'bg-green-100 text-green-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusBadgeColor = (status: string) => {
    switch (status) {
      case 'final': return 'bg-green-100 text-green-800';
      case 'draft': return 'bg-blue-100 text-blue-800';
      case 'archived': return 'bg-gray-100 text-gray-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Hero */}
      <div
        className="relative overflow-hidden rounded-2xl p-8 md:p-10 text-white"
        style={{ background: 'linear-gradient(135deg, #1e1b4b 0%, #4c1d95 45%, #7c3aed 100%)' }}
      >
        <div className="absolute -top-20 -right-20 w-72 h-72 rounded-full bg-fuchsia-500/20 blur-3xl" />
        <div className="absolute -bottom-10 -left-10 w-60 h-60 rounded-full bg-violet-400/10 blur-3xl" />
        <div className="relative flex flex-col md:flex-row md:items-end md:justify-between gap-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 ring-1 ring-white/20 text-xs font-semibold tracking-wider backdrop-blur-sm mb-4">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              NIS2 DIRECTIVE
            </div>
            <h1 className="text-3xl md:text-4xl font-bold leading-tight">
              NIS2 Compliance Dashboard
              <span className="block text-violet-100/90 font-medium text-lg md:text-xl mt-2">
                Network and Information Security Directive 2 posture, evidence and remediation.
              </span>
            </h1>
          </div>
          <div className="text-right">
            <div className="text-5xl font-extrabold text-white drop-shadow-sm">
              {complianceScore()}%
            </div>
            <div className="text-sm font-semibold text-violet-100/80 uppercase tracking-wider">
              Overall Compliance
            </div>
          </div>
        </div>
      </div>

      {/* Compliance Overview Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="relative overflow-hidden bg-white rounded-2xl p-5 ring-1 ring-slate-200/70 shadow-sm">
          <div className="absolute top-0 right-0 w-20 h-20 rounded-full bg-emerald-500/10 blur-2xl" />
          <div className="relative">
            <div className="text-3xl font-bold text-emerald-600">
              {requirements.filter(r => r.status === 'compliant').length}
            </div>
            <div className="text-xs font-semibold text-emerald-700 uppercase tracking-wider mt-1">Compliant</div>
          </div>
        </div>
        <div className="relative overflow-hidden bg-white rounded-2xl p-5 ring-1 ring-slate-200/70 shadow-sm">
          <div className="absolute top-0 right-0 w-20 h-20 rounded-full bg-amber-500/10 blur-2xl" />
          <div className="relative">
            <div className="text-3xl font-bold text-amber-600">
              {requirements.filter(r => r.status === 'partially-compliant').length}
            </div>
            <div className="text-xs font-semibold text-amber-700 uppercase tracking-wider mt-1">Partial</div>
          </div>
        </div>
        <div className="relative overflow-hidden bg-white rounded-2xl p-5 ring-1 ring-slate-200/70 shadow-sm">
          <div className="absolute top-0 right-0 w-20 h-20 rounded-full bg-rose-500/10 blur-2xl" />
          <div className="relative">
            <div className="text-3xl font-bold text-rose-600">
              {requirements.filter(r => r.status === 'non-compliant').length}
            </div>
            <div className="text-xs font-semibold text-rose-700 uppercase tracking-wider mt-1">Non-Compliant</div>
          </div>
        </div>
        <div className="relative overflow-hidden bg-white rounded-2xl p-5 ring-1 ring-slate-200/70 shadow-sm">
          <div className="absolute top-0 right-0 w-20 h-20 rounded-full bg-slate-500/10 blur-2xl" />
          <div className="relative">
            <div className="text-3xl font-bold text-slate-600">
              {requirements.filter(r => r.status === 'not-assessed').length}
            </div>
            <div className="text-xs font-semibold text-slate-700 uppercase tracking-wider mt-1">Not Assessed</div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-white shadow-sm rounded-2xl ring-1 ring-slate-200/70">
        <div className="border-b border-slate-200/60">
          <nav className="-mb-px flex flex-wrap gap-2 px-6 py-2">
            {[
              { id: 'overview', label: 'Overview' },
              { id: 'requirements', label: 'Requirements' },
              { id: 'assets', label: 'Asset Compliance' },
              { id: 'reports', label: 'Reports' },
              { id: 'remediation', label: 'Remediation' },
              { id: 'analytics', label: 'Analytics' },
              { id: 'notifications', label: 'Notifications' },
              { id: 'language', label: 'Language' }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`px-4 py-2 rounded-xl font-semibold text-sm transition ${
                  activeTab === tab.id
                    ? 'bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white shadow'
                    : 'text-slate-600 hover:text-violet-700 hover:bg-violet-50'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
      </div>

      <div>
        {/* Legacy inner content remains below */}

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Risk Heat Map */}
            <div className="bg-white shadow-lg rounded-lg p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">Risk Heat Map</h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-red-50 p-4 rounded-lg border-l-4 border-red-400">
                  <h3 className="font-semibold text-red-800">High Risk Areas</h3>
                  <div className="text-2xl font-bold text-red-600 mt-2">3</div>
                  <p className="text-sm text-red-700 mt-1">Critical vulnerabilities requiring immediate attention</p>
                </div>
                <div className="bg-yellow-50 p-4 rounded-lg border-l-4 border-yellow-400">
                  <h3 className="font-semibold text-yellow-800">Medium Risk Areas</h3>
                  <div className="text-2xl font-bold text-yellow-600 mt-2">7</div>
                  <p className="text-sm text-yellow-700 mt-1">Issues that need attention within 30 days</p>
                </div>
                <div className="bg-green-50 p-4 rounded-lg border-l-4 border-green-400">
                  <h3 className="font-semibold text-green-800">Low Risk Areas</h3>
                  <div className="text-2xl font-bold text-green-600 mt-2">15</div>
                  <p className="text-sm text-green-700 mt-1">Well-controlled areas with minor improvements needed</p>
                </div>
              </div>
            </div>

            {/* Compliance Timeline */}
            <div className="bg-white shadow-lg rounded-lg p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">Compliance Timeline</h2>
              <div className="space-y-4">
                <div className="flex items-center space-x-4">
                  <div className="w-4 h-4 bg-green-500 rounded-full"></div>
                  <div className="flex-1">
                    <p className="font-medium">Q3 2024 Assessment Completed</p>
                    <p className="text-sm text-gray-600">65% compliance score achieved</p>
                  </div>
                  <span className="text-sm text-gray-500">Sep 30, 2024</span>
                </div>
                <div className="flex items-center space-x-4">
                  <div className="w-4 h-4 bg-blue-500 rounded-full"></div>
                  <div className="flex-1">
                    <p className="font-medium">Q4 2024 Assessment In Progress</p>
                    <p className="text-sm text-gray-600">Current score: {complianceScore()}%</p>
                  </div>
                  <span className="text-sm text-gray-500">Dec 15, 2024</span>
                </div>
                <div className="flex items-center space-x-4">
                  <div className="w-4 h-4 bg-gray-300 rounded-full"></div>
                  <div className="flex-1">
                    <p className="font-medium text-gray-500">Q1 2025 Target</p>
                    <p className="text-sm text-gray-500">Target: 85% compliance score</p>
                  </div>
                  <span className="text-sm text-gray-500">Mar 31, 2025</span>
                </div>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="bg-white shadow-lg rounded-lg p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">Quick Actions</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <button className="p-4 border-2 border-dashed border-gray-300 rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-colors">
                  <div className="text-center">
                    <div className="text-2xl mb-2">📋</div>
                    <div className="font-medium">New Assessment</div>
                  </div>
                </button>
                <button className="p-4 border-2 border-dashed border-gray-300 rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-colors">
                  <div className="text-center">
                    <div className="text-2xl mb-2">📊</div>
                    <div className="font-medium">Generate Report</div>
                  </div>
                </button>
                <button className="p-4 border-2 border-dashed border-gray-300 rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-colors">
                  <div className="text-center">
                    <div className="text-2xl mb-2">🔧</div>
                    <div className="font-medium">Remediation Plan</div>
                  </div>
                </button>
                <button className="p-4 border-2 border-dashed border-gray-300 rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-colors">
                  <div className="text-center">
                    <div className="text-2xl mb-2">📧</div>
                    <div className="font-medium">Export Data</div>
                  </div>
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'requirements' && (
          <div className="space-y-6">
            {/* Filters */}
            <div className="bg-white shadow-lg rounded-lg p-6">
              <div className="flex flex-wrap gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Category</label>
                  <select
                    value={selectedCategory}
                    onChange={(e) => setSelectedCategory(e.target.value)}
                    className="border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    {categories.map(category => (
                      <option key={category} value={category}>
                        {category === 'all' ? 'All Categories' : category}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Status</label>
                  <select
                    value={selectedStatus}
                    onChange={(e) => setSelectedStatus(e.target.value)}
                    className="border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    {statuses.map(status => (
                      <option key={status} value={status}>
                        {status === 'all' ? 'All Statuses' : status.replace('-', ' ')}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {/* Requirements List */}
            <div className="bg-white shadow-lg rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-xl font-semibold text-gray-900">Requirements Assessment</h2>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Requirement
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Category
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Priority
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {filteredRequirements.map((requirement) => (
                      <tr key={requirement.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4">
                          <div>
                            <div className="text-sm font-medium text-gray-900">{requirement.requirement}</div>
                            <div className="text-sm text-gray-500">{requirement.description}</div>
                            {requirement.evidence && (
                              <div className="text-xs text-blue-600 mt-1">
                                Evidence: {requirement.evidence}
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-sm text-gray-900">{requirement.category}</span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getPriorityColor(requirement.priority)}`}>
                            {requirement.priority}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <select
                            value={requirement.status}
                            onChange={(e) => updateRequirement(requirement.id, { 
                              status: e.target.value as any,
                              lastAssessed: new Date().toISOString().split('T')[0]
                            })}
                            className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full border ${getStatusColor(requirement.status)}`}
                          >
                            <option value="not-assessed">Not Assessed</option>
                            <option value="compliant">Compliant</option>
                            <option value="partially-compliant">Partially Compliant</option>
                            <option value="non-compliant">Non-Compliant</option>
                          </select>
                        </td>
                        <td className="px-6 py-4">
                          <button
                            onClick={() => {
                              const evidence = prompt('Enter evidence for compliance:');
                              if (evidence) {
                                updateRequirement(requirement.id, { evidence });
                              }
                            }}
                            className="text-blue-600 hover:text-blue-900 text-sm font-medium"
                          >
                            Add Evidence
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Recommendations */}
            <div className="bg-white shadow-lg rounded-lg p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">Recommendations</h2>
              <div className="space-y-4">
                {requirements.filter(r => r.status === 'non-compliant' || r.status === 'partially-compliant').map(req => (
                  <div key={req.id} className="border-l-4 border-red-400 pl-4">
                    <h3 className="font-medium text-gray-900">{req.requirement}</h3>
                    <p className="text-sm text-gray-600 mt-1">
                      Priority: <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getPriorityColor(req.priority)}`}>
                        {req.priority}
                      </span>
                    </p>
                    <p className="text-sm text-gray-600 mt-1">
                      {req.status === 'non-compliant' 
                        ? 'This requirement needs immediate attention to achieve compliance.'
                        : 'This requirement needs improvement to achieve full compliance.'
                      }
                    </p>
                  </div>
                ))}
                {requirements.filter(r => r.status === 'non-compliant' || r.status === 'partially-compliant').length === 0 && (
                  <p className="text-green-600">All requirements are compliant! Great job!</p>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'assets' && (
          <div className="space-y-6">
            {/* Asset Compliance Overview */}
            <div className="bg-white shadow-lg rounded-lg p-6">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-gray-900">Asset Compliance Overview</h2>
                <button className="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600">
                  Add Asset
                </button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-blue-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-blue-600">{assetCompliance.length}</div>
                  <div className="text-sm text-blue-700">Total Assets</div>
                </div>
                <div className="bg-green-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">
                    {assetCompliance.filter(a => a.complianceScore >= 80).length}
                  </div>
                  <div className="text-sm text-green-700">Compliant Assets</div>
                </div>
                <div className="bg-red-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">
                    {assetCompliance.filter(a => a.criticality === 'critical').length}
                  </div>
                  <div className="text-sm text-red-700">Critical Assets</div>
                </div>
                <div className="bg-yellow-50 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-yellow-600">
                    {assetCompliance.reduce((sum, a) => sum + a.vulnerabilities, 0)}
                  </div>
                  <div className="text-sm text-yellow-700">Total Vulnerabilities</div>
                </div>
              </div>
            </div>

            {/* Asset List */}
            <div className="bg-white shadow-lg rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">Asset Compliance Details</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Asset Name
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Type
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Criticality
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Compliance Score
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Vulnerabilities
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {assetCompliance.map((asset) => (
                      <tr key={asset.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4">
                          <div>
                            <div className="text-sm font-medium text-gray-900">{asset.name}</div>
                            <div className="text-sm text-gray-500">Last assessed: {asset.lastAssessment}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-sm text-gray-900">{asset.type}</span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getCriticalityColor(asset.criticality)}`}>
                            {asset.criticality}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center">
                            <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                              <div 
                                className={`h-2 rounded-full ${
                                  asset.complianceScore >= 80 ? 'bg-green-500' :
                                  asset.complianceScore >= 60 ? 'bg-yellow-500' : 'bg-red-500'
                                }`}
                                style={{ width: `${asset.complianceScore}%` }}
                              ></div>
                            </div>
                            <span className="text-sm text-gray-900">{asset.complianceScore}%</span>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            asset.vulnerabilities === 0 ? 'bg-green-100 text-green-800' :
                            asset.vulnerabilities <= 2 ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800'
                          }`}>
                            {asset.vulnerabilities}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <button className="text-blue-600 hover:text-blue-900 text-sm font-medium">
                            View Details
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'reports' && (
          <div className="space-y-6">
            {/* Reports Overview */}
            <div className="bg-white shadow-lg rounded-lg p-6">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-gray-900">Compliance Reports</h2>
                <button className="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600">
                  Generate New Report
                </button>
              </div>
            </div>

            {/* Reports List */}
            <div className="bg-white shadow-lg rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">Available Reports</h3>
              </div>
              <div className="divide-y divide-gray-200">
                {complianceReports.map((report) => (
                  <div key={report.id} className="p-6 hover:bg-gray-50">
                    <div className="flex justify-between items-start">
                      <div className="flex-1">
                        <h4 className="text-lg font-medium text-gray-900">{report.title}</h4>
                        <p className="text-sm text-gray-600 mt-1">Generated on {report.date}</p>
                        <div className="flex items-center space-x-4 mt-2">
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusBadgeColor(report.status)}`}>
                            {report.status}
                          </span>
                          <span className="text-sm text-gray-600">{report.findings} findings</span>
                          <span className="text-sm text-gray-600">{report.recommendations} recommendations</span>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-2xl font-bold text-blue-600">{report.score}%</div>
                        <div className="text-sm text-gray-500">Compliance Score</div>
                        <div className="flex space-x-2 mt-2">
                          <button className="text-blue-600 hover:text-blue-900 text-sm font-medium">
                            View
                          </button>
                          <button className="text-green-600 hover:text-green-900 text-sm font-medium">
                            Export
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'remediation' && (
          <div className="space-y-6">
            {/* Remediation Overview */}
            <div className="bg-white shadow-lg rounded-lg p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">Remediation Planning</h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-red-50 p-4 rounded-lg border-l-4 border-red-400">
                  <h3 className="font-semibold text-red-800">Immediate Actions (0-7 days)</h3>
                  <div className="text-2xl font-bold text-red-600 mt-2">5</div>
                  <p className="text-sm text-red-700 mt-1">Critical issues requiring immediate attention</p>
                </div>
                <div className="bg-yellow-50 p-4 rounded-lg border-l-4 border-yellow-400">
                  <h3 className="font-semibold text-yellow-800">Short Term (8-30 days)</h3>
                  <div className="text-2xl font-bold text-yellow-600 mt-2">12</div>
                  <p className="text-sm text-yellow-700 mt-1">Issues to be addressed within 30 days</p>
                </div>
                <div className="bg-blue-50 p-4 rounded-lg border-l-4 border-blue-400">
                  <h3 className="font-semibold text-blue-800">Long Term (31-90 days)</h3>
                  <div className="text-2xl font-bold text-blue-600 mt-2">8</div>
                  <p className="text-sm text-blue-700 mt-1">Strategic improvements and enhancements</p>
                </div>
              </div>
            </div>

            {/* Remediation Tasks */}
            <div className="bg-white shadow-lg rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">Remediation Tasks</h3>
              </div>
              <div className="divide-y divide-gray-200">
                {requirements.filter(r => r.status === 'non-compliant' || r.status === 'partially-compliant').map((req, index) => (
                  <div key={req.id} className="p-6">
                    <div className="flex justify-between items-start">
                      <div className="flex-1">
                        <h4 className="text-lg font-medium text-gray-900">{req.requirement}</h4>
                        <p className="text-sm text-gray-600 mt-1">{req.description}</p>
                        <div className="flex items-center space-x-4 mt-2">
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getPriorityColor(req.priority)}`}>
                            {req.priority} priority
                          </span>
                          <span className="text-sm text-gray-600">Estimated cost: $5,000 - $15,000</span>
                          <span className="text-sm text-gray-600">Timeline: 2-4 weeks</span>
                        </div>
                      </div>
                      <div className="text-right">
                        <button className="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600 text-sm">
                          Create Task
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'analytics' && (
          <AdvancedAnalytics 
            complianceScore={complianceScore()}
            requirements={requirements}
            assetCompliance={assetCompliance}
          />
        )}

        {activeTab === 'reports' && (
          <div className="space-y-6">
            <PDFReportGenerator
              complianceScore={complianceScore()}
              requirements={requirements}
              assetCompliance={assetCompliance}
              onGenerate={(reportData) => {
                console.log('Generated report:', reportData);
                alert('Report generated successfully! Check console for details.');
              }}
            />
          </div>
        )}

        {activeTab === 'notifications' && (
          <EmailNotifications />
        )}

        {activeTab === 'language' && (
          <MultiLanguageSupport />
        )}
      </div>
    </div>
  );
};

export default NIS2Compliance; 