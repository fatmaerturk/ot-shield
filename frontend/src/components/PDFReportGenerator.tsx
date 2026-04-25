import React from 'react';

interface PDFReportGeneratorProps {
  complianceScore: number;
  requirements: any[];
  assetCompliance: any[];
  onGenerate: (reportData: any) => void;
}

const PDFReportGenerator: React.FC<PDFReportGeneratorProps> = ({
  complianceScore,
  requirements,
  assetCompliance,
  onGenerate
}) => {
  const generateExecutiveReport = () => {
    const reportData = {
      type: 'executive',
      title: 'NIS2 Compliance Executive Report',
      date: new Date().toISOString().split('T')[0],
      score: complianceScore,
      summary: {
        totalRequirements: requirements.length,
        compliant: requirements.filter(r => r.status === 'compliant').length,
        nonCompliant: requirements.filter(r => r.status === 'non-compliant').length,
        partiallyCompliant: requirements.filter(r => r.status === 'partially-compliant').length
      },
      criticalFindings: requirements.filter(r => r.status === 'non-compliant' && r.priority === 'high'),
      recommendations: requirements.filter(r => r.status === 'non-compliant' || r.status === 'partially-compliant')
    };
    onGenerate(reportData);
  };

  const generateDetailedReport = () => {
    const reportData = {
      type: 'detailed',
      title: 'NIS2 Compliance Detailed Assessment Report',
      date: new Date().toISOString().split('T')[0],
      score: complianceScore,
      requirements: requirements,
      assetCompliance: assetCompliance,
      riskAnalysis: {
        highRisk: requirements.filter(r => r.priority === 'high' && r.status !== 'compliant').length,
        mediumRisk: requirements.filter(r => r.priority === 'medium' && r.status !== 'compliant').length,
        lowRisk: requirements.filter(r => r.priority === 'low' && r.status !== 'compliant').length
      }
    };
    onGenerate(reportData);
  };

  const generateRemediationPlan = () => {
    const nonCompliantRequirements = requirements.filter(r => r.status === 'non-compliant' || r.status === 'partially-compliant');
    const reportData = {
      type: 'remediation',
      title: 'NIS2 Compliance Remediation Plan',
      date: new Date().toISOString().split('T')[0],
      totalIssues: nonCompliantRequirements.length,
      priorityBreakdown: {
        high: nonCompliantRequirements.filter(r => r.priority === 'high').length,
        medium: nonCompliantRequirements.filter(r => r.priority === 'medium').length,
        low: nonCompliantRequirements.filter(r => r.priority === 'low').length
      },
      estimatedCost: nonCompliantRequirements.length * 10000, // $10k per issue
      estimatedTimeline: '3-6 months',
      actionItems: nonCompliantRequirements.map(req => ({
        requirement: req.requirement,
        priority: req.priority,
        estimatedCost: req.priority === 'high' ? 15000 : req.priority === 'medium' ? 10000 : 5000,
        timeline: req.priority === 'high' ? '1-2 weeks' : req.priority === 'medium' ? '2-4 weeks' : '1-2 months'
      }))
    };
    onGenerate(reportData);
  };

  return (
    <div className="bg-white shadow-lg rounded-lg p-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">Generate Reports</h2>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button
          onClick={generateExecutiveReport}
          className="p-4 border-2 border-blue-300 rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-colors"
        >
          <div className="text-center">
            <div className="text-2xl mb-2">📊</div>
            <div className="font-medium text-blue-700">Executive Report</div>
            <div className="text-sm text-gray-600 mt-1">High-level summary for management</div>
          </div>
        </button>
        
        <button
          onClick={generateDetailedReport}
          className="p-4 border-2 border-green-300 rounded-lg hover:border-green-500 hover:bg-green-50 transition-colors"
        >
          <div className="text-center">
            <div className="text-2xl mb-2">📋</div>
            <div className="font-medium text-green-700">Detailed Report</div>
            <div className="text-sm text-gray-600 mt-1">Comprehensive assessment details</div>
          </div>
        </button>
        
        <button
          onClick={generateRemediationPlan}
          className="p-4 border-2 border-orange-300 rounded-lg hover:border-orange-500 hover:bg-orange-50 transition-colors"
        >
          <div className="text-center">
            <div className="text-2xl mb-2">🔧</div>
            <div className="font-medium text-orange-700">Remediation Plan</div>
            <div className="text-sm text-gray-600 mt-1">Action plan with costs & timeline</div>
          </div>
        </button>
      </div>
    </div>
  );
};

export default PDFReportGenerator; 