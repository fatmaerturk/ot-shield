import React, { useState } from 'react';

interface AnalyticsData {
  complianceTrend: Array<{ date: string; score: number }>;
  riskDistribution: Array<{ category: string; count: number }>;
  assetVulnerabilities: Array<{ asset: string; vulnerabilities: number }>;
  remediationProgress: Array<{ month: string; completed: number; total: number }>;
}

interface AdvancedAnalyticsProps {
  complianceScore: number;
  requirements: any[];
  assetCompliance: any[];
}

const AdvancedAnalytics: React.FC<AdvancedAnalyticsProps> = ({
  complianceScore,
  requirements,
  assetCompliance
}) => {
  const [selectedTimeframe, setSelectedTimeframe] = useState<'3m' | '6m' | '1y'>('6m');

  // Mock analytics data
  const analyticsData: AnalyticsData = {
    complianceTrend: [
      { date: '2024-07', score: 45 },
      { date: '2024-08', score: 52 },
      { date: '2024-09', score: 65 },
      { date: '2024-10', score: 68 },
      { date: '2024-11', score: 72 },
      { date: '2024-12', score: complianceScore }
    ],
    riskDistribution: [
      { category: 'Risk Management', count: 3 },
      { category: 'Incident Handling', count: 2 },
      { category: 'Access Control', count: 4 },
      { category: 'Asset Management', count: 1 },
      { category: 'Monitoring', count: 2 }
    ],
    assetVulnerabilities: assetCompliance.map(asset => ({
      asset: asset.name,
      vulnerabilities: asset.vulnerabilities
    })),
    remediationProgress: [
      { month: 'Oct', completed: 5, total: 15 },
      { month: 'Nov', completed: 8, total: 15 },
      { month: 'Dec', completed: 12, total: 15 }
    ]
  };

  const predictNextQuarterScore = () => {
    const recentScores = analyticsData.complianceTrend.slice(-3).map(d => d.score);
    const averageImprovement = recentScores.reduce((acc, score, i) => {
      if (i === 0) return 0;
      return acc + (score - recentScores[i - 1]);
    }, 0) / (recentScores.length - 1);
    
    return Math.min(100, Math.round(complianceScore + averageImprovement));
  };

  const getRiskLevel = (score: number) => {
    if (score >= 80) return { level: 'Low', color: 'text-green-600', bg: 'bg-green-100' };
    if (score >= 60) return { level: 'Medium', color: 'text-yellow-600', bg: 'bg-yellow-100' };
    return { level: 'High', color: 'text-red-600', bg: 'bg-red-100' };
  };

  const riskLevel = getRiskLevel(complianceScore);
  const predictedScore = predictNextQuarterScore();

  return (
    <div className="space-y-6">
      {/* Predictive Analytics */}
      <div className="bg-white shadow-sm rounded-2xl ring-1 ring-slate-200/70 p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Predictive Analytics</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-blue-50 p-4 rounded-lg">
            <h3 className="font-semibold text-blue-800 mb-2">Current Risk Level</h3>
            <div className={`text-2xl font-bold ${riskLevel.color}`}>{riskLevel.level}</div>
            <p className="text-sm text-blue-700 mt-1">Based on current compliance score</p>
          </div>
          <div className="bg-green-50 p-4 rounded-lg">
            <h3 className="font-semibold text-green-800 mb-2">Q1 2025 Prediction</h3>
            <div className="text-2xl font-bold text-green-600">{predictedScore}%</div>
            <p className="text-sm text-green-700 mt-1">Projected compliance score</p>
          </div>
          <div className="bg-purple-50 p-4 rounded-lg">
            <h3 className="font-semibold text-purple-800 mb-2">Improvement Rate</h3>
            <div className="text-2xl font-bold text-purple-600">+{predictedScore - complianceScore}%</div>
            <p className="text-sm text-purple-700 mt-1">Expected improvement</p>
          </div>
        </div>
      </div>

      {/* Compliance Trend Chart */}
      <div className="bg-white shadow-sm rounded-2xl ring-1 ring-slate-200/70 p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold text-gray-900">Compliance Trend</h2>
          <select
            value={selectedTimeframe}
            onChange={(e) => setSelectedTimeframe(e.target.value as any)}
            className="border border-gray-300 rounded-md px-3 py-1 text-sm"
          >
            <option value="3m">Last 3 Months</option>
            <option value="6m">Last 6 Months</option>
            <option value="1y">Last Year</option>
          </select>
        </div>
        <div className="h-64 bg-gray-50 rounded-lg p-4">
          <div className="flex items-end justify-between h-full space-x-2">
            {analyticsData.complianceTrend.map((point, index) => (
              <div key={index} className="flex-1 flex flex-col items-center">
                <div 
                  className="bg-blue-500 rounded-t w-full"
                  style={{ height: `${point.score}%` }}
                ></div>
                <div className="text-xs text-gray-600 mt-2">{point.date}</div>
                <div className="text-xs font-medium">{point.score}%</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Risk Distribution */}
      <div className="bg-white shadow-sm rounded-2xl ring-1 ring-slate-200/70 p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Risk Distribution by Category</h2>
        <div className="space-y-3">
          {analyticsData.riskDistribution.map((item, index) => (
            <div key={index} className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">{item.category}</span>
              <div className="flex items-center space-x-2">
                <div className="w-32 bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-red-500 h-2 rounded-full"
                    style={{ width: `${(item.count / Math.max(...analyticsData.riskDistribution.map(r => r.count))) * 100}%` }}
                  ></div>
                </div>
                <span className="text-sm text-gray-600 w-8">{item.count}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Asset Vulnerability Analysis */}
      <div className="bg-white shadow-sm rounded-2xl ring-1 ring-slate-200/70 p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Asset Vulnerability Analysis</h2>
        <div className="space-y-3">
          {analyticsData.assetVulnerabilities.map((asset, index) => (
            <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <span className="text-sm font-medium text-gray-700">{asset.asset}</span>
              <div className="flex items-center space-x-2">
                <span className={`px-2 py-1 text-xs font-semibold rounded-full ${
                  asset.vulnerabilities === 0 ? 'bg-green-100 text-green-800' :
                  asset.vulnerabilities <= 2 ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800'
                }`}>
                  {asset.vulnerabilities} vulnerabilities
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Remediation Progress */}
      <div className="bg-white shadow-sm rounded-2xl ring-1 ring-slate-200/70 p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Remediation Progress</h2>
        <div className="space-y-4">
          {analyticsData.remediationProgress.map((progress, index) => (
            <div key={index} className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">{progress.month}</span>
              <div className="flex items-center space-x-2">
                <div className="w-32 bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-green-500 h-2 rounded-full"
                    style={{ width: `${(progress.completed / progress.total) * 100}%` }}
                  ></div>
                </div>
                <span className="text-sm text-gray-600">{progress.completed}/{progress.total}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Key Insights */}
      <div className="bg-white shadow-sm rounded-2xl ring-1 ring-slate-200/70 p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Key Insights</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-blue-50 p-4 rounded-lg">
            <h3 className="font-semibold text-blue-800 mb-2">Top Priority Areas</h3>
            <ul className="text-sm text-blue-700 space-y-1">
              <li>• Access Control (4 high-priority issues)</li>
              <li>• Risk Management (3 critical findings)</li>
              <li>• Incident Handling (2 urgent items)</li>
            </ul>
          </div>
          <div className="bg-green-50 p-4 rounded-lg">
            <h3 className="font-semibold text-green-800 mb-2">Positive Trends</h3>
            <ul className="text-sm text-green-700 space-y-1">
              <li>• 13% improvement since Q3 2024</li>
              <li>• 80% of critical assets secured</li>
              <li>• Remediation progress on track</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdvancedAnalytics; 