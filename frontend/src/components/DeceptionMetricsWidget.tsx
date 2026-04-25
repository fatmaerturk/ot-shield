import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement } from 'chart.js';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement);

interface DeceptionMetricsWidgetProps {
  compact?: boolean;
}

const DeceptionMetricsWidget: React.FC<DeceptionMetricsWidgetProps> = ({ compact = false }) => {
  const [decoyStats] = useState({
    totalDeployed: 156,
    activeInteractions: 487,
    avgResponseTime: 48,
    blockedAttempts: 318,
    falsePositiveRate: 5.8,
    threatDetectionRate: 94.2,
  });

  const [interactionHistory] = useState([
    { time: '00:00', count: 12, type: 'scanning' },
    { time: '04:00', count: 28, type: 'probing' },
    { time: '08:00', count: 45, type: 'mixed' },
    { time: '12:00', count: 67, type: 'attacks' },
    { time: '16:00', count: 54, type: 'scanning' },
    { time: '20:00', count: 38, type: 'probing' },
    { time: '23:59', count: 18, type: 'scanning' },
  ]);

  const [decoysByType] = useState([
    { type: 'Fake HMI', count: 45, interactions: 127 },
    { type: 'Fake PLC/RTU', count: 67, interactions: 234 },
    { type: 'Fake Historical Data', count: 28, interactions: 89 },
    { type: 'Fake IED', count: 16, interactions: 37 },
  ]);

  // Chart data - Interaction Timeline
  const interactionChartData = {
    labels: interactionHistory.map(h => h.time),
    datasets: [
      {
        label: 'Decoy Interactions',
        data: interactionHistory.map(h => h.count),
        borderColor: '#a855f7',
        backgroundColor: 'rgba(168, 85, 247, 0.1)',
        fill: true,
        tension: 0.4,
        pointBackgroundColor: '#ec4899',
        pointBorderColor: '#a855f7',
        pointRadius: 4,
      },
    ],
  };

  // Chart data - Decoy Type Distribution
  const decoyDistributionData = {
    labels: decoysByType.map(d => d.type),
    datasets: [
      {
        label: 'Interactions',
        data: decoysByType.map(d => d.interactions),
        backgroundColor: [
          'rgba(236, 72, 153, 0.6)',
          'rgba(168, 85, 247, 0.6)',
          'rgba(6, 182, 212, 0.6)',
          'rgba(74, 222, 128, 0.6)',
        ],
        borderColor: ['#ec4899', '#a855f7', '#06b6d4', '#4ade80'],
        borderWidth: 2,
      },
    ],
  };

  // Attack Vector Blocked
  const attackBlockedData = {
    labels: ['Blocked by Deception', 'Detected by Analytics', 'Allowed (Monitoring)'],
    datasets: [
      {
        data: [318, 89, 80],
        backgroundColor: [
          'rgba(34, 197, 94, 0.6)',
          'rgba(168, 85, 247, 0.6)',
          'rgba(245, 158, 11, 0.6)',
        ],
        borderColor: ['#22c55e', '#a855f7', '#f59e0b'],
        borderWidth: 2,
      },
    ],
  };

  if (compact) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="bg-gradient-to-br from-slate-800 to-slate-900 border border-purple-500/30 rounded-lg p-4"
      >
        <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
          <span className="text-lg">✨</span>
          Deception Layer Status
        </h3>
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-purple-500/10 p-2 rounded border border-purple-500/20">
            <p className="text-xs text-slate-400">🛡️ Deployed</p>
            <p className="text-lg font-bold text-purple-400">{decoyStats.totalDeployed}</p>
          </div>
          <div className="bg-pink-500/10 p-2 rounded border border-pink-500/20">
            <p className="text-xs text-slate-400">🎯 24h Hits</p>
            <p className="text-lg font-bold text-pink-400">{decoyStats.activeInteractions}</p>
          </div>
          <div className="bg-green-500/10 p-2 rounded border border-green-500/20">
            <p className="text-xs text-slate-400">⚡ Response</p>
            <p className="text-lg font-bold text-green-400">{decoyStats.avgResponseTime}ms</p>
          </div>
          <div className="bg-orange-500/10 p-2 rounded border border-orange-500/20">
            <p className="text-xs text-slate-400">🚫 Blocked</p>
            <p className="text-lg font-bold text-orange-400">{decoyStats.blockedAttempts}</p>
          </div>
        </div>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="space-y-6"
    >
      {/* Top Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-gradient-to-br from-slate-800 to-slate-900 border border-purple-500/30 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-400 uppercase">Deployed Decoys</span>
            <span className="text-lg">✨</span>
          </div>
          <p className="text-2xl font-bold text-purple-400">{decoyStats.totalDeployed}</p>
          <div className="text-xs text-slate-500 mt-2">Active across all levels</div>
        </div>

        <div className="bg-gradient-to-br from-slate-800 to-slate-900 border border-pink-500/30 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-400 uppercase">24h Interactions</span>
            <span className="text-lg">📈</span>
          </div>
          <p className="text-2xl font-bold text-pink-400">{decoyStats.activeInteractions}</p>
          <div className="text-xs text-slate-500 mt-2">↑ 12% vs yesterday</div>
        </div>

        <div className="bg-gradient-to-br from-slate-800 to-slate-900 border border-green-500/30 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-400 uppercase">Avg Response</span>
            <span className="text-lg">✅</span>
          </div>
          <p className="text-2xl font-bold text-green-400">{decoyStats.avgResponseTime}ms</p>
          <div className="text-xs text-slate-500 mt-2">Sub-100ms detection</div>
        </div>

        <div className="bg-gradient-to-br from-slate-800 to-slate-900 border border-orange-500/30 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-400 uppercase">Threats Blocked</span>
            <span className="text-lg">🎯</span>
          </div>
          <p className="text-2xl font-bold text-orange-400">{decoyStats.blockedAttempts}</p>
          <div className="text-xs text-slate-500 mt-2">Via deception layer</div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Interaction Timeline */}
        <div className="lg:col-span-2 bg-gradient-to-br from-slate-800 to-slate-900 border border-purple-500/30 rounded-lg p-6">
          <h4 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
            <div className="w-1 h-4 bg-gradient-to-b from-purple-500 to-pink-500 rounded"></div>
            Decoy Interaction Timeline
          </h4>
          <div style={{ height: '250px' }}>
            <Line data={interactionChartData} options={{
              responsive: true,
              maintainAspectRatio: false,
              plugins: { legend: { labels: { color: '#999' } } },
              scales: {
                y: {
                  beginAtZero: true,
                  grid: { color: 'rgba(168, 85, 247, 0.1)' },
                  ticks: { color: '#999' }
                },
                x: {
                  grid: { display: false },
                  ticks: { color: '#999' }
                }
              }
            }} />
          </div>
        </div>

        {/* Attack Vectors Blocked */}
        <div className="bg-gradient-to-br from-slate-800 to-slate-900 border border-purple-500/30 rounded-lg p-6">
          <h4 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
            <div className="w-1 h-4 bg-gradient-to-b from-purple-500 to-pink-500 rounded"></div>
            Attack Vectors
          </h4>
          <div style={{ height: '250px' }}>
            <Doughnut data={attackBlockedData} options={{
              responsive: true,
              maintainAspectRatio: false,
              plugins: { legend: { position: 'bottom', labels: { color: '#999', font: { size: 10 } } } }
            }} />
          </div>
        </div>
      </div>

      {/* Decoy Type Breakdown */}
      <div className="bg-gradient-to-br from-slate-800 to-slate-900 border border-purple-500/30 rounded-lg p-6">
        <h4 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
          <div className="w-1 h-4 bg-gradient-to-b from-purple-500 to-pink-500 rounded"></div>
          Decoy Asset Types & Interactions
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div style={{ height: '250px' }}>
            <Bar data={decoyDistributionData} options={{
              indexAxis: 'y',
              responsive: true,
              maintainAspectRatio: false,
              plugins: { legend: { labels: { color: '#999' } } },
              scales: {
                x: {
                  grid: { color: 'rgba(168, 85, 247, 0.1)' },
                  ticks: { color: '#999' }
                },
                y: {
                  grid: { display: false },
                  ticks: { color: '#999' }
                }
              }
            }} />
          </div>

          <div className="space-y-3">
            {decoysByType.map((decoy, idx) => (
              <div key={idx} className="p-3 bg-slate-700/50 rounded border border-slate-600/50">
                <div className="flex justify-between items-center mb-2">
                  <span className="text-sm font-bold text-white">{decoy.type}</span>
                  <span className="text-xs bg-purple-500/30 px-2 py-1 rounded text-purple-300">{decoy.count} deployed</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 bg-slate-600 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-purple-500 to-pink-500"
                      style={{ width: `${(decoy.interactions / 234) * 100}%` }}
                    ></div>
                  </div>
                  <span className="text-xs text-slate-400">{decoy.interactions} hits</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Detection Confidence */}
      <div className="bg-gradient-to-br from-slate-800 to-slate-900 border border-purple-500/30 rounded-lg p-6">
        <h4 className="text-sm font-bold text-white mb-4">Detection Confidence Breakdown</h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <div className="flex justify-between mb-2">
              <span className="text-sm text-slate-400">True Positive Rate</span>
              <span className="font-bold text-green-400">{decoyStats.threatDetectionRate.toFixed(1)}%</span>
            </div>
            <div className="h-3 bg-slate-700 rounded-full overflow-hidden">
              <div className="h-full bg-green-500" style={{ width: `${decoyStats.threatDetectionRate}%` }}></div>
            </div>
          </div>
          <div>
            <div className="flex justify-between mb-2">
              <span className="text-sm text-slate-400">False Positive Rate</span>
              <span className="font-bold text-orange-400">{decoyStats.falsePositiveRate.toFixed(1)}%</span>
            </div>
            <div className="h-3 bg-slate-700 rounded-full overflow-hidden">
              <div className="h-full bg-orange-500" style={{ width: `${decoyStats.falsePositiveRate}%` }}></div>
            </div>
          </div>
          <div>
            <div className="flex justify-between mb-2">
              <span className="text-sm text-slate-400">Precision Score</span>
              <span className="font-bold text-purple-400">{(100 - decoyStats.falsePositiveRate).toFixed(1)}%</span>
            </div>
            <div className="h-3 bg-slate-700 rounded-full overflow-hidden">
              <div className="h-full bg-gradient-to-r from-purple-500 to-pink-500" style={{ width: `${100 - decoyStats.falsePositiveRate}%` }}></div>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
};

export default DeceptionMetricsWidget;
