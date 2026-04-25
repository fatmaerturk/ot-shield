import React from 'react';
import { PageHero, Panel, KpiCard, Icon, pageItem, pageContainer } from './theme';
import { motion } from 'framer-motion';

const Compliance: React.FC = () => {
  const rows = [
    { control: 'Asset Inventory', status: 'Pass', reviewed: '2024-05-10' },
    { control: 'Network Segmentation', status: 'Warning', reviewed: '2024-04-28' },
    { control: 'Access Control', status: 'Fail', reviewed: '2024-05-01' },
  ];

  const statusStyle = (s: string) => {
    switch (s) {
      case 'Pass':
        return 'bg-emerald-100 text-emerald-700 ring-emerald-200';
      case 'Warning':
        return 'bg-amber-100 text-amber-700 ring-amber-200';
      default:
        return 'bg-rose-100 text-rose-700 ring-rose-200';
    }
  };

  return (
    <motion.div variants={pageContainer} initial="hidden" animate="visible">
      <PageHero
        eyebrow="COMPLIANCE OVERVIEW"
        icon={<Icon.CheckCircle className="w-4 h-4" />}
        title={
          <>
            Compliance posture across OT frameworks
            <span className="block text-violet-100/90 font-medium text-lg md:text-xl mt-2">
              Track NIST CSF, IEC 62443 and internal control maturity in one place.
            </span>
          </>
        }
      />

      <motion.div variants={pageItem} className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <KpiCard
          label="Overall Score"
          value="85%"
          hint="Composite across all frameworks"
          icon={<Icon.Target className="w-5 h-5" />}
          color="violet"
          progress={85}
        />
        <KpiCard
          label="NIST CSF"
          value="90%"
          hint="Identify, Protect, Detect, Respond"
          icon={<Icon.Shield className="w-5 h-5" />}
          color="fuchsia"
          progress={90}
        />
        <KpiCard
          label="IEC 62443"
          value="75%"
          hint="2 zones below SL-2 target"
          icon={<Icon.Layers className="w-5 h-5" />}
          color="rose"
          progress={75}
        />
      </motion.div>

      <motion.div variants={pageItem}>
        <Panel
          title="Control Mapping & Gap Analysis"
          subtitle="Individual controls with status and last review date"
          icon={<Icon.CheckCircle className="w-5 h-5" />}
        >
          <div className="overflow-hidden rounded-xl ring-1 ring-slate-200/60">
            <table className="min-w-full">
              <thead className="bg-slate-50">
                <tr>
                  <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500">Control</th>
                  <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500">Status</th>
                  <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500">Last Reviewed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/60 bg-white">
                {rows.map((row, idx) => (
                  <tr key={idx} className="hover:bg-violet-50/30 transition">
                    <td className="px-4 py-3 text-sm font-medium text-slate-900">{row.control}</td>
                    <td className="px-4 py-3">
                      <span className={`text-[11px] font-bold px-2.5 py-1 rounded-full ring-1 ${statusStyle(row.status)}`}>
                        {row.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-600">{row.reviewed}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </motion.div>
    </motion.div>
  );
};

export default Compliance;
