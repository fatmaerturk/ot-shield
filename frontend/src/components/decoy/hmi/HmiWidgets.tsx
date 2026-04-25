import React from 'react';
import type { HmiAlarm, HmiMetric } from '../../../services/fakeHmiService';

// ---------- Gauge (semi-circle) ----------
export const HmiGauge: React.FC<{ metric: HmiMetric; accent: string }> = ({ metric, accent }) => {
  const pct = Math.max(0, Math.min(1, (metric.value - metric.min) / Math.max(0.0001, metric.max - metric.min)));
  const angle = -90 + pct * 180; // -90 to 90
  const rad = (angle * Math.PI) / 180;
  const cx = 50, cy = 55, r = 38;
  const nx = cx + r * Math.cos(rad);
  const ny = cy + r * Math.sin(rad);
  return (
    <div className="relative">
      <svg viewBox="0 0 100 70" className="w-full h-20">
        <path d="M 12 55 A 38 38 0 0 1 88 55" stroke="#e2e8f0" strokeWidth="6" fill="none" strokeLinecap="round" />
        <path
          d="M 12 55 A 38 38 0 0 1 88 55"
          stroke={metric.alarming ? '#ef4444' : accent}
          strokeWidth="6"
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${pct * 119.4} 200`}
        />
        <line x1={cx} y1={cy} x2={nx} y2={ny} stroke="#0f172a" strokeWidth="2" strokeLinecap="round" />
        <circle cx={cx} cy={cy} r="3" fill="#0f172a" />
      </svg>
      <div className="absolute inset-x-0 bottom-0 text-center">
        <div className={`text-sm font-bold font-mono ${metric.alarming ? 'text-rose-600' : 'text-slate-900'}`}>
          {metric.value}<span className="text-[9px] ml-0.5 text-slate-500">{metric.unit}</span>
        </div>
      </div>
    </div>
  );
};

// ---------- Vertical tank ----------
export const HmiTank: React.FC<{ metric: HmiMetric; accent: string }> = ({ metric, accent }) => {
  const pct = Math.max(0, Math.min(100, ((metric.value - metric.min) / Math.max(0.001, metric.max - metric.min)) * 100));
  return (
    <div className="flex flex-col items-center gap-1">
      <div className="w-12 h-24 rounded-lg ring-2 ring-slate-300 bg-slate-50 relative overflow-hidden">
        <div
          className={`absolute left-0 right-0 bottom-0 ${metric.alarming ? 'bg-gradient-to-t from-rose-500 to-rose-300' : ''}`}
          style={{
            height: `${pct}%`,
            background: metric.alarming ? undefined : `linear-gradient(to top, ${accent}, ${accent}80)`,
          }}
        />
        {/* Tick marks */}
        {[25, 50, 75].map(t => (
          <div key={t} className="absolute left-0 right-0 border-t border-slate-200" style={{ bottom: `${t}%` }} />
        ))}
      </div>
      <div className={`text-xs font-mono font-bold ${metric.alarming ? 'text-rose-600' : 'text-slate-900'}`}>
        {metric.value}{metric.unit}
      </div>
    </div>
  );
};

// ---------- Linear meter (horizontal bar) ----------
export const HmiLinearMeter: React.FC<{ metric: HmiMetric; accent: string }> = ({ metric, accent }) => {
  const pct = Math.max(0, Math.min(100, ((metric.value - metric.min) / Math.max(0.001, metric.max - metric.min)) * 100));
  return (
    <div>
      <div className="flex items-baseline justify-between mb-1">
        <span className="text-[10.5px] font-semibold text-slate-600 truncate">{metric.name}</span>
        <span className={`text-xs font-mono font-bold tabular-nums ${metric.alarming ? 'text-rose-600' : 'text-slate-900'}`}>
          {metric.value}<span className="text-[9px] ml-0.5 text-slate-500">{metric.unit}</span>
        </span>
      </div>
      <div className="h-2 rounded-full bg-slate-100 ring-1 ring-slate-200 overflow-hidden">
        <div
          className="h-full transition-all duration-500 ease-out"
          style={{
            width: `${pct}%`,
            background: metric.alarming
              ? 'linear-gradient(to right, #f43f5e, #ef4444)'
              : `linear-gradient(to right, ${accent}80, ${accent})`,
          }}
        />
      </div>
      <div className="mt-0.5 flex justify-between text-[9px] text-slate-400 font-mono">
        <span>{metric.min}</span>
        <span>{metric.max}</span>
      </div>
    </div>
  );
};

// ---------- Digital display (big number) ----------
export const HmiDigital: React.FC<{ metric: HmiMetric; accent: string }> = ({ metric, accent }) => (
  <div className="bg-slate-900 rounded-lg p-2 ring-1 ring-slate-800 relative overflow-hidden">
    <div className="absolute inset-0 opacity-5" style={{
      backgroundImage: 'repeating-linear-gradient(0deg, transparent 0, transparent 2px, #fff 2px, #fff 3px)'
    }} />
    <div className="relative">
      <div className="text-[9px] uppercase tracking-wider text-slate-400">{metric.name}</div>
      <div className={`text-2xl font-bold font-mono tabular-nums ${metric.alarming ? 'text-rose-400' : ''}`}
           style={{ color: metric.alarming ? undefined : accent }}>
        {metric.value}
        <span className="text-xs ml-1 opacity-60">{metric.unit}</span>
      </div>
    </div>
  </div>
);

// ---------- Alarm strip ----------
export const HmiAlarmStrip: React.FC<{ alarms: HmiAlarm[]; maxRows?: number }> = ({ alarms, maxRows = 5 }) => {
  const sevTone = (s: HmiAlarm['severity']) =>
    s === 'CRITICAL' ? 'bg-rose-600 text-white' :
    s === 'HIGH' ? 'bg-orange-500 text-white' :
    s === 'MEDIUM' ? 'bg-amber-400 text-amber-950' :
    'bg-slate-300 text-slate-800';
  const rows = alarms.slice(0, maxRows);
  return (
    <div className="rounded-lg ring-1 ring-slate-200 overflow-hidden bg-white">
      <div className="bg-slate-900 text-white text-[10px] uppercase tracking-wider px-2 py-1 flex items-center justify-between">
        <span>Alarm Summary</span>
        <span className="text-slate-400">{alarms.filter(a => !a.acknowledged).length} active</span>
      </div>
      <div className="divide-y divide-slate-100">
        {rows.length === 0 && (
          <div className="px-2 py-3 text-[11px] text-slate-400 text-center">No alarms</div>
        )}
        {rows.map(a => (
          <div key={a.id} className="flex items-center gap-2 px-2 py-1.5">
            <span className={`inline-block text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${sevTone(a.severity)}`}>
              {a.severity}
            </span>
            <span className="text-[11px] text-slate-700 flex-1 truncate" title={a.message}>{a.message}</span>
            <span className="text-[9px] font-mono text-slate-400">
              {new Date(a.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
            </span>
            {a.acknowledged && (
              <span className="text-[9px] text-emerald-600 font-bold">ACK</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

// ---------- Status dot for running/stopped/etc ----------
export const HmiLed: React.FC<{ value: number; label: string; on?: string; off?: string }> = ({
  value, label, on = 'bg-emerald-500', off = 'bg-slate-300'
}) => (
  <div className="flex items-center gap-1.5">
    <span className={`w-2.5 h-2.5 rounded-full ${value > 0 ? on : off} ${value > 0 ? 'animate-pulse' : ''} ring-2 ring-white shadow`} />
    <span className="text-[10px] font-semibold text-slate-600">{label}</span>
  </div>
);

// ---------- HMI screen bezel chrome (variant frame wrapper) ----------
export const HmiBezel: React.FC<{
  tone: 'siemens' | 'rockwell' | 'schneider' | 'generic';
  title: string;
  subtitle?: string;
  logo?: React.ReactNode;
  children: React.ReactNode;
}> = ({ tone, title, subtitle, logo, children }) => {
  const chromes = {
    siemens:   { bar: 'from-teal-700 to-teal-900', accent: '#009999', bg: 'bg-slate-100', font: 'font-sans' },
    rockwell:  { bar: 'from-red-700 to-red-900',   accent: '#cc0000', bg: 'bg-zinc-100', font: 'font-sans' },
    schneider: { bar: 'from-emerald-700 to-emerald-900', accent: '#3dcd58', bg: 'bg-slate-50', font: 'font-sans' },
    generic:   { bar: 'from-slate-700 to-slate-900', accent: '#334155', bg: 'bg-slate-100', font: 'font-mono' },
  }[tone];
  return (
    <div className={`rounded-xl ring-2 ring-slate-800 shadow-2xl overflow-hidden ${chromes.bg} ${chromes.font}`}>
      <div className={`bg-gradient-to-r ${chromes.bar} text-white px-3 py-2 flex items-center gap-3`}>
        {logo}
        <div className="flex-1 min-w-0">
          <div className="text-[11px] font-bold uppercase tracking-wider truncate">{title}</div>
          {subtitle && <div className="text-[9.5px] text-white/70 truncate">{subtitle}</div>}
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-red-400" />
          <span className="w-2 h-2 rounded-full bg-amber-400" />
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        </div>
      </div>
      <div className="p-3">{children}</div>
    </div>
  );
};
