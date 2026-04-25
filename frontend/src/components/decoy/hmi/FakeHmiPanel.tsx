import React from 'react';
import type { FakeHmiInstance, HmiMetric } from '../../../services/fakeHmiService';
import { HmiBezel, HmiGauge, HmiTank, HmiLinearMeter, HmiDigital, HmiAlarmStrip, HmiLed } from './HmiWidgets';

/**
 * FakeHmiPanel - renders a convincing HMI mockup for a given fake-HMI instance.
 * Visual style picked from instance.variant. Process layout informed by scenario.
 */
export const FakeHmiPanel: React.FC<{ hmi: FakeHmiInstance; compact?: boolean }> = ({ hmi, compact = false }) => {
  const variantTone =
    hmi.variant === 'SIEMENS' ? 'siemens' :
    hmi.variant === 'ROCKWELL' ? 'rockwell' :
    hmi.variant === 'SCHNEIDER' ? 'schneider' :
    'generic';

  const accent =
    hmi.variant === 'SIEMENS' ? '#009999' :
    hmi.variant === 'ROCKWELL' ? '#cc0000' :
    hmi.variant === 'SCHNEIDER' ? '#3dcd58' :
    '#6366f1';

  const logo = <VariantLogo variant={hmi.variant} />;

  return (
    <HmiBezel
      tone={variantTone as any}
      title={`${hmi.vendor} - ${hmi.model}`}
      subtitle={`${hmi.name} · ${hmi.ipAddress}:${hmi.port} · FW ${hmi.firmware}`}
      logo={logo}
    >
      {hmi.scenario === 'WATER_TREATMENT' && <WaterTreatmentLayout hmi={hmi} accent={accent} compact={compact} />}
      {hmi.scenario === 'SUBSTATION' && <SubstationLayout hmi={hmi} accent={accent} compact={compact} />}
      {hmi.scenario === 'OIL_GAS' && <OilGasLayout hmi={hmi} accent={accent} compact={compact} />}
      {hmi.scenario === 'MANUFACTURING' && <ManufacturingLayout hmi={hmi} accent={accent} compact={compact} />}
    </HmiBezel>
  );
};

// ============================================================
// Per-variant branded logo
// ============================================================
const VariantLogo: React.FC<{ variant: FakeHmiInstance['variant'] }> = ({ variant }) => {
  if (variant === 'SIEMENS') return (
    <div className="px-2 py-0.5 bg-white/10 ring-1 ring-white/30 rounded text-[10px] font-black tracking-[0.25em]">
      SIEMENS
    </div>
  );
  if (variant === 'ROCKWELL') return (
    <div className="px-2 py-0.5 bg-white/10 ring-1 ring-white/30 rounded text-[10px] font-black tracking-wider italic">
      Rockwell
    </div>
  );
  if (variant === 'SCHNEIDER') return (
    <div className="flex items-center gap-1">
      <span className="w-4 h-4 rounded-sm bg-white/20 ring-1 ring-white/40 flex items-center justify-center text-[9px] font-black">SE</span>
      <span className="text-[9.5px] font-bold tracking-wide">Schneider</span>
    </div>
  );
  return (
    <div className="px-2 py-0.5 bg-white/10 ring-1 ring-white/30 rounded text-[10px] font-black font-mono tracking-widest">
      SCADA
    </div>
  );
};

// ============================================================
// Scenario 1 - WATER TREATMENT
// ============================================================
const WaterTreatmentLayout: React.FC<{ hmi: FakeHmiInstance; accent: string; compact: boolean }> = ({ hmi, accent, compact }) => {
  const m = byKey(hmi.metrics);
  return (
    <div className="space-y-3">
      {/* Process flow: tank → filter → tank */}
      <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3">
        <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Process Flow - Raw → Filter → Clearwell</div>
        <div className="grid grid-cols-5 gap-2 items-end">
          {m.tank1_level && <div className="flex flex-col items-center"><div className="text-[9px] text-slate-500 mb-1">Raw</div><HmiTank metric={m.tank1_level} accent={accent} /></div>}
          <PipeArrow accent={accent} label={m.flow_in?.value ? `${m.flow_in.value} m³/h` : ''} />
          {m.filter_dp && <div className="flex flex-col items-center"><div className="text-[9px] text-slate-500 mb-1">Filter</div><HmiGauge metric={m.filter_dp} accent={accent} /></div>}
          <PipeArrow accent={accent} label={m.flow_out?.value ? `${m.flow_out.value} m³/h` : ''} />
          {m.tank2_level && <div className="flex flex-col items-center"><div className="text-[9px] text-slate-500 mb-1">Clearwell</div><HmiTank metric={m.tank2_level} accent={accent} /></div>}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3 space-y-2">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Chemistry</div>
          {m.chlorine_ppm && <HmiLinearMeter metric={m.chlorine_ppm} accent={accent} />}
          {m.ph && <HmiLinearMeter metric={m.ph} accent={accent} />}
          {m.turbidity && <HmiLinearMeter metric={m.turbidity} accent={accent} />}
        </div>
        <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Pumps</div>
          <div className="grid grid-cols-2 gap-2">
            {m.pump1_rpm && <HmiDigital metric={m.pump1_rpm} accent={accent} />}
            {m.pump2_rpm && <HmiDigital metric={m.pump2_rpm} accent={accent} />}
          </div>
          <div className="mt-2 flex items-center gap-3">
            <HmiLed value={m.pump1_rpm?.value ?? 0} label="P-1 Run" />
            <HmiLed value={m.pump2_rpm?.value ?? 0} label="P-2 Run" />
          </div>
        </div>
      </div>

      {!compact && <HmiAlarmStrip alarms={hmi.alarms} />}
    </div>
  );
};

// ============================================================
// Scenario 2 - SUBSTATION
// ============================================================
const SubstationLayout: React.FC<{ hmi: FakeHmiInstance; accent: string; compact: boolean }> = ({ hmi, accent, compact }) => {
  const m = byKey(hmi.metrics);
  return (
    <div className="space-y-3">
      {/* Single-line bus diagram */}
      <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3">
        <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-2">33 kV Bus - Single-Line</div>
        <svg viewBox="0 0 400 70" className="w-full">
          {/* Bus bar */}
          <line x1="30" y1="30" x2="370" y2="30" stroke="#0f172a" strokeWidth="3" />
          {[80, 160, 240, 320].map((x, i) => (
            <g key={i}>
              <line x1={x} y1="30" x2={x} y2="55" stroke="#0f172a" strokeWidth="2" />
              <rect x={x - 6} y="55" width="12" height="8" fill={m.breaker_1?.value === 1 ? '#10b981' : '#ef4444'} />
              <text x={x} y="72" fontSize="8" textAnchor="middle" fill="#334155" fontFamily="monospace">CB-{101 + i}</text>
            </g>
          ))}
          {/* Incoming line */}
          <line x1="200" y1="5" x2="200" y2="30" stroke="#0f172a" strokeWidth="3" />
          <text x="210" y="12" fontSize="8" fill="#334155">132 kV</text>
        </svg>
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3 space-y-2">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Phase Voltage</div>
          {m.v_l1 && <HmiDigital metric={m.v_l1} accent={accent} />}
          {m.v_l2 && <HmiDigital metric={m.v_l2} accent={accent} />}
          {m.v_l3 && <HmiDigital metric={m.v_l3} accent={accent} />}
        </div>
        <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3 space-y-2">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Phase Current</div>
          {m.i_l1 && <HmiLinearMeter metric={m.i_l1} accent={accent} />}
          {m.i_l2 && <HmiLinearMeter metric={m.i_l2} accent={accent} />}
          {m.i_l3 && <HmiLinearMeter metric={m.i_l3} accent={accent} />}
        </div>
        <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3 space-y-2">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Assets</div>
          {m.freq && <HmiGauge metric={m.freq} accent={accent} />}
          {m.trafo_oil_temp && <HmiLinearMeter metric={m.trafo_oil_temp} accent={accent} />}
          {m.sf6_pressure && <HmiLinearMeter metric={m.sf6_pressure} accent={accent} />}
        </div>
      </div>

      {!compact && <HmiAlarmStrip alarms={hmi.alarms} />}
    </div>
  );
};

// ============================================================
// Scenario 3 - OIL & GAS
// ============================================================
const OilGasLayout: React.FC<{ hmi: FakeHmiInstance; accent: string; compact: boolean }> = ({ hmi, accent, compact }) => {
  const m = byKey(hmi.metrics);
  return (
    <div className="space-y-3">
      <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3">
        <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Pipeline Segments - Pressure Profile</div>
        <div className="grid grid-cols-3 gap-2">
          {m.pipe_p1 && <HmiGauge metric={m.pipe_p1} accent={accent} />}
          {m.pipe_p2 && <HmiGauge metric={m.pipe_p2} accent={accent} />}
          {m.pipe_p3 && <HmiGauge metric={m.pipe_p3} accent={accent} />}
        </div>
        <div className="mt-2 grid grid-cols-5 items-center gap-1">
          <span className="text-[9px] text-slate-500 text-center">P1</span>
          <PipeArrow accent={accent} label="" />
          <span className="text-[9px] text-slate-500 text-center">P2</span>
          <PipeArrow accent={accent} label="" />
          <span className="text-[9px] text-slate-500 text-center">P3</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3 space-y-2">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Valves & Safety</div>
          <div className="grid grid-cols-2 gap-2">
            <div className="flex items-center gap-2 p-2 bg-slate-50 rounded ring-1 ring-slate-200">
              <HmiLed value={m.valve_1?.value ?? 0} label="V-101 Open" on="bg-emerald-500" off="bg-rose-500" />
            </div>
            <div className="flex items-center gap-2 p-2 bg-slate-50 rounded ring-1 ring-slate-200">
              <HmiLed value={m.valve_2?.value ?? 0} label="V-204 Open" on="bg-emerald-500" off="bg-rose-500" />
            </div>
          </div>
          {m.lel && <HmiLinearMeter metric={m.lel} accent={accent} />}
        </div>
        <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3 space-y-2">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Flows & Storage</div>
          {m.pump_a && <HmiLinearMeter metric={m.pump_a} accent={accent} />}
          {m.pump_b && <HmiLinearMeter metric={m.pump_b} accent={accent} />}
          <div className="grid grid-cols-2 gap-2 pt-1">
            {m.tank_t1 && <HmiTank metric={m.tank_t1} accent={accent} />}
            {m.tank_t2 && <HmiTank metric={m.tank_t2} accent={accent} />}
          </div>
        </div>
      </div>

      {!compact && <HmiAlarmStrip alarms={hmi.alarms} />}
    </div>
  );
};

// ============================================================
// Scenario 4 - MANUFACTURING
// ============================================================
const ManufacturingLayout: React.FC<{ hmi: FakeHmiInstance; accent: string; compact: boolean }> = ({ hmi, accent, compact }) => {
  const m = byKey(hmi.metrics);
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3 col-span-2 space-y-2">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Production Line</div>
          <div className="grid grid-cols-2 gap-2">
            {m.conveyor_rpm && <HmiDigital metric={m.conveyor_rpm} accent={accent} />}
            {m.robot_cyc && <HmiDigital metric={m.robot_cyc} accent={accent} />}
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="bg-slate-50 rounded p-2 ring-1 ring-slate-200">
              <div className="text-[9px] text-emerald-700 font-bold">GOOD</div>
              <div className="text-xl font-bold font-mono tabular-nums text-emerald-700">{m.good_count?.value ?? 0}</div>
            </div>
            <div className="bg-slate-50 rounded p-2 ring-1 ring-slate-200">
              <div className="text-[9px] text-rose-700 font-bold">REJECT</div>
              <div className="text-xl font-bold font-mono tabular-nums text-rose-700">{m.reject_count?.value ?? 0}</div>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3 flex flex-col items-center justify-center">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">OEE</div>
          {m.oee && <HmiGauge metric={m.oee} accent={accent} />}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3 space-y-2">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Stations</div>
          {m.press_p1 && <HmiLinearMeter metric={m.press_p1} accent={accent} />}
          {m.press_p2 && <HmiLinearMeter metric={m.press_p2} accent={accent} />}
          {m.temp_weld && <HmiLinearMeter metric={m.temp_weld} accent={accent} />}
        </div>
        <div className="bg-white rounded-lg ring-1 ring-slate-200 p-3 space-y-2">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Utilities</div>
          {m.lube_psi && <HmiLinearMeter metric={m.lube_psi} accent={accent} />}
          {m.air_psi && <HmiLinearMeter metric={m.air_psi} accent={accent} />}
        </div>
      </div>

      {!compact && <HmiAlarmStrip alarms={hmi.alarms} />}
    </div>
  );
};

// ============================================================
// Helpers
// ============================================================
function byKey(metrics: HmiMetric[]): Record<string, HmiMetric> {
  const out: Record<string, HmiMetric> = {};
  for (const m of metrics) out[m.key] = m;
  return out;
}

const PipeArrow: React.FC<{ accent: string; label: string }> = ({ accent, label }) => (
  <div className="flex flex-col items-center">
    <svg viewBox="0 0 40 20" className="w-full h-5">
      <line x1="0" y1="10" x2="32" y2="10" stroke={accent} strokeWidth="4" strokeLinecap="round" />
      <polygon points="32,4 40,10 32,16" fill={accent} />
    </svg>
    {label && <span className="text-[9px] font-mono text-slate-500 mt-0.5">{label}</span>}
  </div>
);

export default FakeHmiPanel;
