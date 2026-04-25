import React, { useMemo } from 'react';
import { DecoyInstance, Engagement, EngagementStatus } from '../../services/decoyService';

/**
 * Facility Topology Map
 * --------------------------------------------------------------
 * Renders one card per facility (Plant-A, Plant-B, Refinery, Pharma).
 * Each card is a small Purdue-Level diagram with the facility's decoys
 * placed at their normalised (facilityX, facilityY). Decoys with an
 * active engagement pulse softly.
 *
 * Click a facility -> filter parent feed by facility (passed as decoy IDs).
 * Click a decoy    -> filter parent feed by that decoy.
 */

interface Props {
  instances: DecoyInstance[];
  engagements: Engagement[];
  selectedDecoyId?: string | null;
  onSelectDecoy?: (id: string | null) => void;
  onSelectFacility?: (facility: string | null, decoyIds: string[]) => void;
}

const PROTOCOL_COLOR: Record<string, string> = {
  MODBUS: 'fill-violet-500',
  S7: 'fill-fuchsia-500',
  DNP3: 'fill-pink-500',
  ETHERNET_IP: 'fill-rose-500',
  OPC_UA: 'fill-amber-500',
};

const PROTOCOL_LABEL: Record<string, string> = {
  MODBUS: 'Modbus',
  S7: 'S7',
  DNP3: 'DNP3',
  ETHERNET_IP: 'EN/IP',
  OPC_UA: 'OPC UA',
};

const FacilityTopologyMap: React.FC<Props> = ({
  instances, engagements, selectedDecoyId, onSelectDecoy, onSelectFacility,
}) => {
  // group decoys by facility, count active engagements per decoy
  const facilities = useMemo(() => {
    const m = new Map<string, DecoyInstance[]>();
    for (const d of instances) {
      const f = d.facility || 'Other';
      const list = m.get(f) || [];
      list.push(d);
      m.set(f, list);
    }
    return Array.from(m.entries());
  }, [instances]);

  const activeByDecoy = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of engagements) {
      if (e.status === 'ACTIVE') m.set(e.decoyInstanceId, (m.get(e.decoyInstanceId) || 0) + 1);
    }
    return m;
  }, [engagements]);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
      {facilities.map(([facility, decoys]) => {
        const facilityActive = decoys.reduce((s, d) => s + (activeByDecoy.get(d.id) || 0), 0);
        const totalEng = decoys.reduce((s, d) => s + d.totalEngagements, 0);
        return (
          <button
            key={facility}
            onClick={() => onSelectFacility?.(facility, decoys.map(d => d.id))}
            className="group text-left relative rounded-xl bg-gradient-to-br from-slate-50 to-violet-50/50 ring-1 ring-violet-100 p-3 hover:ring-violet-300 hover:shadow-md transition"
          >
            <div className="flex items-center justify-between">
              <div>
                <div className="text-[10px] uppercase tracking-wider text-violet-600 font-semibold">Facility</div>
                <div className="text-sm font-bold text-slate-900">{facility}</div>
              </div>
              <div className="text-right">
                <div className="text-[10px] text-slate-500">Active</div>
                <div className={`text-sm font-bold ${facilityActive > 0 ? 'text-rose-600' : 'text-slate-400'}`}>
                  {facilityActive}
                </div>
              </div>
            </div>

            {/* Floor plan */}
            <FacilityCanvas
              decoys={decoys}
              activeByDecoy={activeByDecoy}
              selectedDecoyId={selectedDecoyId || null}
              onSelectDecoy={onSelectDecoy}
            />

            <div className="mt-2 flex items-center justify-between text-[11px] text-slate-500">
              <span>{decoys.length} decoy{decoys.length !== 1 ? 's' : ''}</span>
              <span>{totalEng} total engagements</span>
            </div>
          </button>
        );
      })}
    </div>
  );
};

const FacilityCanvas: React.FC<{
  decoys: DecoyInstance[];
  activeByDecoy: Map<string, number>;
  selectedDecoyId: string | null;
  onSelectDecoy?: (id: string | null) => void;
}> = ({ decoys, activeByDecoy, selectedDecoyId, onSelectDecoy }) => {
  const W = 220;
  const H = 110;
  const PAD = 10;

  // Purdue level horizontal bands (visual only)
  const bands = [
    { lvl: 3, y: PAD,                label: 'L3', color: 'rgba(168,85,247,0.10)' },
    { lvl: 2, y: H / 3 + 4,          label: 'L2', color: 'rgba(217,70,239,0.10)' },
    { lvl: 1, y: (2 * H) / 3 - 6,    label: 'L1', color: 'rgba(236,72,153,0.10)' },
  ];

  return (
    <div className="mt-3 rounded-lg bg-white ring-1 ring-slate-100 overflow-hidden">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto block">
        {/* level bands */}
        {bands.map(b => (
          <g key={b.lvl}>
            <rect x={PAD} y={b.y} width={W - 2 * PAD} height={H / 3 - 6} rx={4} fill={b.color} />
            <text x={PAD + 4} y={b.y + 10} fontSize="8" fill="#7c3aed" fontWeight={700}>{b.label}</text>
          </g>
        ))}

        {/* decoys */}
        {decoys.map(d => {
          const fx = d.facilityX != null ? d.facilityX : 0.5;
          const fy = d.facilityY != null ? d.facilityY : 0.5;
          const x = PAD + fx * (W - 2 * PAD);
          const y = PAD + fy * (H - 2 * PAD);
          const active = activeByDecoy.get(d.id) || 0;
          const isSel = selectedDecoyId === d.id;
          return (
            <g
              key={d.id}
              transform={`translate(${x}, ${y})`}
              style={{ cursor: 'pointer' }}
              onClick={(e) => {
                e.stopPropagation();
                onSelectDecoy?.(isSel ? null : d.id);
              }}
            >
              {active > 0 && (
                <circle r={10} fill="#f472b6" opacity={0.25}>
                  <animate attributeName="r" from="6" to="14" dur="1.6s" repeatCount="indefinite" />
                  <animate attributeName="opacity" from="0.4" to="0" dur="1.6s" repeatCount="indefinite" />
                </circle>
              )}
              <circle
                r={isSel ? 7 : 5.5}
                className={PROTOCOL_COLOR[d.protocol] || 'fill-slate-400'}
                stroke={isSel ? '#a855f7' : '#fff'}
                strokeWidth={isSel ? 2 : 1.2}
              />
              {/* status dot */}
              <circle
                r={2}
                cx={5}
                cy={-5}
                fill={d.status === 'RUNNING' ? '#22c55e' : d.status === 'DEGRADED' ? '#f59e0b' : '#94a3b8'}
                stroke="#fff"
                strokeWidth={0.8}
              />
              <text y={-9} textAnchor="middle" fontSize="6.5" fontWeight={700} fill="#1e1b4b">
                {PROTOCOL_LABEL[d.protocol] || d.protocol}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
};

export default FacilityTopologyMap;
