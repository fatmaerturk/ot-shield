import React from 'react';
import { AssetDTO } from '../../services/assetService';

/**
 * Modern, flat, industrial device icons for the asset inventory. Picks an icon
 * from the asset's role (type / protocol / Purdue level) so an OT device reads
 * as an industrial controller, not a desktop. Pure inline SVG - no image files.
 */

type Cat = 'controller' | 'hmi' | 'scada' | 'network' | 'sensor' | 'workstation';

const categoryOf = (a?: AssetDTO): Cat => {
  const t = (a?.assetType || '').toLowerCase();
  const name = (a?.name || '').toLowerCase();
  const proto = (a?.protocol || '').toLowerCase();
  if (t.includes('hmi')) return 'hmi';
  if (t.includes('scada') || t.includes('historian') || t.includes('server')) return 'scada';
  if (t.includes('router') || t.includes('switch') || t.includes('firewall') || t.includes('ids')
      || name.includes('router') || name.includes('switch') || name.includes('firewall')) return 'network';
  if (a?.purdueLevel === 'LEVEL_0' || t.includes('sensor') || t.includes('actuator')) return 'sensor';
  if (t.includes('workstation') || t.includes('endpoint')) return 'workstation';
  if (t.includes('plc') || t.includes('rtu') || proto) return 'controller';
  // Default: assets discovered on the OT wire are field controllers, not PCs.
  return 'controller';
};

const PAL: Record<Cat, { bg: string; fg: string; ac: string }> = {
  controller: { bg: '#EAEDFB', fg: '#4338CA', ac: '#A5B4FC' },
  hmi: { bg: '#DFF4EC', fg: '#0E7C5E', ac: '#6EE7B7' },
  scada: { bg: '#F1EAFC', fg: '#6D28D9', ac: '#C4B5FD' },
  network: { bg: '#E3EFFB', fg: '#1D4ED8', ac: '#93C5FD' },
  sensor: { bg: '#FBEFD8', fg: '#B45309', ac: '#FBBF24' },
  workstation: { bg: '#ECEEF2', fg: '#475569', ac: '#CBD5E1' },
};

const Glyph: React.FC<{ cat: Cat; fg: string; ac: string }> = ({ cat, fg, ac }) => {
  switch (cat) {
    case 'controller':
      return (
        <>
          <rect x="4" y="4.2" width="1.7" height="3" rx="0.85" fill={ac} />
          <rect x="7.4" y="4.2" width="1.7" height="3" rx="0.85" fill={ac} />
          <rect x="14.9" y="4.2" width="1.7" height="3" rx="0.85" fill={ac} />
          <rect x="18.3" y="4.2" width="1.7" height="3" rx="0.85" fill={ac} />
          <rect x="3" y="7" width="18" height="12.5" rx="2.4" fill={fg} />
          <circle cx="6.6" cy="11.2" r="1.15" fill={ac} />
          <rect x="9.6" y="10.1" width="8.4" height="1.9" rx="0.95" fill={ac} />
          <rect x="9.6" y="14" width="8.4" height="1.9" rx="0.95" fill={ac} opacity="0.55" />
        </>
      );
    case 'hmi':
      return (
        <>
          <rect x="2.6" y="3.4" width="18.8" height="13.6" rx="2.4" fill={fg} />
          <rect x="4.9" y="5.6" width="14.2" height="6.6" rx="1.2" fill={ac} />
          <circle cx="7.4" cy="14.6" r="0.95" fill={ac} />
          <circle cx="12" cy="14.6" r="0.95" fill={ac} />
          <circle cx="16.6" cy="14.6" r="0.95" fill={ac} />
          <rect x="8.6" y="17.4" width="6.8" height="3.2" rx="1.2" fill={fg} />
        </>
      );
    case 'scada':
      return (
        <>
          <rect x="4" y="2.8" width="16" height="18.4" rx="2.4" fill={fg} />
          <rect x="6.1" y="5.2" width="11.8" height="3.4" rx="1.1" fill={ac} />
          <rect x="6.1" y="10.3" width="11.8" height="3.4" rx="1.1" fill={ac} />
          <rect x="6.1" y="15.4" width="11.8" height="3.4" rx="1.1" fill={ac} opacity="0.55" />
          <circle cx="8.1" cy="6.9" r="0.75" fill={fg} />
          <circle cx="8.1" cy="12" r="0.75" fill={fg} />
        </>
      );
    case 'network':
      return (
        <>
          <rect x="2.6" y="7" width="18.8" height="10" rx="2.4" fill={fg} />
          <circle cx="6.2" cy="10.2" r="1" fill={ac} />
          <circle cx="9.4" cy="10.2" r="1" fill={ac} opacity="0.6" />
          {[5, 7.9, 10.8, 13.7, 16.6].map((x) => (
            <rect key={x} x={x} y="13.4" width="2.1" height="2.2" rx="0.5" fill={ac} />
          ))}
        </>
      );
    case 'sensor':
      return (
        <>
          <circle cx="12" cy="12" r="9" fill={fg} />
          <circle cx="12" cy="12" r="6.2" fill={ac} />
          <path d="M12 12 L15.4 8.2" stroke={fg} strokeWidth="1.7" strokeLinecap="round" />
          <circle cx="12" cy="12" r="1.6" fill={fg} />
        </>
      );
    case 'workstation':
      return (
        <>
          <rect x="2.8" y="3.6" width="18.4" height="12.4" rx="2.2" fill={fg} />
          <rect x="5" y="5.8" width="14" height="8" rx="1.1" fill={ac} />
          <rect x="9.6" y="16" width="4.8" height="2.4" fill={fg} />
          <rect x="6.8" y="18.2" width="10.4" height="1.9" rx="0.95" fill={fg} />
        </>
      );
  }
};

const AssetIcon: React.FC<{ asset?: AssetDTO; className?: string }> = ({ asset, className = 'w-12 h-12' }) => {
  const cat = categoryOf(asset);
  const p = PAL[cat];
  return (
    <div
      className={`${className} rounded-xl flex items-center justify-center shrink-0 ring-1 ring-black/5`}
      style={{ background: p.bg }}
    >
      <svg viewBox="0 0 24 24" width="62%" height="62%" fill="none" aria-hidden="true">
        <Glyph cat={cat} fg={p.fg} ac={p.ac} />
      </svg>
    </div>
  );
};

export default AssetIcon;
