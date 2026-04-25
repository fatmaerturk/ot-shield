/**
 * Inline SVG icons for OT/IT asset types. Each entry is a fragment that lives
 * inside a 48x48 viewBox. Styles live on the wrapping <g> in makeIconDataUri
 * so all icons look consistent (dark stroke, rounded joins).
 *
 * These get rendered by vis-network via its `circularImage` shape - the image
 * fills the node circle and the severity-colored ring is drawn on top.
 */

export type AssetIconKey =
  | 'PLC'
  | 'RTU'
  | 'SENSOR'
  | 'HMI'
  | 'SCADA'
  | 'HISTORIAN'
  | 'FIREWALL'
  | 'ROUTER'
  | 'SERVER'
  | 'WORKSTATION'
  | 'CAMERA'
  | 'IOT'
  | 'ACTUATOR'
  | 'UNKNOWN'
  | 'DEFAULT';

// Icon paths. Stroke/fill defaults come from the parent <g>.
const ICON_PATHS: Record<AssetIconKey, string> = {
  // --- Controllers ----------------------------------------------------------
  PLC: `
    <rect x="13" y="13" width="22" height="22" rx="2" fill="#E5E7EB" stroke="#1F2937"/>
    <rect x="18" y="18" width="12" height="12" fill="#6B7280"/>
    <line x1="10" y1="18" x2="13" y2="18"/>
    <line x1="10" y1="24" x2="13" y2="24"/>
    <line x1="10" y1="30" x2="13" y2="30"/>
    <line x1="35" y1="18" x2="38" y2="18"/>
    <line x1="35" y1="24" x2="38" y2="24"/>
    <line x1="35" y1="30" x2="38" y2="30"/>
    <line x1="18" y1="10" x2="18" y2="13"/>
    <line x1="24" y1="10" x2="24" y2="13"/>
    <line x1="30" y1="10" x2="30" y2="13"/>
    <line x1="18" y1="35" x2="18" y2="38"/>
    <line x1="24" y1="35" x2="24" y2="38"/>
    <line x1="30" y1="35" x2="30" y2="38"/>
  `,

  RTU: `
    <rect x="11" y="16" width="26" height="22" rx="2" fill="#E5E7EB" stroke="#1F2937"/>
    <line x1="24" y1="16" x2="24" y2="7"/>
    <path d="M18 10 a6 6 0 0 1 12 0" fill="none"/>
    <path d="M21 12 a3 3 0 0 1 6 0" fill="none"/>
    <circle cx="17" cy="23" r="1.5" fill="#1F2937" stroke="none"/>
    <circle cx="24" cy="23" r="1.5" fill="#1F2937" stroke="none"/>
    <circle cx="31" cy="23" r="1.5" fill="#1F2937" stroke="none"/>
    <rect x="15" y="30" width="18" height="4" rx="1" fill="none"/>
  `,

  // --- Field / sensors / actuators -----------------------------------------
  SENSOR: `
    <circle cx="24" cy="24" r="3" fill="#1F2937" stroke="none"/>
    <path d="M16 24 a8 8 0 0 1 16 0" fill="none"/>
    <path d="M11 24 a13 13 0 0 1 26 0" fill="none"/>
    <path d="M6 24 a18 18 0 0 1 36 0" fill="none" stroke-dasharray="2,2"/>
    <line x1="24" y1="27" x2="24" y2="40"/>
    <line x1="20" y1="40" x2="28" y2="40"/>
  `,

  ACTUATOR: `
    <circle cx="24" cy="18" r="9" fill="none"/>
    <line x1="24" y1="9" x2="24" y2="27"/>
    <line x1="15" y1="18" x2="33" y2="18"/>
    <rect x="20" y="27" width="8" height="12" rx="1" fill="#E5E7EB"/>
    <line x1="18" y1="39" x2="30" y2="39"/>
  `,

  // --- Supervisory & operations --------------------------------------------
  HMI: `
    <rect x="7" y="11" width="34" height="22" rx="2" fill="#E5E7EB" stroke="#1F2937"/>
    <line x1="12" y1="17" x2="36" y2="17"/>
    <line x1="12" y1="22" x2="28" y2="22"/>
    <line x1="12" y1="27" x2="32" y2="27"/>
    <line x1="17" y1="39" x2="31" y2="39"/>
    <line x1="24" y1="33" x2="24" y2="39"/>
    <circle cx="34" cy="15" r="1" fill="#16A34A" stroke="none"/>
  `,

  SCADA: `
    <rect x="8" y="7" width="32" height="18" rx="2" fill="#E5E7EB" stroke="#1F2937"/>
    <circle cx="14" cy="12" r="1" fill="#1F2937" stroke="none"/>
    <path d="M13 20 L17 16 L21 19 L27 13 L31 17 L35 15" fill="none"/>
    <rect x="12" y="30" width="24" height="10" rx="1" fill="#E5E7EB" stroke="#1F2937"/>
    <circle cx="16" cy="35" r="1" fill="#16A34A" stroke="none"/>
    <circle cx="20" cy="35" r="1" fill="#EAB308" stroke="none"/>
    <line x1="25" y1="35" x2="33" y2="35"/>
  `,

  HISTORIAN: `
    <ellipse cx="24" cy="11" rx="12" ry="4" fill="#E5E7EB" stroke="#1F2937"/>
    <path d="M12 11 v26 a12 4 0 0 0 24 0 v-26" fill="#E5E7EB" stroke="#1F2937"/>
    <path d="M12 20 a12 4 0 0 0 24 0" fill="none" stroke-dasharray="2,2"/>
    <path d="M12 28 a12 4 0 0 0 24 0" fill="none" stroke-dasharray="2,2"/>
  `,

  // --- Network & security --------------------------------------------------
  FIREWALL: `
    <path d="M24 6 L38 11 V23 C38 31 24 42 24 42 C24 42 10 31 10 23 V11 Z" fill="#E5E7EB" stroke="#1F2937"/>
    <path d="M24 14 L28 22 L24 20 L20 22 Z" fill="#DC2626" stroke="none"/>
    <line x1="14" y1="18" x2="18" y2="18" stroke-dasharray="2,2"/>
    <line x1="30" y1="18" x2="34" y2="18" stroke-dasharray="2,2"/>
  `,

  ROUTER: `
    <rect x="7" y="18" width="34" height="14" rx="2" fill="#E5E7EB" stroke="#1F2937"/>
    <circle cx="13" cy="25" r="1" fill="#16A34A" stroke="none"/>
    <circle cx="18" cy="25" r="1" fill="#EAB308" stroke="none"/>
    <circle cx="23" cy="25" r="1" fill="#16A34A" stroke="none"/>
    <path d="M14 18 L14 11 L24 5 L34 11 L34 18" fill="none"/>
    <line x1="30" y1="32" x2="30" y2="38"/>
    <line x1="18" y1="32" x2="18" y2="38"/>
    <line x1="24" y1="32" x2="24" y2="38"/>
  `,

  // --- Servers & workstations ----------------------------------------------
  SERVER: `
    <rect x="10" y="8" width="28" height="10" rx="1" fill="#E5E7EB" stroke="#1F2937"/>
    <rect x="10" y="19" width="28" height="10" rx="1" fill="#E5E7EB" stroke="#1F2937"/>
    <rect x="10" y="30" width="28" height="10" rx="1" fill="#E5E7EB" stroke="#1F2937"/>
    <circle cx="14" cy="13" r="1" fill="#16A34A" stroke="none"/>
    <circle cx="14" cy="24" r="1" fill="#16A34A" stroke="none"/>
    <circle cx="14" cy="35" r="1" fill="#16A34A" stroke="none"/>
    <line x1="20" y1="13" x2="34" y2="13"/>
    <line x1="20" y1="24" x2="34" y2="24"/>
    <line x1="20" y1="35" x2="34" y2="35"/>
  `,

  WORKSTATION: `
    <rect x="6" y="9" width="36" height="24" rx="2" fill="#E5E7EB" stroke="#1F2937"/>
    <rect x="10" y="13" width="28" height="16" fill="#CBD5E1" stroke="none"/>
    <rect x="18" y="33" width="12" height="5" fill="none"/>
    <line x1="13" y1="41" x2="35" y2="41"/>
  `,

  CAMERA: `
    <rect x="8" y="14" width="22" height="20" rx="2" fill="#E5E7EB" stroke="#1F2937"/>
    <circle cx="19" cy="24" r="5" fill="none"/>
    <circle cx="19" cy="24" r="2" fill="#1F2937" stroke="none"/>
    <path d="M30 20 L40 16 V32 L30 28 Z" fill="#E5E7EB" stroke="#1F2937"/>
    <circle cx="26" cy="17" r="1" fill="#DC2626" stroke="none"/>
  `,

  // --- Generic / fallback --------------------------------------------------
  IOT: `
    <circle cx="24" cy="24" r="6" fill="#E5E7EB" stroke="#1F2937"/>
    <path d="M14 24 a10 10 0 0 1 20 0" fill="none"/>
    <path d="M8 24 a16 16 0 0 1 32 0" fill="none" stroke-dasharray="2,2"/>
    <circle cx="24" cy="24" r="1.5" fill="#1F2937" stroke="none"/>
  `,

  UNKNOWN: `
    <path d="M24 7 L42 39 H6 Z" fill="#FEF3C7" stroke="#1F2937" stroke-width="2.2"/>
    <line x1="24" y1="18" x2="24" y2="30" stroke-width="2.4"/>
    <circle cx="24" cy="34" r="1.6" fill="#1F2937" stroke="none"/>
  `,

  DEFAULT: `
    <rect x="10" y="10" width="28" height="28" rx="3" fill="#E5E7EB" stroke="#1F2937"/>
    <circle cx="24" cy="24" r="5" fill="#9CA3AF" stroke="none"/>
    <line x1="24" y1="14" x2="24" y2="10"/>
    <line x1="24" y1="38" x2="24" y2="34"/>
    <line x1="14" y1="24" x2="10" y2="24"/>
    <line x1="38" y1="24" x2="34" y2="24"/>
  `,
};

// A small label for the icon legend
export const ICON_LABEL: Record<AssetIconKey, string> = {
  PLC: 'PLC',
  RTU: 'RTU',
  SENSOR: 'Sensor',
  ACTUATOR: 'Actuator',
  HMI: 'HMI',
  SCADA: 'SCADA',
  HISTORIAN: 'Historian',
  FIREWALL: 'Firewall',
  ROUTER: 'Router/Switch',
  SERVER: 'Server',
  WORKSTATION: 'Workstation',
  CAMERA: 'IP Camera',
  IOT: 'IoT Device',
  UNKNOWN: 'Unknown / External',
  DEFAULT: 'Generic Device',
};

/**
 * Heuristic mapping from the backend `assetType` string to an icon key.
 * We match on substrings so minor spelling variants (e.g. "PLC Controller",
 * "Flow Sensor", "Web Server") still pick the right icon.
 */
export const detectAssetIconKey = (assetType?: string, category?: string): AssetIconKey => {
  const u = `${assetType || ''} ${category || ''}`.toUpperCase();
  if (!u.trim()) return 'DEFAULT';
  if (u.includes('PLC')) return 'PLC';
  if (u.includes('RTU')) return 'RTU';
  if (u.includes('SENSOR')) return 'SENSOR';
  if (u.includes('ACTUATOR') || u.includes('VALVE') || u.includes('MOTOR') || u.includes('PUMP')) return 'ACTUATOR';
  if (u.includes('HMI')) return 'HMI';
  if (u.includes('SCADA')) return 'SCADA';
  if (u.includes('HISTORIAN') || u.includes('DATABASE') || u.includes('DB')) return 'HISTORIAN';
  if (u.includes('FIREWALL') || u.includes('IPS') || u.includes('IDS')) return 'FIREWALL';
  if (u.includes('ROUTER') || u.includes('SWITCH') || u.includes('GATEWAY')) return 'ROUTER';
  if (u.includes('SERVER') || u.includes('ERP') || u.includes('MES')) return 'SERVER';
  if (u.includes('WORKSTATION') || u.includes('DESKTOP') || u.includes('LAPTOP') || u.includes('PC')) return 'WORKSTATION';
  if (u.includes('CAMERA') || u.includes('CCTV')) return 'CAMERA';
  if (u.includes('IOT') || u.includes('SMART')) return 'IOT';
  return 'DEFAULT';
};

/**
 * Produce a data URI for the given icon key. Caller controls the background
 * (used to indicate offline vs online).
 */
export const makeIconDataUri = (
  key: AssetIconKey,
  opts: { background?: string } = {}
): string => {
  const background = opts.background ?? '#FFFFFF';
  const path = ICON_PATHS[key] || ICON_PATHS.DEFAULT;
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="48" height="48">` +
    `<rect width="48" height="48" fill="${background}"/>` +
    `<g fill="none" stroke="#1F2937" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">` +
    path +
    `</g></svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
};
