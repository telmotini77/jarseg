// Same origin by default: nginx proxies the API, so the dashboard works from any browser.
export const API = import.meta.env.VITE_CYBERSEG_API_URL || '';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type Alert = {
  id: string; timestamp: string; sourceIp: string; destinationIp: string; risk: Severity; description: string; score: number;
  category: string; ruleId: string; mitre: string; layer: string; sensor: string; action: string;
  feature?: { kind?: string; response?: { target?: string; seconds?: number; reason?: string } };
};

export type Block = { ip: string; reason: string; severity: Severity; ruleId: string; sensor: string; offenses: number; blockedAt: string; expiresAt: string };

export type Finding = {
  key: string; source: string; severity: Severity; category: string; title: string; detail: string; recommendation: string;
  asset: string; mitre: string; firstSeen: string; lastSeen: string;
};

export type Stats = {
  alerts: { total: number; bySeverity: Record<string, number>; byCategory: Record<string, number>; byLayer: Record<string, number>; bySensor: Record<string, number>; byAction: Record<string, number> };
  timeline: { hour: string; count: number }[];
  attackers: { ip: string; alerts: number; maxSeverity: Severity; categories: string[]; lastSeen: string; blockedUntil: string | null }[];
  blocksActive: number;
  findingsOpen: Record<string, number>;
};

export type Engine = {
  online: boolean; capturing?: boolean; captureAllowed?: boolean; interface?: string; packetsSeen?: number; lastError?: string | null;
  detectionsTotal?: number;
  prevention?: { mode?: string; activeBlocks?: number; blocksApplied?: number; minSeverity?: string };
  suricata?: { enabled?: boolean; connected?: boolean; alertsForwarded?: number; lastAlertAt?: string | null };
  audit?: { enabled?: boolean; lastRunAt?: string | null; findings?: number };
};
export type EngineState = { captureEnabled: boolean; engine: Engine };

export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(`${path}: ${response.status}`);
  return response.json() as Promise<T>;
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

export const SEVERITY_LABEL: Record<string, string> = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' };

export const CATEGORY_LABEL: Record<string, string> = {
  reconnaissance: 'Reconocimiento', credential_access: 'Fuerza bruta', exploitation: 'Explotación', malware: 'Malware',
  denial_of_service: 'Denegación de servicio', network_interception: 'Intercepción (MITM)', spoofing: 'Suplantación de IP',
  evasion: 'Evasión', command_control: 'Mando y control', exfiltration: 'Exfiltración', lateral_movement: 'Movimiento lateral',
  reputation: 'Mala reputación', policy: 'Política', anomaly: 'Anomalía (ML)', port_scan: 'Reconocimiento',
};

export const ACTION_LABEL: Record<string, string> = {
  blocked: 'Bloqueada', not_blocked: 'No bloqueada', dry_run: 'Simulación', block_failed: 'Fallo al bloquear', alert: '—',
};

export const FINDING_CATEGORY_LABEL: Record<string, string> = {
  exposed_service: 'Servicio expuesto', hardening: 'Kernel / red', ssh_config: 'SSH', firewall: 'Firewall', insecure_protocol: 'Protocolo inseguro',
};

export const COVERAGE: { layer: string; title: string; items: string[] }[] = [
  { layer: 'L2', title: 'Enlace', items: ['ARP spoofing y envenenamiento', 'Inundación de MACs', 'Servidor DHCP falso', 'Router Advertisement IPv6 falso', 'Descubrimiento por ARP'] },
  { layer: 'L3', title: 'Red', items: ['Ping sweep', 'Flood ICMP', 'Smurf', 'Redirección ICMP', 'Ataque LAND', 'IP falsificada (bogon)', 'Fragmentos diminutos', 'Flood de fragmentos'] },
  { layer: 'L4', title: 'Transporte', items: ['Escaneos SYN, UDP, NULL, FIN y XMAS', 'Barrido horizontal', 'SYN flood y DDoS', 'Flood UDP', 'DDoS por reflexión', 'Exfiltración por volumen', 'Anomalías (Isolation Forest)'] },
  { layer: 'L7', title: 'Aplicación', items: ['Fuerza bruta (SSH, RDP, SMB, BD…)', 'Escaneo de rutas web', 'Túneles DNS y DGA', 'Beaconing C2', 'Movimiento lateral', 'Protocolos inseguros', 'Suricata ET: exploits, CVE, malware, reputación'] },
];

export function timeAgo(value: string | null | undefined): string {
  if (!value) return 'nunca';
  const seconds = Math.max(0, (Date.now() - Date.parse(value)) / 1000);
  if (seconds < 60) return 'hace un momento';
  if (seconds < 3600) return `hace ${Math.round(seconds / 60)} min`;
  if (seconds < 86400) return `hace ${Math.round(seconds / 3600)} h`;
  return `hace ${Math.round(seconds / 86400)} d`;
}

export function until(value: string): string {
  const minutes = Math.max(0, Math.round((Date.parse(value) - Date.now()) / 60000));
  return minutes >= 1440 ? `${Math.round(minutes / 1440)} d` : minutes >= 60 ? `${Math.round(minutes / 60)} h` : `${minutes} min`;
}
