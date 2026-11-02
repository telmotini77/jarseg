export const SEVERITY_LABEL: Record<string, string> = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' };

export const CATEGORY_LABEL: Record<string, string> = {
  reconnaissance: 'Reconocimiento', credential_access: 'Fuerza bruta', exploitation: 'Explotación', malware: 'Malware',
  denial_of_service: 'Denegación de servicio', network_interception: 'Intercepción (MITM)', spoofing: 'Suplantación de IP',
  evasion: 'Evasión', command_control: 'Mando y control', exfiltration: 'Exfiltración', lateral_movement: 'Movimiento lateral',
  reputation: 'Mala reputación', policy: 'Política', anomaly: 'Anomalía (ML)',
};

export const ACTION_LABEL: Record<string, string> = {
  blocked: 'Bloqueada', not_blocked: 'No bloqueada', dry_run: 'Simulación', block_failed: 'Fallo al bloquear', alert: 'Solo alerta',
};

export const label = (map: Record<string, string>, value: string) => map[value] ?? value;
