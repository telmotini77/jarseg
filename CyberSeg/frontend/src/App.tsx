import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { io } from 'socket.io-client';
import {
  ACTION_LABEL, API, Alert, Block, CATEGORY_LABEL, COVERAGE, EngineState, FINDING_CATEGORY_LABEL, Finding, SEVERITY_LABEL,
  SEVERITY_ORDER, Stats, getJson, timeAgo, until,
} from './api';

function Badge({ severity }: { severity: string }) {
  return <b className={`badge ${severity}`}>{SEVERITY_LABEL[severity] ?? severity}</b>;
}

function sensorStatus(state: EngineState | null) {
  const engine = state?.engine;
  const online = Boolean(engine?.online);
  const capture = !online ? ['OFFLINE', 'El motor no responde', 'bad']
    : engine?.captureAllowed === false ? ['BLOQUEADA', 'CYBERSEG_CAPTURE_ALLOWED=false', 'bad']
    : engine?.lastError ? ['ERROR', engine.lastError, 'bad']
    : engine?.capturing ? ['ACTIVA', `${engine.interface} · ${(engine.packetsSeen ?? 0).toLocaleString()} paquetes`, 'ok']
    : ['DETENIDA', state?.captureEnabled ? 'Iniciando…' : 'Esperando orden de inicio', 'warn'];
  const suricata = !engine?.suricata?.enabled ? ['DESACTIVADO', 'Sin firmas de exploits', 'warn']
    : engine.suricata.connected ? ['ACTIVO', `${engine.suricata.alertsForwarded ?? 0} alertas desde el arranque · última ${timeAgo(engine.suricata.lastAlertAt)}`, 'ok']
    : ['SIN DATOS', 'Esperando eve.json de Suricata', 'warn'];
  const mode = engine?.prevention?.mode;
  const prevention = mode === 'block' ? ['BLOQUEO', `${engine?.prevention?.activeBlocks ?? 0} IPs bloqueadas ahora`, 'ok']
    : mode === 'dry-run' ? ['SIMULACIÓN', 'Registra lo que bloquearía', 'warn']
    : mode === 'unavailable' ? ['NO DISPONIBLE', 'Falta nft o NET_ADMIN', 'bad']
    : ['SOLO ALERTA', 'No modifica el firewall', 'warn'];
  const audit = engine?.audit?.enabled ? ['ACTIVA', `${engine.audit.findings ?? 0} hallazgos · ${timeAgo(engine.audit.lastRunAt)}`, engine.audit.lastRunAt ? 'ok' : 'warn']
    : ['DESACTIVADA', 'CYBERSEG_AUDIT_ENABLED=false', 'warn'];
  return [['Captura', ...capture], ['Suricata', ...suricata], ['Prevención', ...prevention], ['Auditoría', ...audit]];
}

export function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [engine, setEngine] = useState<EngineState | null>(null);
  const [status, setStatus] = useState('Conectando');
  const [severity, setSeverity] = useState('all');
  const [category, setCategory] = useState('all');
  const statsTimer = useRef<number>();

  const loadStats = useCallback(() => getJson<Stats>('/api/stats').then(setStats).catch(() => undefined), []);
  const loadBlocks = useCallback(() => getJson<Block[]>('/api/blocks').then(setBlocks).catch(() => undefined), []);
  const loadFindings = useCallback(() => getJson<Finding[]>('/api/findings').then(setFindings).catch(() => undefined), []);
  const refreshStatsSoon = useCallback(() => {
    window.clearTimeout(statsTimer.current);
    statsTimer.current = window.setTimeout(loadStats, 1500);
  }, [loadStats]);

  useEffect(() => {
    getJson<Alert[]>('/api/alerts?limit=200').then(setAlerts).catch(() => setStatus('API no disponible'));
    loadStats(); loadBlocks(); loadFindings();
    const socket = API ? io(API) : io();
    socket.on('connect', () => setStatus('En línea'));
    socket.on('disconnect', () => setStatus('Reconectando'));
    socket.on('new_alert', (alert: Alert) => { setAlerts((current) => [alert, ...current].slice(0, 200)); refreshStatsSoon(); });
    socket.on('blocks_changed', () => { loadBlocks(); refreshStatsSoon(); });
    socket.on('findings_changed', () => { loadFindings(); refreshStatsSoon(); });
    const pollEngine = () => getJson<EngineState>('/api/engine/status').then(setEngine).catch(() => setEngine(null));
    pollEngine();
    const engineTimer = window.setInterval(pollEngine, 5000);
    const slowTimer = window.setInterval(() => { loadStats(); loadBlocks(); }, 30000);
    return () => { socket.close(); window.clearInterval(engineTimer); window.clearInterval(slowTimer); };
  }, [loadStats, loadBlocks, loadFindings, refreshStatsSoon]);

  const visible = useMemo(
    () => alerts.filter((alert) => (severity === 'all' || alert.risk === severity) && (category === 'all' || alert.category === category)),
    [alerts, severity, category],
  );
  const categories = useMemo(() => [...new Set(alerts.map((alert) => alert.category))].sort(), [alerts]);
  const severe = (stats?.alerts.bySeverity.critical ?? 0) + (stats?.alerts.bySeverity.high ?? 0);
  const openFindings = Object.values(stats?.findingsOpen ?? {}).reduce((sum, value) => sum + value, 0);
  // Always 24 hourly bars, so a quiet day still reads as a timeline.
  const hours = useMemo(() => {
    const counts = new Map((stats?.timeline ?? []).map((point) => [new Date(point.hour).getTime(), point.count]));
    const current = Math.floor(Date.now() / 3_600_000) * 3_600_000; // same UTC hour as date_trunc
    return Array.from({ length: 24 }, (_, index) => {
      const hour = current - (23 - index) * 3_600_000;
      return { hour, count: counts.get(hour) ?? 0 };
    });
  }, [stats]);
  const peak = Math.max(1, ...hours.map((point) => point.count));

  return <main>
    <header>
      <div><span>CYBERSEG</span><h1>Centro de detección y prevención de intrusiones</h1></div>
      <b className="status">● {status}</b>
    </header>

    <section className="sensors">{sensorStatus(engine).map(([name, value, detail, tone]) =>
      <article key={name} className={tone}><small>{name}</small><strong>{value}</strong><p>{detail}</p></article>)}
    </section>

    <section className="metrics">
      <article><small>ALERTAS 24 H</small><strong>{stats?.alerts.total ?? 0}</strong><p>{stats?.alerts.bySensor.suricata ?? 0} por firmas · {stats?.alerts.bySensor.engine ?? 0} por comportamiento</p></article>
      <article><small>CRÍTICAS Y ALTAS</small><strong className="danger">{severe}</strong><p>{stats?.alerts.bySeverity.critical ?? 0} críticas</p></article>
      <article><small>IPS BLOQUEADAS</small><strong>{stats?.blocksActive ?? 0}</strong><p>{stats?.alerts.byAction.blocked ?? 0} bloqueos en 24 h</p></article>
      <article><small>VULNERABILIDADES</small><strong className={openFindings ? 'warning' : ''}>{openFindings}</strong><p>{stats?.findingsOpen.critical ?? 0} críticas · {stats?.findingsOpen.high ?? 0} altas</p></article>
    </section>

    <section className="grid two">
      <article className="panel">
        <h2>Actividad de las últimas 24 h</h2>
        <div className="timeline">{hours.map((point) =>
          <div key={point.hour} className={point.count ? '' : 'empty'} title={`${new Date(point.hour).toLocaleString()}: ${point.count} alertas`}
            style={{ height: `${point.count ? Math.max(6, (point.count / peak) * 100) : 2}%` }} />)}
        </div>
        <div className="bars">{Object.entries(stats?.alerts.byCategory ?? {}).sort((a, b) => b[1] - a[1]).map(([name, count]) =>
          <div key={name}><span>{CATEGORY_LABEL[name] ?? name}</span><i style={{ width: `${(count / Math.max(1, stats?.alerts.total ?? 1)) * 100}%` }} /><b>{count}</b></div>)}
        </div>
      </article>
      <article className="panel">
        <h2>Principales atacantes</h2>
        <table><thead><tr><th>IP</th><th>Alertas</th><th>Máx.</th><th>Tácticas</th><th>Estado</th></tr></thead>
          <tbody>{(stats?.attackers ?? []).map((attacker) => <tr key={attacker.ip}>
            <td className="mono">{attacker.ip}</td><td>{attacker.alerts}</td><td><Badge severity={attacker.maxSeverity} /></td>
            <td>{attacker.categories.map((item) => CATEGORY_LABEL[item] ?? item).join(', ')}</td>
            <td>{attacker.blockedUntil ? <b className="blocked">Bloqueada · {until(attacker.blockedUntil)}</b> : <span className="muted">Activa</span>}</td>
          </tr>)}</tbody></table>
        {!stats?.attackers.length && <p className="muted">Sin orígenes hostiles en 24 h.</p>}
      </article>
    </section>

    <section className="panel">
      <div className="panel-head"><h2>Alertas</h2>
        <div className="filters">
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="all">Todas las severidades</option>{SEVERITY_ORDER.map((item) => <option key={item} value={item}>{SEVERITY_LABEL[item]}</option>)}
          </select>
          <select value={category} onChange={(event) => setCategory(event.target.value)}>
            <option value="all">Todas las categorías</option>{categories.map((item) => <option key={item} value={item}>{CATEGORY_LABEL[item] ?? item}</option>)}
          </select>
        </div>
      </div>
      <table><thead><tr><th>Fecha</th><th>Severidad</th><th>Categoría</th><th>Capa</th><th>MITRE</th><th>Origen → destino</th><th>Respuesta</th><th>Detalle</th></tr></thead>
        <tbody>{visible.map((alert) => <tr key={alert.id}>
          <td>{new Date(alert.timestamp).toLocaleString()}</td><td><Badge severity={alert.risk} /></td>
          <td>{CATEGORY_LABEL[alert.category] ?? alert.category}<small className="muted block">{alert.sensor === 'suricata' ? 'Suricata' : 'Comportamiento'}</small></td>
          <td>{alert.layer || '—'}</td>
          <td>{alert.mitre ? <a href={`https://attack.mitre.org/techniques/${alert.mitre.replace('.', '/')}/`} target="_blank" rel="noreferrer">{alert.mitre}</a> : '—'}</td>
          <td className="mono">{alert.sourceIp}<br />→ {alert.destinationIp}</td>
          <td><span className={`action ${alert.action}`} title={alert.feature?.response?.reason}>{ACTION_LABEL[alert.action] ?? alert.action}</span></td>
          <td>{alert.description}</td>
        </tr>)}</tbody></table>
      {!visible.length && <p className="muted">Sin alertas para este filtro.</p>}
    </section>

    <section className="grid two">
      <article className="panel">
        <h2>Vulnerabilidades y exposición</h2>
        {findings.map((finding) => <details key={finding.key} className="finding">
          <summary><Badge severity={finding.severity} /> <b>{finding.title}</b> <span className="muted">· {FINDING_CATEGORY_LABEL[finding.category] ?? finding.category} · {finding.asset}</span></summary>
          <p>{finding.detail}</p><p className="fix"><b>Cómo corregirlo:</b> {finding.recommendation}</p>
          <small className="muted">{finding.source === 'audit' ? 'Auditoría del servidor' : 'Observado en el tráfico'} · visto {timeAgo(finding.lastSeen)}</small>
        </details>)}
        {!findings.length && <p className="muted">No hay vulnerabilidades abiertas.</p>}
      </article>
      <article className="panel">
        <h2>IPs bloqueadas</h2>
        <table><thead><tr><th>IP</th><th>Severidad</th><th>Motivo</th><th>Expira</th></tr></thead>
          <tbody>{blocks.map((block) => <tr key={block.ip}>
            <td className="mono">{block.ip}{block.offenses > 1 && <small className="muted block">reincidente ×{block.offenses}</small>}</td>
            <td><Badge severity={block.severity} /></td><td>{block.reason}</td><td>{until(block.expiresAt)}</td>
          </tr>)}</tbody></table>
        {!blocks.length && <p className="muted">Ninguna IP bloqueada ahora mismo.</p>}
      </article>
    </section>

    <section className="panel">
      <h2>Cobertura por capa</h2>
      <div className="coverage">{COVERAGE.map((layer) => <article key={layer.layer}>
        <header><b>{layer.layer}</b> {layer.title}<span>{stats?.alerts.byLayer[layer.layer] ?? 0} alertas 24 h</span></header>
        <ul>{layer.items.map((item) => <li key={item}>{item}</li>)}</ul>
      </article>)}</div>
    </section>
  </main>;
}
