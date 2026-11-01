import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { io } from 'socket.io-client';
import {
  ACTION_LABEL, API, Alert, Block, CATEGORY_LABEL, COVERAGE, EngineState, FINDING_CATEGORY_LABEL, Finding, OrderResult,
  SEVERITY_LABEL, SEVERITY_ORDER, Session, Stats, Unauthorized, getJson, postJson, timeAgo, until,
} from './api';
import { Login } from './Login';

type Notice = { id: number; text: string; ok: boolean };
type InstallPrompt = Event & { prompt: () => Promise<void> };

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
  // undefined: still checking the session cookie.
  const [session, setSession] = useState<Session | null | undefined>(undefined);
  useEffect(() => { getJson<Session>('/api/auth/me').then(setSession).catch(() => setSession(null)); }, []);
  if (session === undefined) return <main className="login"><p className="muted">Conectando con CyberSeg…</p></main>;
  if (session === null) return <Login onLogin={setSession} />;
  return <Dashboard session={session} onSignedOut={() => setSession(null)} />;
}

function Dashboard({ session, onSignedOut }: { session: Session; onSignedOut: () => void }) {
  const admin = session.role === 'admin';
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [accepted, setAccepted] = useState<Finding[] | null>(null);
  const [engine, setEngine] = useState<EngineState | null>(null);
  const [status, setStatus] = useState('Conectando');
  const [severity, setSeverity] = useState('all');
  const [category, setCategory] = useState('all');
  const [hideReviewed, setHideReviewed] = useState(false);
  const [notices, setNotices] = useState<Notice[]>([]);
  const [installPrompt, setInstallPrompt] = useState<InstallPrompt | null>(null);
  const [desktopAvailable, setDesktopAvailable] = useState(false);
  const statsTimer = useRef<number>();
  const noticeId = useRef(0);

  const notify = useCallback((text: string, ok = true) => {
    const id = ++noticeId.current;
    setNotices((current) => [...current, { id, text, ok }]);
    window.setTimeout(() => setNotices((current) => current.filter((notice) => notice.id !== id)), 7000);
  }, []);
  // Any request may find the session expired: send the user back to the login.
  const guard = useCallback((failure: unknown) => {
    if (failure instanceof Unauthorized) onSignedOut();
    else notify(failure instanceof Error ? failure.message : 'La operación falló.', false);
  }, [notify, onSignedOut]);

  const loadAlerts = useCallback(() => getJson<Alert[]>('/api/alerts?limit=200').then(setAlerts).catch(guard), [guard]);
  const loadStats = useCallback(() => getJson<Stats>('/api/stats').then(setStats).catch(guard), [guard]);
  const loadBlocks = useCallback(() => getJson<Block[]>('/api/blocks').then(setBlocks).catch(guard), [guard]);
  const loadFindings = useCallback(() => getJson<Finding[]>('/api/findings').then(setFindings).catch(guard), [guard]);
  const refreshStatsSoon = useCallback(() => {
    window.clearTimeout(statsTimer.current);
    statsTimer.current = window.setTimeout(loadStats, 1500);
  }, [loadStats]);

  useEffect(() => {
    loadAlerts(); loadStats(); loadBlocks(); loadFindings();
    const socket = API ? io(API) : io();
    socket.on('connect', () => setStatus('En línea'));
    socket.on('disconnect', () => setStatus('Reconectando'));
    socket.on('new_alert', (alert: Alert) => { setAlerts((current) => [alert, ...current].slice(0, 200)); refreshStatsSoon(); });
    socket.on('alerts_changed', () => { loadAlerts(); refreshStatsSoon(); });
    socket.on('blocks_changed', () => { loadBlocks(); refreshStatsSoon(); });
    socket.on('findings_changed', () => { loadFindings(); refreshStatsSoon(); });
    socket.on('order_result', (result: OrderResult) => notify(result.message, result.ok));
    const pollEngine = () => getJson<EngineState>('/api/engine/status').then(setEngine).catch(guard);
    pollEngine();
    socket.on('engine_changed', pollEngine);
    const engineTimer = window.setInterval(pollEngine, 5000);
    const slowTimer = window.setInterval(() => { loadStats(); loadBlocks(); }, 30000);
    fetch('/descargas/CyberSeg.exe', { method: 'HEAD', credentials: 'same-origin' }).then((response) => setDesktopAvailable(response.ok)).catch(() => undefined);
    const onInstallable = (event: Event) => { event.preventDefault(); setInstallPrompt(event as InstallPrompt); };
    window.addEventListener('beforeinstallprompt', onInstallable);
    return () => {
      socket.close(); window.clearInterval(engineTimer); window.clearInterval(slowTimer);
      window.removeEventListener('beforeinstallprompt', onInstallable);
    };
  }, [loadAlerts, loadStats, loadBlocks, loadFindings, refreshStatsSoon, notify, guard]);

  const run = useCallback(async (path: string, body: unknown, done?: string) => {
    try {
      const result = await postJson<{ message?: string }>(path, body);
      notify(done ?? result.message ?? 'Hecho.');
    } catch (failure) {
      guard(failure);
    }
  }, [notify, guard]);

  const review = (alert: Alert, change: { acknowledged?: boolean; falsePositive?: boolean }) =>
    run(`/api/manage/alerts/${alert.id}/review`, change, change.falsePositive !== undefined
      ? (change.falsePositive ? 'Alerta marcada como falso positivo.' : 'Falso positivo retirado.')
      : (change.acknowledged ? 'Alerta marcada como revisada.' : 'Alerta pendiente de nuevo.'));
  const block = (ip: string, hours: number, reason: string) => run('/api/manage/blocks', { ip, hours, reason });
  const unblock = (ip: string) => run('/api/manage/blocks/unblock', { ip });
  const acceptRisk = (finding: Finding, value: boolean) =>
    run('/api/manage/findings/accept', { key: finding.key, accepted: value }, value ? 'Riesgo aceptado: no volverá a abrirse.' : 'Vulnerabilidad reabierta.')
      .then(() => { if (accepted) getJson<Finding[]>('/api/findings?status=accepted').then(setAccepted).catch(guard); });
  const toggleCapture = () => run('/api/manage/capture', { enabled: !engine?.captureEnabled },
    engine?.captureEnabled ? 'Captura detenida.' : 'Captura iniciada.');
  const logout = () => postJson('/api/auth/logout').catch(() => undefined).finally(onSignedOut);

  const [manualIp, setManualIp] = useState('');
  const [manualHours, setManualHours] = useState(24);
  const [manualReason, setManualReason] = useState('');
  const submitBlock = (event: FormEvent) => {
    event.preventDefault();
    block(manualIp.trim(), manualHours, manualReason.trim()).then(() => { setManualIp(''); setManualReason(''); });
  };

  const visible = useMemo(
    () => alerts.filter((alert) => (severity === 'all' || alert.risk === severity) && (category === 'all' || alert.category === category)
      && !(hideReviewed && (alert.acknowledged || alert.falsePositive))),
    [alerts, severity, category, hideReviewed],
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
      <div className="session">
        <b className="status">● {status}</b>
        <span className="muted">{session.user} · {admin ? 'Administrador' : 'Solo lectura'}</span>
        {admin && engine?.engine.online && <button className="ghost" onClick={toggleCapture}>{engine.captureEnabled ? 'Detener captura' : 'Iniciar captura'}</button>}
        {installPrompt && <button className="ghost" onClick={() => installPrompt.prompt().then(() => setInstallPrompt(null))}>Instalar app</button>}
        <button className="ghost" onClick={logout}>Cerrar sesión</button>
      </div>
    </header>

    <div className="notices">{notices.map((notice) => <p key={notice.id} className={notice.ok ? 'ok' : 'bad'}>{notice.text}</p>)}</div>

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
            <td>{attacker.blockedUntil ? <b className="blocked">Bloqueada · {until(attacker.blockedUntil)}</b> : <span className="muted">Activa</span>}
              {admin && (attacker.blockedUntil
                ? <button className="link" onClick={() => unblock(attacker.ip)}>Desbloquear</button>
                : <button className="link" onClick={() => block(attacker.ip, 24, 'desde principales atacantes')}>Bloquear 24 h</button>)}
            </td>
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
          <label className="check"><input type="checkbox" checked={hideReviewed} onChange={(event) => setHideReviewed(event.target.checked)} /> Ocultar revisadas</label>
        </div>
      </div>
      <table><thead><tr><th>Fecha</th><th>Severidad</th><th>Categoría</th><th>Capa</th><th>MITRE</th><th>Origen → destino</th><th>Respuesta</th><th>Detalle</th>{admin && <th>Gestión</th>}</tr></thead>
        <tbody>{visible.map((alert) => <tr key={alert.id} className={alert.falsePositive ? 'dimmed' : ''}>
          <td>{new Date(alert.timestamp).toLocaleString()}</td><td><Badge severity={alert.risk} /></td>
          <td>{CATEGORY_LABEL[alert.category] ?? alert.category}<small className="muted block">{alert.sensor === 'suricata' ? 'Suricata' : 'Comportamiento'}</small></td>
          <td>{alert.layer || '—'}</td>
          <td>{alert.mitre ? <a href={`https://attack.mitre.org/techniques/${alert.mitre.replace('.', '/')}/`} target="_blank" rel="noreferrer">{alert.mitre}</a> : '—'}</td>
          <td className="mono">{alert.sourceIp}<br />→ {alert.destinationIp}</td>
          <td><span className={`action ${alert.action}`} title={alert.feature?.response?.reason}>{ACTION_LABEL[alert.action] ?? alert.action}</span></td>
          <td>{alert.description}{alert.acknowledged && <small className="tag">revisada</small>}{alert.falsePositive && <small className="tag">falso positivo</small>}</td>
          {admin && <td className="actions">
            <button className="link" onClick={() => review(alert, { acknowledged: !alert.acknowledged })}>{alert.acknowledged ? 'Pendiente' : 'Revisada'}</button>
            <button className="link" onClick={() => review(alert, { falsePositive: !alert.falsePositive })}>{alert.falsePositive ? 'No es falso +' : 'Falso positivo'}</button>
          </td>}
        </tr>)}</tbody></table>
      {!visible.length && <p className="muted">Sin alertas para este filtro.</p>}
    </section>

    <section className="grid two">
      <article className="panel">
        <div className="panel-head"><h2>Vulnerabilidades y exposición</h2>
          <button className="link" onClick={() => accepted ? setAccepted(null) : getJson<Finding[]>('/api/findings?status=accepted').then(setAccepted).catch(guard)}>
            {accepted ? 'Ocultar riesgos aceptados' : 'Ver riesgos aceptados'}
          </button>
        </div>
        {findings.map((finding) => <details key={finding.key} className="finding">
          <summary><Badge severity={finding.severity} /> <b>{finding.title}</b> <span className="muted">· {FINDING_CATEGORY_LABEL[finding.category] ?? finding.category} · {finding.asset}</span></summary>
          <p>{finding.detail}</p><p className="fix"><b>Cómo corregirlo:</b> {finding.recommendation}</p>
          <small className="muted">{finding.source === 'audit' ? 'Auditoría del servidor' : 'Observado en el tráfico'} · visto {timeAgo(finding.lastSeen)}</small>
          {admin && <button className="link" onClick={() => acceptRisk(finding, true)}>Aceptar el riesgo</button>}
        </details>)}
        {!findings.length && <p className="muted">No hay vulnerabilidades abiertas.</p>}
        {accepted && <div className="accepted"><h3>Riesgos aceptados</h3>
          {accepted.map((finding) => <p key={finding.key}><Badge severity={finding.severity} /> {finding.title} <span className="muted">· {finding.asset}</span>
            {admin && <button className="link" onClick={() => acceptRisk(finding, false)}>Reabrir</button>}</p>)}
          {!accepted.length && <p className="muted">Ninguno.</p>}
        </div>}
      </article>
      <article className="panel">
        <h2>IPs bloqueadas</h2>
        {admin && <form className="inline-form" onSubmit={submitBlock}>
          <input placeholder="IP a bloquear" value={manualIp} onChange={(event) => setManualIp(event.target.value)} required />
          <select value={manualHours} onChange={(event) => setManualHours(Number(event.target.value))}>
            {[1, 6, 24, 72, 168, 720].map((value) => <option key={value} value={value}>{value < 24 ? `${value} h` : `${value / 24} d`}</option>)}
          </select>
          <input placeholder="Motivo (opcional)" value={manualReason} onChange={(event) => setManualReason(event.target.value)} />
          <button type="submit">Bloquear</button>
        </form>}
        <table><thead><tr><th>IP</th><th>Severidad</th><th>Motivo</th><th>Expira</th>{admin && <th />}</tr></thead>
          <tbody>{blocks.map((item) => <tr key={item.ip}>
            <td className="mono">{item.ip}{item.offenses > 1 && <small className="muted block">reincidente ×{item.offenses}</small>}</td>
            <td><Badge severity={item.severity} /></td><td>{item.reason}</td><td>{until(item.expiresAt)}</td>
            {admin && <td><button className="link" onClick={() => unblock(item.ip)}>Desbloquear</button></td>}
          </tr>)}</tbody></table>
        {!blocks.length && <p className="muted">Ninguna IP bloqueada ahora mismo.</p>}
      </article>
    </section>

    <section className="panel">
      <h2>Descargas</h2>
      <div className="downloads">
        <article><h3>Informe PDF</h3><p className="muted">Resumen ejecutivo: alertas, atacantes, bloqueos y vulnerabilidades con su corrección.</p>
          <a href="/api/export/report.pdf?days=7" download>Últimos 7 días</a><a href="/api/export/report.pdf?days=30" download>Últimos 30 días</a></article>
        <article><h3>Excel</h3><p className="muted">Libro con hojas de resumen, alertas, IPs bloqueadas y vulnerabilidades, con filtros.</p>
          <a href="/api/export/report.xlsx?days=7" download>Últimos 7 días</a><a href="/api/export/report.xlsx?days=30" download>Últimos 30 días</a></article>
        <article><h3>CSV de alertas</h3><p className="muted">Para importar en otras herramientas (SIEM, hojas de cálculo).</p>
          <a href="/api/export/alerts.csv?days=7" download>Últimos 7 días</a><a href="/api/export/alerts.csv?days=90" download>Últimos 90 días</a></article>
        <article><h3>Aplicaciones</h3><p className="muted">Usa CyberSeg como programa propio en tu PC o móvil.</p>
          {desktopAvailable ? <a href="/descargas/CyberSeg.exe" download>Programa para Windows (.exe)</a> : <span className="muted small">El .exe aún no está publicado en el servidor (carpeta downloads/).</span>}
          {installPrompt ? <button className="link" onClick={() => installPrompt.prompt().then(() => setInstallPrompt(null))}>Instalar como app</button>
            : <span className="muted small">App instalable: menú del navegador → «Instalar CyberSeg».</span>}
          <a href="/certificado" target="_blank" rel="noreferrer">Certificado del servidor</a></article>
      </div>
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
