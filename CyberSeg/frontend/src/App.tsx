import { useEffect, useMemo, useState } from 'react';
import { io } from 'socket.io-client';

type Alert = { id: string; timestamp: string; sourceIp: string; destinationIp: string; risk: string; description: string; score: number };
const api = import.meta.env.VITE_CYBERSEG_API_URL || 'http://127.0.0.1:8780';

export function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [status, setStatus] = useState('Conectando');
  useEffect(() => {
    fetch(`${api}/api/alerts?limit=50`).then((response) => response.json()).then(setAlerts).catch(() => setStatus('API no disponible'));
    const socket = io(api);
    socket.on('connect', () => setStatus('En línea'));
    socket.on('disconnect', () => setStatus('Reconectando'));
    socket.on('new_alert', (alert: Alert) => setAlerts((current) => [alert, ...current].slice(0, 50)));
    return () => { socket.close(); };
  }, []);
  const high = useMemo(() => alerts.filter((alert) => alert.risk === 'high').length, [alerts]);
  return <main>
    <header><div><span>CYBERSEG</span><h1>Detección local de anomalías</h1></div><b className="status">● {status}</b></header>
    <section className="metrics"><article><small>ALERTAS</small><strong>{alerts.length}</strong><p>Últimas 50</p></article><article><small>RIESGO ALTO</small><strong>{high}</strong><p>Requiere revisión</p></article><article><small>MODO</small><strong>PASSIVE</strong><p>Sin bloqueo automático</p></article></section>
    <section className="panel"><h2>Alertas recientes</h2><table><thead><tr><th>Fecha</th><th>Origen</th><th>Destino</th><th>Riesgo</th><th>Detalle</th></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.id}><td>{new Date(alert.timestamp).toLocaleString()}</td><td>{alert.sourceIp}</td><td>{alert.destinationIp}</td><td><b className={alert.risk}>{alert.risk.toUpperCase()}</b></td><td>{alert.description}</td></tr>)}</tbody></table>{!alerts.length && <p>Sin alertas registradas.</p>}</section>
  </main>;
}
