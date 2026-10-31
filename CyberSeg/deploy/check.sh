#!/usr/bin/env bash
# Checks that the API answers, the engine is alive and packets are being captured.
set -uo pipefail

API="${CYBERSEG_API_URL:-http://127.0.0.1:8780}"
ok=0
for tool in curl python3; do
  command -v "$tool" >/dev/null || { echo "Falta $tool en el servidor." >&2; exit 1; }
done

json() { PYTHONIOENCODING=utf-8 python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null; }
pass() { printf '  [OK]    %s\n' "$*"; }
warn() { printf '  [FALLO] %s\n' "$*"; ok=1; }

echo "CyberSeg — verificación ($API)"

if ! health="$(curl -fsS --max-time 5 "$API/health" 2>/dev/null)"; then
  warn "La API no responde en $API (docker compose ps / logs backend)."
  exit 1
fi
pass "API en línea: $health"

status() { curl -fsS --max-time 5 "$API/api/engine/status"; }
first="$(status)"
online="$(printf '%s' "$first" | json "d['engine'].get('online', False)")"
if [ "$online" != "True" ]; then
  warn "El motor no envía latidos (docker compose logs engine)."
  exit 1
fi
pass "Motor en línea"

error="$(printf '%s' "$first" | json "d['engine'].get('lastError') or ''")"
[ -z "$error" ] || warn "Motor: $error"

if [ "$(printf '%s' "$first" | json "d['engine'].get('capturing', False)")" = "True" ]; then
  iface="$(printf '%s' "$first" | json "d['engine'].get('interface')")"
  before="$(printf '%s' "$first" | json "d['engine'].get('packetsSeen', 0)")"
  sleep 6
  after="$(status | json "d['engine'].get('packetsSeen', 0)")"
  if [ "${after:-0}" -gt "${before:-0}" ]; then
    pass "Capturando en $iface: $((after - before)) paquetes nuevos en 6 s ($after en total)"
  else
    warn "Captura activa en $iface pero sin paquetes nuevos: ¿es la interfaz con tráfico?"
  fi
  printf '%s' "$first" | json "'  [INFO]  Escaneos detectados: %s · modelo de anomalías %s' % (d['engine'].get('portScansDetected', 0), 'entrenado' if d['engine'].get('anomalyModelTrained') else 'aprendiendo tráfico normal')"
elif [ "$(printf '%s' "$first" | json "d['captureEnabled']")" = "True" ]; then
  warn "Captura solicitada pero aún no activa; revisa: docker compose logs engine"
else
  warn "Captura detenida. Actívala con CYBERSEG_CAPTURE_AUTOSTART=true o desde JARVIS."
fi

engine() { printf '%s' "$first" | json "$1"; }
case "$(engine "(d['engine'].get('prevention') or {}).get('mode', '')")" in
  block) pass "Prevención activa: $(engine "d['engine']['prevention'].get('activeBlocks', 0)") IPs bloqueadas ahora" ;;
  dry-run) warn "Prevención en simulación (CYBERSEG_PREVENTION_MODE=dry-run): no bloquea" ;;
  unavailable) warn "Prevención no disponible: el motor no puede usar nftables (revisa NET_ADMIN en docker compose logs engine)" ;;
  *) warn "Prevención desactivada (CYBERSEG_PREVENTION_MODE=alert)" ;;
esac
if [ "$(engine "(d['engine'].get('suricata') or {}).get('enabled', False)")" = "True" ]; then
  if [ "$(engine "d['engine']['suricata'].get('connected', False)")" = "True" ]; then
    pass "Suricata conectado: $(engine "d['engine']['suricata'].get('alertsForwarded', 0)") alertas por firmas desde el arranque"
  else
    warn "Suricata sin datos: comprueba COMPOSE_PROFILES=suricata y docker compose logs suricata"
  fi
fi
if [ "$(engine "(d['engine'].get('audit') or {}).get('enabled', False)")" = "True" ]; then
  open="$(curl -fsS --max-time 5 "$API/api/findings" | json "'%s abiertas (%s críticas, %s altas)' % (len(d), sum(f['severity'] == 'critical' for f in d), sum(f['severity'] == 'high' for f in d))")"
  pass "Auditoría ejecutada $(engine "(d['engine']['audit'].get('lastRunAt') or 'pendiente')[:19]"): vulnerabilidades $open"
fi

recent="$(curl -fsS --max-time 5 "$API/api/alerts?limit=5" | json "'\n'.join('  - [%s] %s' % (a['risk'].upper(), a['description']) for a in d) or '  (sin alertas)'")"
echo "Últimas alertas:"
echo "$recent"
exit $ok
