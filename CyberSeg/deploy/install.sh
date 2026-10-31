#!/usr/bin/env bash
# Optional helper: prepares .env with random secrets and starts CyberSeg with
# Docker Compose on a Linux host you administer. Equivalent to copying
# .env.example to .env, editing it and running `docker compose up -d --build`.
#
#   ./deploy/install.sh                     # capture on the default-route interface
#   ./deploy/install.sh --interface ens3
#   ./deploy/install.sh --no-autostart      # wait for JARVIS to start capture
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"
INTERFACE=""
AUTOSTART=true

while [ $# -gt 0 ]; do
  case "$1" in
    --interface) INTERFACE="${2:?--interface necesita un nombre}"; shift 2 ;;
    --no-autostart) AUTOSTART=false; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 2 ;;
  esac
done

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
secret() { od -An -N"$(($1 / 2))" -tx1 /dev/urandom | tr -d ' \n'; }
set_env() {
  # Replace KEY=... in .env, or append it when missing.
  if grep -q "^$1=" "$ENV_FILE"; then
    sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
  fi
}
default_env() {
  # Add KEY=VALUE only if .env does not define it (upgrades keep user choices).
  grep -q "^$1=" "$ENV_FILE" || printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
}
env_value() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1; }

[ "$(uname -s)" = "Linux" ] || fail "La captura del host requiere un servidor Linux (network_mode: host)."

step "Comprobando Docker"
command -v docker >/dev/null || fail "Docker no está instalado. Guía oficial: https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || fail "Falta el plugin 'docker compose' (paquete docker-compose-plugin)."
docker info >/dev/null 2>&1 || fail "No hay acceso al daemon de Docker: ejecuta con sudo o añade tu usuario al grupo docker."
case "$(command -v docker)" in
  /snap/*) echo "AVISO: Docker está instalado como snap (opción del instalador de Ubuntu Server) y puede fallar con la red del host. Recomendado: sudo snap remove docker && sudo apt install docker.io docker-compose-v2" ;;
esac

step "Seleccionando la interfaz de captura"
if [ -z "$INTERFACE" ]; then
  INTERFACE="$(ip -o route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')"
fi
[ -n "$INTERFACE" ] || fail "No se detectó la interfaz por defecto; usa --interface <nombre>."
ip link show "$INTERFACE" >/dev/null 2>&1 || fail "La interfaz '$INTERFACE' no existe. Interfaces: $(ls /sys/class/net | tr '\n' ' ')"
ADDRESS="$(ip -o -4 addr show "$INTERFACE" | awk '{print $4}' | head -n1)"
echo "Interfaz: $INTERFACE ($ADDRESS)"
VIRT="$(systemd-detect-virt 2>/dev/null || true)"
if [ -n "$VIRT" ] && [ "$VIRT" != "none" ]; then
  echo "Máquina virtual detectada ($VIRT): usa el adaptador de red en modo puente (bridge) para que el tráfico de la LAN llegue a $INTERFACE."
fi
case "$ADDRESS" in
  10.0.2.15/*) echo "AVISO: $ADDRESS es la red NAT de VirtualBox; los demás equipos no pueden alcanzar la VM. Cambia el adaptador a 'Adaptador puente'." ;;
esac

step "Preparando $ENV_FILE"
if [ ! -f "$ENV_FILE" ]; then
  cp "$ROOT/.env.example" "$ENV_FILE"
  set_env POSTGRES_PASSWORD "$(secret 40)"
  set_env CYBERSEG_ENGINE_TOKEN "$(secret 64)"
  echo "Se generaron contraseña de base de datos y token aleatorios."
elif grep -Eq '^(POSTGRES_PASSWORD|CYBERSEG_ENGINE_TOKEN)=(change_this|replace_with|$)' "$ENV_FILE"; then
  fail "$ENV_FILE conserva valores de ejemplo en POSTGRES_PASSWORD o CYBERSEG_ENGINE_TOKEN. Cámbialos o borra el archivo para regenerarlo."
fi
set_env CYBERSEG_CAPTURE_ALLOWED true
set_env CYBERSEG_INTERFACE "$INTERFACE"
set_env CYBERSEG_CAPTURE_AUTOSTART "$AUTOSTART"
default_env COMPOSE_PROFILES suricata
default_env CYBERSEG_SURICATA_ENABLED true
default_env CYBERSEG_PREVENTION_MODE block
HOME_NET="$(env_value CYBERSEG_HOME_NET)"
if [ -n "$ADDRESS" ] && { [ -z "$HOME_NET" ] || [ "$HOME_NET" = "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]" ]; }; then
  # Suricata must treat this server's own address as "home", even if public.
  set_env CYBERSEG_HOME_NET "[${ADDRESS%/*}/32,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
fi

# The active response must never lock out the administrator: trust the IP
# this script is being run from over SSH.
ADMIN_IP="${SSH_CLIENT%% *}"
[ -n "$ADMIN_IP" ] || ADMIN_IP="$(who -m 2>/dev/null | sed -n 's/.*(\([0-9a-fA-F.:]*\)).*/\1/p')"
TRUSTED="$(env_value CYBERSEG_TRUSTED_NETWORKS)"
if [ -n "$ADMIN_IP" ]; then
  case ",$TRUSTED," in
    *",$ADMIN_IP,"*|*",$ADMIN_IP/32,"*) ;;
    *) set_env CYBERSEG_TRUSTED_NETWORKS "${TRUSTED:+$TRUSTED,}$ADMIN_IP"; echo "Tu IP de administración $ADMIN_IP nunca será bloqueada (CYBERSEG_TRUSTED_NETWORKS)." ;;
  esac
elif [ -z "$TRUSTED" ]; then
  echo "AVISO: no se detectó tu IP de administración. Añádela a CYBERSEG_TRUSTED_NETWORKS en $ENV_FILE para no bloquearte a ti mismo."
fi
chmod 600 "$ENV_FILE"

MEMORY_MB="$(awk '/MemTotal/ {print int($2 / 1024)}' /proc/meminfo)"
if [ "$(env_value COMPOSE_PROFILES)" = "suricata" ] && [ "${MEMORY_MB:-0}" -lt 3500 ]; then
  echo "AVISO: la máquina tiene ${MEMORY_MB} MB de RAM; Suricata necesita 1-2 GB. Recomendado: 4 GB o más."
fi

step "Construyendo e iniciando los contenedores"
cd "$ROOT"
docker compose up -d --build --remove-orphans

step "Verificando"
for _ in $(seq 1 30); do
  curl -fsS --max-time 2 http://127.0.0.1:8780/api/engine/status 2>/dev/null | grep -q '"online":true' && break
  sleep 2
done
"$ROOT/deploy/check.sh" || true

cat <<EOF

CyberSeg está en marcha y Docker lo reiniciará con el servidor
(asegúrate de tener 'systemctl enable docker').
  Estado:     $ROOT/deploy/check.sh
  Registros:  cd $ROOT && docker compose logs -f engine
  Dashboard:  desde tu PC ejecuta  ssh -L 5178:127.0.0.1:5178 <usuario>@<servidor>
              y abre http://127.0.0.1:5178
  JARVIS:     CYBERSEG_API_TOKEN = el valor de CYBERSEG_ENGINE_TOKEN en $ENV_FILE
EOF
