#!/usr/bin/env bash
# Optional helper: prepares .env with random secrets and starts CyberSeg with
# Docker Compose on a Linux host you administer. Equivalent to copying
# .env.example to .env, editing it and running `docker compose up -d --build`.
#
#   ./deploy/install.sh                     # capture on the default-route interface
#   ./deploy/install.sh --interface ens3
#   ./deploy/install.sh --no-autostart      # wait for JARVIS to start capture
#   ./deploy/install.sh --vpn-endpoint 203.0.113.7   # public IP for the VPN
#   ./deploy/install.sh --no-vpn            # LAN access only, no remote VPN
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"
INTERFACE=""
AUTOSTART=true
VPN=true
VPN_ENDPOINT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --interface) INTERFACE="${2:?--interface necesita un nombre}"; shift 2 ;;
    --no-autostart) AUTOSTART=false; shift ;;
    --no-vpn) VPN=false; shift ;;
    --vpn-endpoint) VPN_ENDPOINT="${2:?--vpn-endpoint necesita una IP o nombre}"; shift 2 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
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

# Web dashboard on the LAN: https://<server IP>/ (no domain) with a login.
SERVER_IP="${ADDRESS%/*}"
set_env CYBERSEG_SERVER_IP "$SERVER_IP"
case "$SERVER_IP" in
  10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) set_env CYBERSEG_DASHBOARD_BIND "$SERVER_IP" ;;
  *)
    set_env CYBERSEG_DASHBOARD_BIND 127.0.0.1
    echo "AVISO: $SERVER_IP es una IP pública; el panel solo escuchará en 127.0.0.1 (entra con un túnel SSH)." ;;
esac
default_env CYBERSEG_HTTPS_PORT 443
default_env CYBERSEG_HTTP_PORT 80
default_env CYBERSEG_ADMIN_USER admin
NEW_PASSWORD=""
if [ -z "$(env_value CYBERSEG_ADMIN_PASSWORD)" ]; then
  NEW_PASSWORD="$(secret 20)"
  set_env CYBERSEG_ADMIN_PASSWORD "$NEW_PASSWORD"
fi

# Remote access: WireGuard VPN. Only its UDP port faces the Internet.
if [ "$VPN" = true ]; then
  step "Preparando la VPN WireGuard"
  [ -n "$VPN_ENDPOINT" ] || VPN_ENDPOINT="$(env_value CYBERSEG_VPN_ENDPOINT)"
  if [ -z "$VPN_ENDPOINT" ]; then
    VPN_ENDPOINT="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    [ -n "$VPN_ENDPOINT" ] || fail "No se detectó tu IP pública. Indícala con --vpn-endpoint <IP> (o usa --no-vpn)."
    echo "IP pública detectada: $VPN_ENDPOINT (si tu proveedor la cambia, usa un nombre DNS dinámico con --vpn-endpoint)."
  fi
  set_env CYBERSEG_VPN_ENDPOINT "$VPN_ENDPOINT"
  set_env COMPOSE_FILE "docker-compose.yml:docker-compose.vpn.yml"
  default_env CYBERSEG_VPN_PORT 51820
  default_env CYBERSEG_VPN_PEERS "pc,movil"
  default_env CYBERSEG_VPN_SUBNET 10.13.13.0
  default_env CYBERSEG_VPN_SERVER_IP 10.13.13.1
  VPN_IP="$(env_value CYBERSEG_VPN_SERVER_IP)"
  VPN_NET="$(env_value CYBERSEG_VPN_SUBNET)/24"
  # VPN clients are authenticated peers: never blocked by the active response.
  TRUSTED="$(env_value CYBERSEG_TRUSTED_NETWORKS)"
  case ",$TRUSTED," in
    *",$VPN_NET,"*) ;;
    *) set_env CYBERSEG_TRUSTED_NETWORKS "${TRUSTED:+$TRUSTED,}$VPN_NET" ;;
  esac
  if ss -lunH "sport = :$(env_value CYBERSEG_VPN_PORT)" 2>/dev/null | grep -q . && [ ! -f "$ROOT/vpn/wg_confs/wg0.conf" ]; then
    fail "El puerto UDP $(env_value CYBERSEG_VPN_PORT) ya está en uso. Cambia CYBERSEG_VPN_PORT en $ENV_FILE."
  fi
else
  sed -i '/^COMPOSE_FILE=/d' "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"

HTTPS_PORT="$(env_value CYBERSEG_HTTPS_PORT)"
HTTP_PORT="$(env_value CYBERSEG_HTTP_PORT)"
if [ -z "$(docker compose -f "$ROOT/docker-compose.yml" --project-directory "$ROOT" ps -q frontend 2>/dev/null)" ]; then
  for port in "$HTTPS_PORT" "$HTTP_PORT"; do
    if ss -ltnH "sport = :$port" 2>/dev/null | grep -q .; then
      fail "El puerto $port ya está en uso por otro servicio. Cambia CYBERSEG_HTTPS_PORT/CYBERSEG_HTTP_PORT en $ENV_FILE (p. ej. 8443 y 8080)."
    fi
  done
fi

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

PORT_SUFFIX=""
[ "$HTTPS_PORT" = "443" ] || PORT_SUFFIX=":$HTTPS_PORT"
HTTP_SUFFIX=""
[ "$HTTP_PORT" = "80" ] || HTTP_SUFFIX=":$HTTP_PORT"
FINGERPRINT="$(docker compose exec -T frontend cat /etc/cyberseg/public/fingerprint.txt 2>/dev/null || echo 'consulta: docker compose logs frontend')"
if [ -n "$NEW_PASSWORD" ]; then
  CREDENTIALS="usuario $(env_value CYBERSEG_ADMIN_USER) · contraseña $NEW_PASSWORD  (guárdala; está en $ENV_FILE)"
else
  CREDENTIALS="usuario $(env_value CYBERSEG_ADMIN_USER) · la contraseña de CYBERSEG_ADMIN_PASSWORD en $ENV_FILE"
fi

cat <<EOF

CyberSeg está en marcha y Docker lo reiniciará con el servidor
(asegúrate de tener 'systemctl enable docker').

  Panel web:    https://$SERVER_IP$PORT_SUFFIX/   (solo desde tu red local)
  Acceso:       $CREDENTIALS
  Certificado:  http://$SERVER_IP$HTTP_SUFFIX/certificado  (instálalo una vez en cada equipo)
  Huella CA:    $FINGERPRINT
  Windows:      CyberSeg.exe instala el certificado y abre el panel en su propia ventana.

  Estado:       $ROOT/deploy/check.sh
  Registros:    cd $ROOT && docker compose logs -f engine
  JARVIS:       CYBERSEG_API_TOKEN = el valor de CYBERSEG_ENGINE_TOKEN en $ENV_FILE
EOF

if [ "$VPN" = true ]; then
  cat <<EOF

  Acceso remoto por VPN (desde cualquier red):
    1. En tu router, redirige el puerto UDP $(env_value CYBERSEG_VPN_PORT) a $SERVER_IP. Es el único puerto expuesto.
    2. Instala WireGuard (wireguard.com/install) en el PC o el móvil e importa su perfil:
         PC:     $ROOT/vpn/peer_pc/peer_pc.conf
         Móvil:  escanea el QR de  docker compose exec vpn /app/show-peer movil
    3. Con la VPN activa, abre la misma dirección que en casa: https://$SERVER_IP$PORT_SUFFIX/
       (o CyberSeg.exe con la IP $SERVER_IP). El túnel solo lleva el tráfico de CyberSeg.
    Más dispositivos: añade nombres a CYBERSEG_VPN_PEERS y ejecuta docker compose up -d.
EOF
fi
