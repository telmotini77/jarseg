# CyberSeg: IDS/IPS multicapa con auditoría de vulnerabilidades

CyberSeg protege un servidor Linux y su segmento de red. Combina cuatro defensas:

1. **Detección por comportamiento**: 13 detectores propios cubren las capas 2, 3, 4 y 7 (ARP spoofing, escaneos, floods, fuerza bruta, túneles DNS, C2…).
2. **Detección por firmas**: Suricata con Emerging Threats Open, unas 53.000 reglas activas contra exploits, CVE, malware, C2 y IPs de mala reputación.
3. **Prevención (IPS)**: bloquea automáticamente en el firewall del servidor (nftables) a los atacantes de riesgo alto o crítico.
4. **Auditoría de vulnerabilidades**: revisa los servicios expuestos, el endurecimiento del kernel, SSH y el firewall del propio servidor, además de los protocolos inseguros que circulan por la red.

Cada alerta se clasifica con su severidad, categoría, técnica **MITRE ATT&CK** y **capa OSI**. Se guarda en PostgreSQL, se muestra en vivo en el dashboard y llega a JARVIS (y de ahí a Telegram).

## Arquitectura

```
                tráfico de la interfaz (eth0 / ens33)
                 │                              │
   ┌─────────────▼─────────────┐   ┌────────────▼────────────┐
   │ engine (Python, scapy)    │   │ suricata (ET Open)      │
   │ 13 detectores L2-L7       │◄──┤ eve.json (solo alertas) │
   │ Isolation Forest (ML)     │   └─────────────────────────┘
   │ auditoría del servidor    │   suricata-update: reglas nuevas cada 24 h
   │ respuesta activa nftables ├──► firewall del host (bloqueos con caducidad)
   └─────────────┬─────────────┘
                 │ HTTP + token (127.0.0.1:8780)
   ┌─────────────▼─────────────┐      ┌───────────────────────────┐
   │ backend NestJS + Postgres ├─────►│ frontend React + nginx    │
   │ alertas, bloqueos,        │  WS  │ (proxy de solo lectura)   │
   │ hallazgos, estadísticas   │      └───────────────────────────┘
   └─────────────┬─────────────┘
                 └──► JARVIS (estado, alertas, avisos por Telegram)
```

## Cobertura

| Capa | Detección | MITRE | Riesgo | Respuesta |
|---|---|---|---|---|
| L2 | ARP spoofing (la MAC de una IP cambia; la de la puerta de enlace siempre) | T1557.002 | alto / crítico | alerta |
| L2 | Envenenamiento ARP activo (flood de respuestas) | T1557.002 | alto | alerta |
| L2 | Inundación de MACs (desbordamiento de la tabla CAM) | T1557 | alto | alerta |
| L2 | Servidor DHCP no autorizado | T1557.003 | crítico | alerta |
| L2 | Router Advertisement IPv6 no autorizado | T1557 | alto | alerta |
| L2 | Descubrimiento de equipos por ARP | T1018 | medio | alerta |
| L3 | Ping sweep | T1018 | alto | **bloqueo** |
| L3 | Flood ICMP | T1498.001 | alto | **bloqueo** |
| L3 | Smurf (ping a difusión) | T1498.002 | medio | alerta |
| L3 | Redirección ICMP | T1557 | medio | alerta |
| L3 | Ataque LAND, IP de origen falsificada (bogon) | T1498 | alto / medio | alerta |
| L3 | Fragmentos diminutos (evasión) y flood de fragmentos | T1498.001 | alto | **bloqueo** |
| L4 | Escaneo de puertos SYN/connect y UDP | T1046 | alto | **bloqueo** |
| L4 | Escaneo sigiloso NULL / FIN / XMAS | T1046 | alto | **bloqueo** |
| L4 | Barrido horizontal (un puerto en muchos equipos) | T1046 | alto | **bloqueo** |
| L4 | SYN flood de un origen | T1498.001 | alto | **bloqueo** |
| L4 | SYN flood distribuido (DDoS) | T1498.001 | crítico | alerta |
| L4 | Flood UDP | T1498.001 | alto | **bloqueo** |
| L4 | DDoS por reflexión/amplificación (DNS, NTP, SSDP, memcached…) | T1498.002 | crítico | alerta |
| L4 | Exfiltración por volumen saliente | T1048 | medio | alerta |
| L4 | Anomalías estadísticas (Isolation Forest) | — | medio / alto | alerta |
| L7 | Fuerza bruta (SSH, RDP, SMB, FTP, bases de datos, VNC, Redis…) | T1110 | alto | **bloqueo** |
| L7 | Escaneo de rutas web (ráfagas de 404) | T1595.003 | alto | **bloqueo** |
| L7 | Túnel DNS / exfiltración por DNS | T1071.004 | alto / medio | alerta |
| L7 | Malware con DGA (ráfagas de NXDOMAIN) | T1568.002 | medio | alerta |
| L7 | Beaconing periódico hacia un servidor externo (C2) | T1071 | medio | alerta |
| L7 | Movimiento lateral (SMB/RDP/WinRM/SSH hacia muchos equipos internos) | T1021 | alto / medio | alerta |
| L7 | **Suricata**: exploits y CVE (Log4Shell, SQLi, RCE…), malware, C2, IPs en listas negras | según regla | según regla | **bloqueo** si alto/crítico |

Las detecciones que no se mitigan bloqueando una IP solo generan alerta. Es el caso de los orígenes falsificados, los ataques de capa 2 en los que la IP es la de la víctima, los reflectores legítimos y los clientes internos que hay que revisar. Cada origen genera una sola alerta por tipo cada `CYBERSEG_ALERT_COOLDOWN_SECONDS`.

### Vulnerabilidades y exposición

| Origen | Qué detecta |
|---|---|
| Auditoría del servidor (cada 6 h) | Servicios peligrosos escuchando hacia la red (Telnet, FTP, SMB, RDP, Redis, MongoDB, Elasticsearch, API de Docker sin TLS, bases de datos…) e inventario de puertos abiertos |
| | Kernel: SYN cookies, filtrado de ruta inversa, redirecciones ICMP, source routing, respuesta a pings de difusión, registro de martians |
| | SSH: acceso root, contraseñas vacías, autenticación por contraseña, X11, `MaxAuthTries` |
| | Firewall de entrada sin política «denegar por defecto» |
| Tráfico observado | Telnet; credenciales FTP, POP3, IMAP o HTTP Basic sin cifrar; SMBv1 (EternalBlue); SSL 3.0 / TLS 1.0 / 1.1 negociados; SNMP v1/v2c y comunidades por defecto |

Cada hallazgo incluye la recomendación concreta para corregirlo. Cuando la auditoría deja de encontrarlo, se marca como resuelto.

## Prevención (bloqueo automático)

- **Bloqueo:** se bloquean las IPs de alertas de riesgo `high` o `critical` que sean bloqueables, en el tráfico de entrada, de salida y reenviado. Esto también protege los servicios publicados por Docker.
- **Caducidad:** cada bloqueo vive en un conjunto de nftables con caducidad propia, así que se levanta solo aunque el motor se detenga. La primera vez dura 1 h y cada reincidencia lo multiplica por 4, hasta un máximo de 7 días. Si un mismo ataque dispara varias firmas, cuenta como una sola infracción.
- **Direcciones nunca bloqueadas:**
  - el propio servidor, su puerta de enlace y sus servidores DNS;
  - loopback, multicast y difusión;
  - las redes de `CYBERSEG_TRUSTED_NETWORKS`. `install.sh` añade ahí automáticamente la IP desde la que administras por SSH.
- **Malware que llama al exterior:** si es este servidor el que contacta con un servidor malicioso, se bloquea el destino.
- **Modos** (`CYBERSEG_PREVENTION_MODE`):
  - `block`: bloquea;
  - `dry-run`: solo registra lo que habría bloqueado;
  - `alert`: nunca toca el firewall.

Para desbloquear una IP:

```bash
curl -X POST http://127.0.0.1:8780/api/blocks/unblock \
  -H "Content-Type: application/json" -H "X-CyberSeg-Engine-Token: <CYBERSEG_ENGINE_TOKEN>" \
  -d '{"ip":"203.0.113.9"}'
```

## Despliegue con Docker en Linux

Requisitos: Docker Engine con el plugin `docker compose`, en el servidor Linux cuyo tráfico quieres vigilar, con **4 GB de RAM** (Suricata usa 1–2 GB). Los sensores usan `network_mode: host` para ver la interfaz real y gestionar su firewall. Por eso funcionan en Linux, no en Docker Desktop para Windows o macOS.

Lo más sencillo es usar el instalador:

```bash
./deploy/install.sh               # o: ./deploy/install.sh --interface ens33
```

El instalador hace todo esto:
- detecta la interfaz;
- genera secretos aleatorios;
- marca tu IP SSH como de confianza;
- configura `HOME_NET` de Suricata con la IP del servidor;
- arranca los contenedores y verifica los cuatro sensores.

También puedes hacerlo a mano:

```bash
cp .env.example .env
openssl rand -hex 32   # CYBERSEG_ENGINE_TOKEN
openssl rand -hex 20   # POSTGRES_PASSWORD
```

En `.env` define al menos esto:

```dotenv
CYBERSEG_CAPTURE_ALLOWED=true
CYBERSEG_INTERFACE=eth0
CYBERSEG_CAPTURE_AUTOSTART=true
CYBERSEG_TRUSTED_NETWORKS=<IP desde la que administras>
CYBERSEG_HOME_NET=[<IP del servidor>/32,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]
```

Después arranca y verifica:

```bash
docker compose up -d --build
./deploy/check.sh
```

Todos los servicios tienen `restart: unless-stopped` y registros limitados (5 × 10 MB). La base de datos conserva 90 días (`CYBERSEG_RETENTION_DAYS`).

### Ubuntu Server en una máquina virtual

**1. Red de la VM.** Es lo más importante: CyberSeg solo ve el tráfico que llega a la tarjeta de red de la VM. Configura el adaptador en modo puente:

| Hipervisor | Adaptador |
|---|---|
| VirtualBox | "Adaptador puente". En NAT (IP `10.0.2.15`) ningún equipo de la LAN alcanza la VM. |
| VMware Workstation / Player | "Bridged" |
| Hyper-V | Conmutador virtual **externo** |
| Proxmox | Puente `vmbr0` |

Ver el tráfico entre *otros* equipos exige además el modo promiscuo del hipervisor y un puerto espejo (SPAN) en el switch.

**2. Recursos.** 2 vCPU, 4 GB de RAM y 20 GB de disco.

**3. Docker.** En el instalador de Ubuntu Server marca "Install OpenSSH server" y **no** marques el snap `docker`. Después:

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-v2 git
sudo systemctl enable --now docker
sudo usermod -aG docker $USER    # cierra la sesión y vuelve a entrar
```

**4. Instalación.** Copia la carpeta `CyberSeg` a la VM y ejecuta `./deploy/install.sh` **desde la sesión SSH de tu PC**, para que tu IP quede como de confianza.

**5. Conexión desde Windows.** Abre un túnel SSH:

```powershell
ssh -N -L 5178:127.0.0.1:5178 -L 8780:127.0.0.1:8780 usuario@IP-de-la-VM
```

Con el túnel abierto:
- el dashboard queda en `http://127.0.0.1:5178`;
- JARVIS funciona con `CYBERSEG_API_URL=http://127.0.0.1:8780`.

Para publicar el dashboard en la LAN, define `CYBERSEG_DASHBOARD_USER`, `CYBERSEG_DASHBOARD_PASSWORD` y `CYBERSEG_DASHBOARD_BIND=0.0.0.0`. Docker publica los puertos por delante de `ufw`.

### Probar la detección y la prevención

Hazlo desde **otro equipo tuyo que no esté en `CYBERSEG_TRUSTED_NETWORKS`** y solo contra tu propio servidor:

```bash
nmap -sS -p 1-200 <ip-del-servidor>   # escaneo SYN → alerta HIGH y bloqueo
nmap -sX -p 20-30 <ip-del-servidor>   # escaneo XMAS → alerta HIGH y bloqueo
curl -A '${jndi:ldap://x/a}' http://<ip-del-servidor>/   # Log4Shell → firma de Suricata (si hay un servicio web)
```

Desde un equipo de confianza las alertas aparecen igual, pero sin bloqueo (respuesta "No bloqueada"). El tráfico que el servidor se envía a sí mismo no pasa por la interfaz y no se ve.

### Diagnóstico

| Síntoma | Causa probable |
|---|---|
| "El motor no envía latidos" | Revisa `docker compose logs engine`. Si da 401, el token del motor y el del backend no coinciden. |
| Captura `BLOQUEADA` / `DETENIDA` | `CYBERSEG_CAPTURE_ALLOWED` o `CYBERSEG_CAPTURE_AUTOSTART` están en `false` |
| Prevención `NO DISPONIBLE` | El motor no tiene `NET_ADMIN` o falla `nft` (revisa los registros del motor) |
| Suricata `SIN DATOS` | Falta `COMPOSE_PROFILES=suricata`, o Suricata no tiene RAM: `docker compose logs suricata` |
| Captura activa pero 0 paquetes | La interfaz elegida no es la que lleva el tráfico |
| Te bloqueaste a ti mismo | Desde la consola de la VM: `docker compose exec engine nft flush set inet cyberseg blocked4`. Después añade tu IP a `CYBERSEG_TRUSTED_NETWORKS`. |

## Límites conocidos

- **Tráfico cifrado (HTTPS, SSH):** su contenido no se inspecciona. Se detectan sus patrones (fuerza bruta, beaconing, volumen, reputación) y los exploits en protocolos sin cifrar o en servicios donde termines TLS.
- **Zero-days sin firma:** solo se ven si su comportamiento es anómalo.
- **DDoS volumétricos:** se detectan, pero solo se mitigan aguas arriba, con tu proveedor o un servicio anti-DDoS.
- **Rendimiento:** el motor en Python está pensado para el tráfico de un servidor o una oficina pequeña, hasta decenas de miles de paquetes por segundo. Suricata, escrito en C, asume la inspección profunda.

## Integración con JARVIS

En el `.env` de JARVIS configura:
- `CYBERSEG_ENABLED=true`;
- la URL local;
- `CYBERSEG_API_TOKEN` igual a `CYBERSEG_ENGINE_TOKEN`.

Si JARVIS corre en Docker en el mismo servidor, usa `docker compose -f docker-compose.yml -f docker-compose.server.yml up -d`. Deja `CYBERSEG_SERVER_AUTO_BLOCK=false`: el bloqueo ya lo hace CyberSeg.

- `Jarvis dime el estado de CyberSeg`: captura, IPs bloqueadas y estado de Suricata.
- `Jarvis muéstrame las alertas de CyberSeg`: alertas clasificadas por familia de amenaza.
- `Jarvis inicia la captura de CyberSeg` (exige confirmación) / `Jarvis detén la captura de CyberSeg`.

Con `CYBERSEG_MONITOR_ENABLED=true`, JARVIS avisa de cada alerta `HIGH`/`CRITICAL`.

## Desarrollo y pruebas

```bash
cd engine && pip install -r requirements.txt pytest && pytest   # 67 pruebas (detectores, Suricata, IPS, auditoría)
cd backend && npm ci && npm run build
cd frontend && npm ci && npm run dev                            # proxy a la API en 127.0.0.1:8780
```
