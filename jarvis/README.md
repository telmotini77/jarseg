# JARVIS v1.4 — Aplicación de escritorio y perfiles multiusuario

## JARVIS Desktop (interfaz principal)

JARVIS se inicia como una aplicación nativa de Windows, no como una página en
Chrome. El HUD se dibuja con el Canvas local de Tkinter y se conecta de forma
directa al core Python: no usa navegador, HTTP, WebSocket ni una webview para
la interacción normal. Muestra estado del núcleo, telemetría, perfil activo,
agentes y una consola de conversación dentro de la propia ventana.

Inícialo con doble clic en `run_desktop.pyw`, con
`launch_jarvis_desktop.bat`, o desde PowerShell:

```powershell
py main.py --desktop
```

`Esc` cierra la app, `F11` alterna pantalla completa y `Ctrl+Espacio` enfoca
la caja de comandos. El panel anterior queda disponible solamente mediante
`py main.py --legacy-panel`.

El HUD nativo incluye el estado local del IDS CyberSeg junto con los agentes,
telemetría y conversación. Es la interfaz principal de escritorio: no depende
de un navegador ni expone el control del equipo por Internet.

Para crear un ejecutable sin ventana de consola:

```powershell
.\build_desktop.ps1
```

El resultado es `dist\JARVIS\JARVIS.exe`. Copia o crea un `.env` junto al
ejecutable con tu configuración local; el empaquetado no transporta claves,
contraseñas ni sesiones del proyecto.

Browser media commands use the Browser Agent and DOM/media APIs:
`reproduce <title> en YouTube`, `pausa`, `continúa`, `sube el volumen`, `baja el
volumen` and `pon pantalla completa`. It never falls back to screen coordinates.

JARVIS can control a visible, dedicated Google Chrome profile for research and
navigation: `busca APIs de OpenAI en Chrome`, `abre el primer resultado`, `lee
esta página`, `resume esta página` and `consulta precios de SSD`. It can read,
navigate and fill non-sensitive fields; clicks, form submissions, downloads,
credentials, payments and system changes always remain protected by explicit
confirmation or are blocked.

El navegador se llama **Survivor**. Su Search Engine v1 se ejecuta
dentro de ese navegador administrado y soporta Google, Bing,
DuckDuckGo and YouTube: `busca routers GPON en Bing`, `busca tutoriales de
FastAPI en YouTube`, `abre el primer resultado` and `historial de búsquedas`.
It normalizes result links, ranks visible matches and never bypasses CAPTCHA or
site access controls.

Survivor es un navegador asistido, no un índice web propio: usa Google
Chrome como motor de renderizado mediante un perfil aislado de JARVIS y usa los
proveedores configurados para obtener resultados. Incluye pestañas, atrás,
adelante, recarga, inicio, lectura y resumen de página, búsqueda de texto y
relleno de campos no sensibles. Di `Jarvis abre Survivor`, `Jarvis ve al
inicio` o `Jarvis qué es Survivor`.

Project Builder converts a detailed prompt into a reviewed local scaffold. Say
`crea un proyecto para una API de inventario con FastAPI y pruebas`; JARVIS
shows every proposed file and its diff. Say `crea el proyecto propuesto` and
confirm before it writes anything under `PROJECT_BUILDER_ROOT`.

Docker is headless and is not the Windows app: it can run the local API at
`http://127.0.0.1:8766` for integrations or testing, while JARVIS Desktop runs
on the Windows host. The optional web dashboard is disabled by default; enable
it deliberately with `py main.py --dashboard` or `DASHBOARD_ENABLED=true`.

## JARVIS Mobile

La versión móvil es una PWA instalable y de solo consulta. Abre `/mobile`
desde el servidor de JARVIS y usa “Añadir a pantalla de inicio” en Android o
iPhone. Muestra el estado de JARVIS, conectividad y alertas recientes de
CyberSeg; no puede iniciar una captura, cambiar un firewall, ejecutar comandos
ni ver claves.

Por seguridad, el contenedor de ejemplo se publica únicamente en
`127.0.0.1:8766`; por ello un teléfono no debe exponerse directamente a ese
puerto ni a CyberSeg. Para usar la app en otro dispositivo hace falta una red
privada autenticada y HTTPS, además de decidir explícitamente qué teléfonos
podrán acceder. JARVIS queda preparado como compañera móvil, pero no abre la
red local ni Internet por defecto.

### Emparejamiento y credenciales móviles

El APK ofrece dos controles de conexión: **URL privada HTTPS** para una VPN o
gateway privado, y **Wi‑Fi local HTTPS** para una red doméstica/empresarial
confiable. Ambas alternativas requieren HTTPS, un token distinto por móvil y
no incluyen el token dentro del APK. Android lo guarda cifrado con su almacén
de credenciales. El servidor solo entrega el resumen de estado y CyberSeg al
endpoint móvil; no expone perfiles, métricas completas, comandos ni controles
de firewall.

En el servidor, configura un token largo y único antes de activar la API:

```dotenv
MOBILE_API_ENABLED=true
MOBILE_API_TOKEN=un_token_largo_unico_de_al_menos_24_caracteres
```

El token se introduce una sola vez en JARVIS Mobile. Para usar Wi‑Fi local,
la URL HTTPS debe ser alcanzable desde el teléfono y tener un certificado que
el dispositivo confíe; para acceso fuera de casa/oficina usa una VPN privada o
gateway HTTPS autenticado. No publiques el puerto de JARVIS ni CyberSeg en
Internet directamente.

## Servicio en segundo plano

El modo servicio mantiene activos el API local, recordatorios, automatizaciones
y el monitor de CyberSeg sin abrir el HUD, el micrófono ni TTS. En Windows se
puede iniciar con `launch_jarvis_service.bat` o `py main.py --service`.

Para una ejecución resiliente en segundo plano con reinicio tras un fallo, usa
Docker:

```powershell
docker compose up --build -d
docker compose logs -f jarvis
```

El contenedor solo publica `127.0.0.1:8766`; no convierte JARVIS en un servicio
público. Sus controles de mouse, teclado, ventanas y captura de pantalla quedan
aislados, porque un contenedor no debe manejar el escritorio de Windows. Deténlo
con `docker compose down`.

## Alertas rápidas por Telegram

Las alertas IoT, los recordatorios y las notificaciones de automatizaciones se
encolan primero en un worker local de Telegram; la voz se reproduce aparte y
nunca retrasa el envío. El worker reutiliza la conexión HTTPS, elimina avisos
idénticos durante tres segundos y reintenta una vez sin bloquear JARVIS.

Configura estas variables en tu `.env` (no compartas el token):

```dotenv
TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=token_entregado_por_BotFather
TELEGRAM_CHAT_ID=tu_chat_id_o_canal
```

## CyberSeg IDS local

El proyecto hermano `..\CyberSeg` reconstruye el IDS defensivo: motor Python
de captura local opcional, Isolation Forest, API NestJS/Prisma/PostgreSQL y
dashboard React. JARVIS solo se conecta por loopback para consultar estado y
alertas; iniciar la captura exige confirmación y una interfaz previamente
autorizada.

```dotenv
CYBERSEG_ENABLED=true
CYBERSEG_API_URL=http://127.0.0.1:8780
CYBERSEG_API_TOKEN=el_mismo_CYBERSEG_ENGINE_TOKEN_de_CyberSeg
CYBERSEG_MONITOR_ENABLED=true
CYBERSEG_MONITOR_POLL_SECONDS=15
```

Comandos: `Jarvis dime el estado de CyberSeg`, `Jarvis muéstrame las alertas
de CyberSeg`, `Jarvis inicia la captura de CyberSeg` y `Jarvis detén la captura
de CyberSeg`. El estado incluye la interfaz, los paquetes analizados y los
escaneos de puertos detectados por el motor.

En un servidor Linux con CyberSeg en Docker, `host.docker.internal` apunta al
puente `docker0` y no alcanza la API publicada solo en `127.0.0.1`. Arranca
JARVIS con la red del host para que use la URL de loopback:

```bash
docker compose -f docker-compose.yml -f docker-compose.server.yml up -d --build
```

Con este modo, la API de JARVIS escucha en `127.0.0.1:8766` del servidor.

Con el monitor activo, JARVIS consulta CyberSeg cada 15 segundos y avisa por
Telegram de tres resultados: una revisión limpia del radar y del sistema, una
interferencia `HIGH`/`CRITICAL`, o una vulneración `HIGH`/`CRITICAL`. Las
revisiones limpias se limitan al intervalo configurado y los riesgos
`LOW`/`MEDIUM` quedan en el registro local. Los avisos de estado
solo se notifican si se activa
`CYBERSEG_MONITOR_NOTIFY_SERVICE_STATE=true`. Al iniciar no reenvía alertas
antiguas, salvo que se configure `CYBERSEG_MONITOR_NOTIFY_EXISTING=true`.
Cada lectura local se reintenta dos veces con espera exponencial; las acciones
de captura no se repiten automáticamente. JARVIS exige tres ciclos fallidos
consecutivos antes de tratar CyberSeg como caído y, si la caída persiste,
reduce gradualmente la frecuencia de consulta hasta un máximo configurado.
Al recuperarse vuelve inmediatamente a su frecuencia normal. Una demora en las
alertas o en el estado del motor no desconecta al servicio de monitoreo. Puedes
ajustar estos valores con `CYBERSEG_HTTP_RETRY_ATTEMPTS`,
`CYBERSEG_MONITOR_RETRY_ATTEMPTS`, `CYBERSEG_MONITOR_FAILURE_THRESHOLD` y
`CYBERSEG_MONITOR_MAX_POLL_SECONDS`.
La severidad mínima de los avisos se ajusta con
`CYBERSEG_MONITOR_MIN_RISK=high`. También se envía el reporte
"no se detectaron interferencias ni vulnerabilidades" al iniciar una revisión limpia y como máximo
una vez cada 24 horas; el intervalo se cambia con
`CYBERSEG_MONITOR_CLEAN_REPORT_SECONDS=86400`.

### Inteligencia defensiva local

JARVIS incorpora una taxonomía local para enriquecer las alertas de CyberSeg:
reconocimiento, credenciales, phishing, malware/ransomware, explotación web,
denegación de servicio, intercepción de red, movimiento lateral, mando y
control, exfiltración, identidad en la nube, cadena de suministro,
interferencias inalámbricas, IoT y riesgo interno. No ejecuta, genera ni
enseña ataques: clasifica evidencias ya detectadas y propone el foco de
contención. Consulta su cobertura con `Jarvis muéstrame el entrenamiento de
CyberSeg`; las alertas mostradas por JARVIS se etiquetan automáticamente.

## Perfiles de protección: escritorio y servidor Linux

CyberSeg incluye su propia prevención: bloquea en nftables, con caducidad, a
los atacantes de riesgo alto. Si lo usas, deja `CYBERSEG_SERVER_AUTO_BLOCK=false`
para no duplicar bloqueos. El bloqueo de JARVIS queda para instalaciones de
CyberSeg con `CYBERSEG_PREVENTION_MODE=alert`.

El perfil `desktop` es el predeterminado: analiza las alertas y las comunica a
Telegram, sin cambiar la red del equipo. El perfil `server` funciona en Linux
sin HUD, micrófono ni controles de escritorio. Ante una alerta CyberSeg de
riesgo `HIGH` o `CRITICAL`, puede añadir una regla de bloqueo de entrada para
la IP de origen y enviar a Telegram tanto la anomalía como el resultado.

```dotenv
CYBERSEG_DEPLOYMENT_PROFILE=server
CYBERSEG_SERVER_AUTO_BLOCK=true
CYBERSEG_SERVER_FIREWALL=auto
CYBERSEG_SERVER_MIN_RISK=high
# Incluye siempre la IP o red desde la que administras el servidor.
CYBERSEG_SERVER_ALLOWLIST=203.0.113.10/32
```

Inicia el servidor con `python main.py --server`. Para modificar el firewall,
el proceso debe ejecutarse con la capacidad de administración de red ya
concedida; JARVIS no invoca `sudo`, no cambia políticas globales ni abre puertos.
Detecta `firewalld`, `ufw`, `nftables` e `iptables`, por lo que sirve en las
distribuciones Linux que usen cualquiera de ellos. Las IP privadas se omiten de
forma predeterminada para evitar aislar la red interna; se pueden habilitar con
`CYBERSEG_SERVER_ALLOW_PRIVATE_SOURCES=true` después de definir la lista de
permitidos.

En Docker, JARVIS llega al backend local de CyberSeg por
`host.docker.internal`; ejecuta también el `docker compose up -d` del proyecto
`..\CyberSeg`. Ambos puertos permanecen ligados al equipo local. Para que un
contenedor pueda proteger el host necesitaría acceso explícito al firewall del
host; para el perfil servidor se recomienda ejecutar JARVIS directamente en el
sistema Linux.

v1.4 conserva Voice System, Memory Engine, Dashboard, Orchestrator, Automation
Engine, Productivity, Browser, Terminal, Code, IoT y Security Manager, y añade
perfiles locales independientes. Cada perfil tiene UUID, rol, preferencias, voz,
proyecto/dispositivo predeterminado y sesión propia.

```text
User
├── Preferences / Voice profile / Permissions
├── Private memories and conversations
├── Projects / Automations / Integrations
└── Notifications and dashboard preferences
```

Los roles son `owner`, `standard` y `guest`; las políticas globales de seguridad
siempre tienen precedencia. El cambio de perfil borra la memoria de trabajo y
filtra los recuerdos privados por `user_id`. La primera migración hace una copia
de seguridad y asigna los datos heredados al perfil Owner. No hay servidor público,
biometría obligatoria, ni cookies compartidas entre perfiles.

La API local incluye `/api/users`, `/api/users/me`, preferencias y endpoints de
sesión (login, logout, lock y switch). El Dashboard ofrece Profile y Users; la
administración de perfiles queda restringida al Owner.

## JARVIS v1.5 roadmap

Mobile app + remote control: notificaciones push, tareas, automatizaciones, IoT,
voz móvil, QR pairing y autorización de dispositivos.

---

El dashboard React permanece como una herramienta local y opcional para
integraciones, sin sustituir la aplicación nativa, voz, TTS, agentes, MQTT,
memoria ni las confirmaciones de seguridad. No se abre automáticamente.

```text
                  JARVIS CORE
                       │
                Orchestrator
                       │
  Code · Browser · Terminal · IoT · Memory · Vision
                       │
                   Event Bus
                       │
            FastAPI + WebSocket local
                       │
             JARVIS Desktop (Tkinter nativo)
```

El dashboard contiene Dashboard, Agents, Tasks, Automation, Terminal, Code, Browser, IoT, Memory, History, Logs, Security y Settings. Los datos se actualizan por WebSocket y con una actualización moderada de métricas. No muestra razonamiento privado: solo objetivos, pasos, estados, resultados y errores resumidos.

## Seguridad del dashboard

- Solo se liga a `127.0.0.1`, `localhost` o `::1`; no existe configuración pública en v1.1.
- Las operaciones que cambian estado exigen un token efímero de sesión local y validación de origen.
- El navegador no recibe secretos, claves API, contraseñas MQTT, tokens ni cabeceras de autorización.
- El campo “Ask JARVIS” utiliza exactamente `Jarvis.process`, por lo que conserva parser, allow-lists, clasificador de riesgo y confirmaciones de voz.
- No hay endpoint para PowerShell, filesystem, MQTT ni ejecución arbitraria. Las automatizaciones admiten únicamente acciones registradas.

## Desarrollo y dashboard opcional

```powershell
cd dashboard
npm install
npm run build
cd ..
py -m pip install -r requirements.txt
py main.py --desktop
```

El build se guarda en `dashboard/dist` y FastAPI lo sirve directamente: Node no es necesario para la ejecución final. Para desarrollo visual separado puede usarse `npm run dev`; el backend sigue siendo el proceso Python local.

Configuración relevante:

```dotenv
DASHBOARD_ENABLED=false
DASHBOARD_HOST=127.0.0.1
DASHBOARD_PORT=8765
DASHBOARD_AUTO_OPEN=false
DASHBOARD_WS_ENABLED=true
DASHBOARD_SYSTEM_METRICS_INTERVAL=2
DASHBOARD_TELEMETRY_INTERVAL=2
```

---

# JARVIS v1.0 — Orquestador multiagente + Automation Engine

JARVIS v1.0 conserva voz/TTS, Windows, navegador, terminal, memoria, código y ESP32/MQTT; añade un Event Bus central, un registro de agentes y un orquestador que coordina tareas estructuradas. No ejecuta planes ni automatizaciones provenientes de texto libre: cada agente, acción, dependencia, recurso y nivel de riesgo se valida antes de ejecutarse.

```text
Voz → Router determinista → confirmación → Orquestador → agentes registrados
                                      ↘ Event Bus ↔ Automation Engine local
```

Agentes registrados: `conversation`, `memory`, `system`, `browser`, `terminal`, `code`, `iot`, `vision` y `automation`. Los resultados se entregan como datos estructurados y se resumen para la respuesta de voz. Los eventos y las automatizaciones nunca conceden permisos por sí mismos.

## Comandos v1.0

Di `Jarvis` antes de cada orden:

- `Jarvis dime qué agentes tienes disponibles`
- `Jarvis dime el estado de tus agentes`
- `Jarvis activa modo solo lectura`
- `Jarvis activa modo asistido`
- `Jarvis revisa CyberSeg y dime qué quedó pendiente` — confirmación
- `Jarvis abre CyberSeg y ejecuta tests` — confirmación
- `Jarvis corrige el primer error` — prepara una corrección revisable, sin aplicar parches libremente
- `Jarvis busca documentación oficial para este error` — confirmación
- `Jarvis abre VS Code, inicia backend y abre navegador` — plan validado y confirmación
- `Jarvis dime estado del ESP32 y backend` — plan de consulta
- `Jarvis estado del orquestador`
- `Jarvis cancela la tarea actual`
- `Jarvis crea modo programación` — automatización manual para abrir VS Code, con confirmación
- `Jarvis ejecuta modo programación` — confirmación
- `Jarvis crea una automatización preparar mi entorno cada mañana a las 8` — recordatorio local programado
- `Jarvis cuando ESP32 laboratorio se desconecte avísame` — evento IoT local, con confirmación
- `Jarvis dime automatizaciones`
- `Jarvis desactiva modo programación`

Las automatizaciones se guardan en SQLite local. Solo admiten triggers manuales, horarios diarios o eventos explícitos y acciones registradas. Las acciones de riesgo no seguro no se ejecutan automáticamente. No hay ejecución de shell, código, MQTT arbitrario, credenciales ni automatizaciones creadas desde contenido web o texto de un modelo.

Configura los interruptores de v1.0 en `.env` a partir de `.env.example`:

```dotenv
ORCHESTRATOR_ENABLED=true
ORCHESTRATOR_MODE=assist
ORCHESTRATOR_MAX_RETRIES=2
ORCHESTRATOR_MAX_PARALLEL_TASKS=3
AUTOMATION_ENGINE_ENABLED=true
AUTOMATION_MAX_ACTIONS=8
AUTOMATION_COOLDOWN_SECONDS=60
AUTOMATION_POLL_SECONDS=20
```

---

# JARVIS v0.9 — ESP32 + MQTT IoT Agent

JARVIS v0.9 añade un IoT Agent para ESP32 y MQTT sin sustituir las versiones anteriores: voz y TTS, control de Windows, visión, wake word, persistencia, recordatorios, rutinas, Browser Agent, Terminal Agent, Memory Engine 2.0 y Code Agent/VS Code continúan disponibles.

## Arquitectura segura

```text
Voz → Intent Classifier → IoT Agent → Device Registry → Validator
     → MQTT Action Registry → confirmación (si aplica) → MQTT Provider → ESP32

ESP32 → MQTT → payload/topic validation → Telemetry + State → Rules → alertas
```

El modelo, una página web, un recuerdo o un dispositivo MQTT no pueden publicar libremente. Cada acción se resuelve contra un dispositivo registrado, confiable, online y con la capacidad declarada.

## MQTT y dispositivos

El proveedor por defecto usa `paho-mqtt` en un loop de fondo, por lo que la voz, el navegador, el terminal y los recordatorios no quedan bloqueados. El broker se configura solo desde `.env`; credenciales, contraseñas y certificados no se registran en logs.

Topics administrados:

```text
<MQTT_TOPIC_PREFIX>/devices/<device_id>/telemetry
<MQTT_TOPIC_PREFIX>/devices/<device_id>/state
<MQTT_TOPIC_PREFIX>/devices/<device_id>/command
<MQTT_TOPIC_PREFIX>/devices/<device_id>/status
<MQTT_TOPIC_PREFIX>/devices/<device_id>/ack
<MQTT_TOPIC_PREFIX>/discovery/announce
```

No se aceptan `#`, `+`, `..`, topics fuera del namespace ni `publish(topic, payload)` arbitrario por voz. Los comandos son JSON con `request_id`; hasta recibir un ACK, JARVIS no afirma que un actuador haya cambiado.

Los ESP32 descubiertos empiezan con `trusted=false`. Un anuncio MQTT nunca autoriza comandos. El registro explícito por voz sí solicita confirmación y concede confianza al dispositivo indicado.

## Configuración MQTT

1. Copia `.env.example` a `.env` y configura el broker.
2. Para desarrollo puedes usar `broker.emqx.io`; para uso real utiliza un broker privado, TLS, autenticación y ACLs.
3. Define un `MQTT_TOPIC_PREFIX` propio, por ejemplo `jarvis/dev-001`.
4. Configura y carga uno de los ejemplos ESP32 con tus credenciales Wi‑Fi y broker.
5. Ejecuta JARVIS y di `Jarvis conecta MQTT`.
6. Verifica que el ESP32 publique `online` en su topic `status`.

```dotenv
IOT_ENABLED=true
MQTT_BROKER_HOST=broker.emqx.io
MQTT_BROKER_PORT=1883
MQTT_USERNAME=
MQTT_PASSWORD=
MQTT_USE_TLS=false
MQTT_CLIENT_ID=jarvis-desktop
MQTT_KEEPALIVE=60
MQTT_DEFAULT_QOS=1
MQTT_RECONNECT_ENABLED=true
MQTT_RECONNECT_MAX_SECONDS=30
MQTT_TOPIC_PREFIX=jarvis/dev-001
MQTT_MAX_PAYLOAD_BYTES=16384
IOT_TELEMETRY_RETENTION_DAYS=30
IOT_COMMAND_TIMEOUT=5
IOT_RULE_COOLDOWN_SECONDS=60
IOT_DEFAULT_DEVICE=
IOT_VERBOSE_TELEMETRY_LOG=false
```

Con `MQTT_USE_TLS=true` usa normalmente el puerto `8883`; para desarrollo no TLS suele usarse `1883`. Mosquitto es una alternativa adecuada para instalar y ejecutar un broker local; JARVIS no lo instala ni modifica automáticamente.

## Telemetría, estado y reglas

La telemetría se persiste en SQLite local durante 30 días por defecto (`iot_telemetry`), no en Memory Engine. Memory Engine solo conserva el nombre, capacidades y contexto lógico de un dispositivo registrado. El estado actual y los comandos se guardan en `iot_devices` e `iot_command_history`; las reglas persisten en `iot_rules`.

Payload de telemetría aceptado:

```json
{
  "device_id": "esp32-lab",
  "timestamp": 1720000000,
  "sensors": {"temperature": 24.8, "humidity": 61.2, "ldr": 723},
  "units": {"temperature": "°C", "humidity": "%"}
}
```

Payload de comando enviado:

```json
{"command":"set_led","value":true,"request_id":"..."}
```

ACK esperado:

```json
{"device_id":"esp32-lab","request_id":"...","success":true,"command":"set_led"}
```

Las reglas usan únicamente `>`, `<`, `>=`, `<=` y `==`, nunca `eval()`. Incluyen cooldown configurable para no repetir una alerta cada segundo. Las reglas de aviso y de LED se crean confirmadamente; acciones peligrosas no se automatizan libremente.

## Comandos IoT

Di `Jarvis` antes de cada orden.

- `Jarvis conecta MQTT`
- `Jarvis desconecta MQTT`
- `Jarvis registra un ESP32 llamado laboratorio con capacidades temperature, humidity, ldr, led, servo` — confirmación
- `Jarvis dime qué ESP32 están conectados`
- `Jarvis dime si el ESP32 del laboratorio está online`
- `Jarvis dime la temperatura del laboratorio`
- `Jarvis dime la humedad`
- `Jarvis dime el valor del LDR`
- `Jarvis dime las últimas cinco lecturas`
- `Jarvis dime cuándo fue la última lectura`
- `Jarvis dime la temperatura máxima de hoy`
- `Jarvis dime el estado de la luz`
- `Jarvis enciende el LED del laboratorio`
- `Jarvis apaga el LED del laboratorio`
- `Jarvis activa el dispositivo del laboratorio` — usa el relay registrado y pide confirmación
- `Jarvis pon el servo a 90 grados` — confirmación
- `Jarvis avísame si la temperatura supera 30 grados` — confirmación
- `Jarvis dime qué automatizaciones IoT tengo`
- `Jarvis desactiva la automatización de temperatura`
- `Jarvis detén las automatizaciones IoT`
- `Jarvis comprueba Arduino CLI y PlatformIO`

Relay, servo, buzzer y registro de dispositivos requieren confirmación. Si hay varios ESP32 y no hay `IOT_DEFAULT_DEVICE`, JARVIS pide cuál usar. Si se pierde MQTT, las salidas se marcan como desconocidas.

## Ejemplos ESP32

Las plantillas no contienen credenciales reales, no se compilan ni se flashean automáticamente:

- `examples/esp32/basic_mqtt_device/basic_mqtt_device.ino`: LED, estado, ACK y Last Will.
- `examples/esp32/dht11_mqtt/dht11_mqtt.ino`: temperatura y humedad DHT11.
- `examples/esp32/ldr_led_mqtt/ldr_led_mqtt.ino`: LDR, LED, estado y ACK.

Usan `WiFi.h`, `PubSubClient.h`, `ArduinoJson` y `millis()` para reconexión y tareas periódicas. Cada placa debe tener un `CLIENT_ID` único. El firmware acepta solo `set_led` y `get_state` en los ejemplos LED; no acepta código, shell, GPIO arbitrario ni credenciales desde MQTT.

## Seguridad y límites

- Se valida JSON, tamaño de payload, device ID, topic y tipos antes de persistir datos.
- Un device ID del payload debe coincidir con el del topic registrado.
- MQTT recibido se trata como datos no confiables: nunca llega al Terminal Agent ni ejecuta firmware, shell o PowerShell.
- No hay OTA, flasheo automático, credenciales Wi‑Fi remotas, reinicio masivo ni publish/suscripción global por voz.
- La desconexión y la desactivación de reglas son acciones de emergencia sin espera adicional.

## Ejecución y pruebas

```powershell
py -m pip install -r requirements.txt
py -m playwright install chromium
py main.py
```

Modo consola:

```powershell
py main.py --console
```

Las pruebas MQTT usan un proveedor simulado y no dependen de Internet ni de `broker.emqx.io`:

```powershell
py -m pytest -q
```

## Solución de problemas

- **No conecta MQTT:** comprueba host, puerto, TLS, firewall y que las credenciales estén en `.env`; nunca las pegues en comandos de voz.
- **ESP32 aparece offline:** confirma el mismo `MQTT_TOPIC_PREFIX`, `DEVICE_ID`, broker y que publique `online` en `status`.
- **No llega telemetría:** confirma que el payload JSON incluya el `device_id` correcto y sensores registrados; payloads inválidos se descartan sin tumbar JARVIS.
- **No se ejecuta un comando:** el dispositivo debe estar registrado, `trusted`, online y tener la capacidad solicitada; espera el ACK para verificarlo.
- **No se escucha una alerta:** verifica `TTS_ENABLED=true` y la salida de audio de Windows.

## Roadmap

La próxima versión propuesta es **JARVIS v1.0 — Multi-Agent Orchestrator**: coordinación entre Code, Browser, Terminal, IoT, Memory y Vision con planificación multi-paso y políticas globales. No se implementa en v0.9.
