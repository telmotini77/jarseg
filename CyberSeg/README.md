# CyberSeg — IDS local por anomalías

CyberSeg es un sistema defensivo de detección de anomalías: agrupa únicamente
tráfico TCP/UDP de una interfaz local autorizada, extrae métricas por ventanas
de tiempo y publica alertas en una API local. No escanea redes, no inyecta
paquetes, no bloquea tráfico y no ejecuta acciones contra equipos remotos.

## Componentes

- `engine/`: captura local opcional, segmentación y Isolation Forest.
- `backend/`: NestJS, Prisma/PostgreSQL, API de alertas y WebSocket.
- `frontend/`: React para alertas en vivo.
- JARVIS: consulta el estado y las alertas por `http://127.0.0.1:8780`.

## Inicio seguro

1. Copia `.env.example` a `.env` y cambia las contraseñas/tokens de ejemplo.
2. Deja `CYBERSEG_CAPTURE_ALLOWED=false` durante las pruebas iniciales.
3. Ejecuta `docker compose up --build`.
4. Abre `http://127.0.0.1:5178` para el dashboard local.

Para habilitar captura en una red que administras, define tanto
`CYBERSEG_CAPTURE_ALLOWED=true` como `CYBERSEG_INTERFACE=<interfaz>`. JARVIS
todavía pedirá confirmación antes de solicitar el inicio; la interfaz no se
selecciona automáticamente.

En Docker el motor observa la red de su contenedor. Para observar una interfaz
del host, ejecuta el motor en ese host Linux/WSL autorizado y usa
`CYBERSEG_API_URL=http://127.0.0.1:8780`; nunca se selecciona ni escanea una
red externa automáticamente.

## Integración JARVIS

En el `.env` de JARVIS configura `CYBERSEG_ENABLED=true`, la URL local y el
mismo `CYBERSEG_ENGINE_TOKEN`. Después podrás decir:

- `Jarvis dime el estado de CyberSeg`
- `Jarvis muéstrame las alertas de CyberSeg`
- `Jarvis inicia la captura de CyberSeg` — exige confirmación
- `Jarvis detén la captura de CyberSeg`
