# 🛡️ HoneyGate — Framework Defensivo de Decepción, Contención Perimetral y Telemetría Forense

[![Plataforma](https://img.shields.io/badge/Plataforma-Kali%20Linux%20%7C%20WSL2%20%7C%20Android-10b981.svg)](#)
[![Licencia](https://img.shields.io/badge/Licencia-Uso%20Defensivo%20%2F%20Blue%20Team-06b6d4.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.11%2B%20(epoll%20ET)-f59e0b.svg)](#)
[![Android](https://img.shields.io/badge/Android-Jetpack%20Compose%20%7C%20Room-ef4444.svg)](#)

**HoneyGate** es un ecosistema defensivo integrado para operaciones de Blue Team, detección de intrusos y decepción de espacio de usuario (*Non-Root*). Combina un motor de red asíncrono de alto rendimiento en Linux/Python con un panel de telemetría y control táctico móvil desarrollado en Android (Jetpack Compose + Room Database).

---

## 🍯 Los 5 Invariantes Obligatorios de HoneyGate

Para garantizar máxima fidelidad defensiva y rigurosidad legal, HoneyGate implementa cinco reglas arquitectónicas inviolables:

1. **🆔 Identidad por Fingerprint Compuesto (`device_id`)**:
   * Nunca se identifica a un visitante únicamente por IP o MAC física (debido a la aleatorización de direcciones MAC en smartphones modernos y el enmascaramiento por NAT).
   * Se genera un identificador determinista combinando:
     $$\text{device\_id} = \text{SHA256}(\text{MAC-por-SSID} + \text{Browser Fingerprint} + \text{JA3/JA4 TLS} + \text{DHCP Option 55})$$
2. **🚧 Contención Estricta de Tráfico Saliente (*Egress Control*)**:
   * Los entornos de decepción **nunca** poseen salida irrestricta a Internet para prevenir pivoteos o ataques secundarios.
   * La salida está contenida y restringida exclusivamente a una lista blanca de FQDNs autorizados o redirigida a un *sinkhole* defensivo local con registro de anomalías.
3. **🔑 Honeytokens Controlados por el Operador**:
   * Toda credencial señuelo, correo canario o token de autenticación embebido es estrictamente ficticio y operado por el administrador.
   * Cualquier consulta o intento de uso de estos señuelos dispara alertas críticas instantáneas en la matriz forense.
4. **⚖️ Cumplimiento Legal y Consentimiento Explícito (AR)**:
   * En portales cautivos (Modos 1 y 3) solo se recopilan metadatos de conexión, nunca el contenido del tráfico de usuarios legítimos.
   * Incorpora aviso legal explícito bajo la **Ley 25.326** de Protección de Datos Personales de la República Argentina y opera exclusivamente en redes autorizadas bajo la **Ley 26.388** de Delitos Informáticos.
5. **⚠️ Confirmación Obligatoria en Acciones Destructivas**:
   * Ningún bloqueo perimetral, revocación de credenciales o purga forense puede ejecutarse de manera accidental: el panel exige confirmación explícita mediante diálogo modal.

---

## 🕹️ Modos de Operación

HoneyGate se adapta dinámicamente a tres escenarios operacionales desde su panel de administración:

```
                  ┌──────────────────────────────────────────────┐
                  │          🛡️ HONEYGATE ARCHITECTURE           │
                  └──────────────────────┬───────────────────────┘
                                         │
        ┌────────────────────────────────┼────────────────────────────────┐
        ▼                                ▼                                ▼
 🌐 MODO 1: PORTAL CAUTIVO        🎯 MODO 2: HONEYPOT AUDIT        🔀 MODO 3: MODO MIXTO
  * Registro solo email            * Simulación Assume-Breach       * Portal opcional
  * Control Anti-Sybil             * 3 Canarios (Admin/Fin/IT)      * Egress medido a Internet
  * Arrendamiento DHCP 300s        * MySQL / Apache / SSH / Telnet  * Escáner activo de red
  * Observación por rotación MAC   * Contención Sinkhole estricta   * Correlación de anomalías
```

### 1. 🌐 Modo 1 — Portal Cautivo con Trazabilidad (Monitoreo Básico)
* **Registro liviano**: Autenticación orientada a etiqueta con correo electrónico (sin contraseña de fricción).
* **Mecanismo Anti-Sybil**: Límite de tasa de un máximo de 3 registros por hora por cada `device_id` compuesto.
* **Filtro de dominios desechables**: Bloqueo proactivo de proveedores temporales (mailinator, 10minutemail, tempmail).
* **Detección de rotación MAC**: Si un dispositivo altera su MAC pero mantiene el fingerprint del navegador o JA3, entra automáticamente en *modo de observación silenciosa*, permitiendo la navegación mientras audita destinos para inferir perfiles de amenaza.
* **Lease DHCP corto**: Expiración a los 300 segundos para reevaluar la telemetría del cliente.

### 2. 🎯 Modo 2 — Honeypot de Auditoría / Red Team (*Assume-Breach*)
* **Simulación multi-sectorial**: Emula la existencia de 3 identidades comprometidas en la organización:
  * `admin.portal@honeygate.internal` (Sector Administración)
  * `finanzas.reportes@honeygate.internal` (Sector Finanzas)
  * `infra.ops@honeygate.internal` (Sector Infraestructura TI)
* **Servicios señuelo expuestos**:
  * Base de datos MySQL (`3306`)
  * Servidores Web Apache/Nginx (`8080`, `8443`)
  * Terminal SSH (`2222`)
  * Servicio Telnet de legado (`2323`)
* **Honeytokens embebidos**: Archivos falsos `/etc/shadow`, variables `.env` ficticias y tablas con canarios.
* **Captura MITRE ATT&CK**: Mapeo en tiempo real de técnicas T1078 (Cuentas Válidas), T1110 (Fuerza Bruta), T1059 (Línea de Comandos) y T1046 (Escaneo de Red).

### 3. 🔀 Modo 3 — Modo Mixto (Portal + Honeypot Unificado)
* Combina el control perimetral del portal con la decepción activa del honeypot.
* Otorga acceso a Internet nominal medido a usuarios validados respetando la Ley 25.326/26.388.
* Incluye un **escáner de red activo** para mapear hosts adyacentes y detectar discrepancias entre direccionamiento IP y firmas físicas.

---

## 👁️ Experiencia de Usuario y Diseño Visual (Eye-Care UX)

La aplicación Android de HoneyGate fue concebida para operadores de centros de operaciones de seguridad (SOC) y analistas que pasan largas jornadas frente a pantallas.

* **Paleta Dark de Bajo Brillo**: Elimina neones deslumbrantes que causan fatiga visual.
  * Fondo Principal: Slate Profundo (`#0F141C`)
  * Superficies y Tarjetas: Azul Noche Calmo (`#161E2E`)
  * Estado Normal: Verde Esmeralda Suave (`#10B981`)
  * Estado Alerted: Ámbar Cálido (`#F59E0B`)
  * Estado Blocked: Coral Suave No Agresivo (`#EF4444`)
  * Acentos de Información: Cian Calmo (`#06B6D4`)
* **Listado Forense con LazyColumn y Chips de Filtrado**: Permite alternar instantáneamente entre eventos `'Blocked'`, `'Alerted'` y `'Normal'`, así como realizar búsquedas textuales por IP, MAC, técnica MITRE o descripción.

---

## 💻 Arquitectura del Backend en Linux (Python Non-Root)

El núcleo de red corre en espacio de usuario en Kali Linux o WSL2:

* **I/O Asíncrona con `select.epoll`**: Bucle en modo Edge-Triggered (`EPOLLET`) para gestionar cientos de conexiones concurrentes en puertos altos sin necesidad de privilegios `root`.
* **Sockets No Bloqueantes**: Descriptores configurados con la bandera `O_NONBLOCK` mediante `fcntl`.
* **Capa Honeywall con Mitigación Perimetral**:
  * Control de tráfico saliente con umbral estricto de **10 peticiones por minuto**.
  * Cierre forzado inmediato mediante `shutdown(socket_fd, SHUT_RDWR)` y `close()` al detectar pivoteos.
  * Aislamiento en lista de contención y resolución de hardware en `/proc/net/arp`.
* **Vigilancia Forense con `inotify` de Kernel (`libc.so.6`)**: Monitoreo reactivo de bitácoras sin sondeo continuo de disco, enlazado directamente con llamadas nativas de C vía `ctypes`.
* **Seguridad Reforzada en la API Web**:
  * Enlace por defecto a `127.0.0.1`.
  * Validación obligatoria de token en cabecera `X-Auth-Token` (`secrets.compare_digest`) en **todos** los endpoints `/api/*` (GET y POST), devolviendo `401 Unauthorized` ante solicitudes no autenticadas o sin token configurado (falla cerrada). El token se lee de `HONEYGATE_API_TOKEN` o se genera efímeramente en cada arranque con `secrets.token_urlsafe(32)`.
  * Sin cabecera `Access-Control-Allow-Origin: *`.
  * Verificación estricta de direcciones IP con el módulo `ipaddress`.
  * Sanitización contra XSS en el panel web (sustitución de `innerHTML` por asignaciones seguras de `textContent` y escape de entidades HTML).

---

## 🔌 Módulo 1 — Conector Live App Android & Daemon Linux (Control Perimetral Remoto)

El **Módulo 1** establece el puente de comando, telemetría y control perimetral bidireccional en tiempo real entre la aplicación Android y el Daemon de HoneyGate corriendo en Linux (Kali o WSL2):

```
┌─────────────────────────────────┐                 ┌───────────────────────────────────┐
│     HONEYGATE ANDROID APP       │                 │      HONEYGATE LINUX DAEMON       │
│                                 │                 │    (Python 3.11 epoll + ctypes)   │
│  [TopAppBar Status Badge]       │   HTTP REST     │                                   │
│  [DaemonControlDialog]          │ ──────────────> │  GET  /api/status                 │
│  * Latencia de red              │   (Header:      │  GET  /api/connections            │
│  * Sockets activos en kernel    │    X-Auth-Token)│  GET  /api/alerts                 │
│  * Ingesta a Room Database      │ <────────────── │                                   │
│                                 │                 │                                   │
│  [Acción de Bloqueo Invariante 5]                 │  POST /api/isolate                │
│  "Aislar IP confirmada"         │ ──────────────> │  -> shutdown(fd, SHUT_RDWR)       │
│                                 │                 │  -> /proc/net/arp MAC correlation │
│  "Desbloquear IP"               │ ──────────────> │  POST /api/unblock                │
└─────────────────────────────────┘                 └───────────────────────────────────┘
```

### Características Clave del Módulo 1:
1. **Comprobación de Salud y Latencia (`GET /api/status`)**:
   * Reporta en vivo el estado del servicio, latencia en milisegundos, conteo de sockets de red activos, total de conexiones atendidas, violaciones de tasa de salida (*rate-limit*) e IPs actualmente aisladas. Requiere `X-Auth-Token`.
2. **Sincronización de Telemetría a Room (`GET /api/connections` y `GET /api/alerts`)**:
   * Las sesiones activas en el bucle epoll son ingestadas directamente a `MonitoredSessionEntity` con cálculo dinámico del `device_id` compuesto.
   * Las alertas forenses de kernel (*inotify*) se almacenan automáticamente en `ForensicEvent` para correlación defensiva y generación de reportes.
   * La base Room (`honeygate_security.db`) está excluida de respaldos en `backup_rules.xml` y `data_extraction_rules.xml` para proteger el token almacenado.
3. **Mitigación Perimetral Remota a Nivel de Kernel (`POST /api/isolate` / `POST /api/unblock`)**:
   * Al confirmar un bloqueo en el panel Android (cumpliendo el **Invariante 5**), se despacha una orden autenticada con `X-Auth-Token` (si el token está vacío en la app, no se contacta al daemon y se solicita configurarlo).
   * El Daemon en Linux localiza el descriptor de socket (`fd`) asociado y ejecuta inmediatamente la llamada al sistema nativa `shutdown(socket_fd, SHUT_RDWR)`, cerrando físicamente la conexión del atacante.
4. **Conectividad Segura (Emulador y Celular Físico por Túnel ADB)**:
   * `network_security_config.xml` prohíbe tráfico HTTP en claro de forma global y lo habilita **únicamente** hacia `127.0.0.1` y `10.0.2.2`.
   * **Emulador Android**: usar `http://10.0.2.2:8888`.
   * **Celular físico por USB**: abrir túnel inverso hacia el daemon local en `127.0.0.1:8888` y configurar `http://127.0.0.1:8888` en la app:
     ```bash
     adb reverse tcp:8888 tcp:8888
     ```

---

## 📁 Estructura del Repositorio

```text
├── honeygate/                 # Núcleo de red y decepción en Python
│   ├── __init__.py            # Inicializador de paquete
│   ├── honeywall_core.py      # Bucle epoll Edge-Triggered, Honeywall y Rate Limiter
│   ├── cli_console.py         # Consola táctica interactiva con autocompletado en tiempo real
│   ├── forensic_monitor.py    # Monitor inotify de bajo nivel (ctypes) y notificaciones
│   └── dashboard_api.py       # API REST segura (127.0.0.1) y Dashboard web HTML5
├── modules/                   # Módulos de auditoría y pruebas de pivoteo
├── logs/                      # Directorio de bitácoras de seguridad
├── app/                       # Aplicación Android (Jetpack Compose & Room Database)
│   ├── src/main/java/com/example/
│   │   ├── data/local/        # Entidades Room (ForensicEvent, MonitoredSession, HoneygateConfig)
│   │   ├── data/remote/       # Cliente REST HoneyGateDaemonClient (X-Auth-Token)
│   │   ├── data/repository/   # Lógica de invariantes, Anti-Sybil y correlación
│   │   ├── ui/components/     # Insignia y diálogo de control del Daemon Linux
│   │   ├── ui/screens/        # Pantallas: LazyColumn forense, Honeygate 3 Modos, Sesiones, Blue Team Report
│   │   └── ui/theme/          # Sistema de diseño Eye-Care M3
├── REGLAS_DEL_PROYECTO.md     # Normas fundamentales y directrices de desarrollo
├── run_framework.py           # Lanzador unificado del backend defensivo
├── test_honeygate.py          # Batería de pruebas automatizadas de integración y seguridad
└── requirements.txt           # Dependencias Python
```

---

## 🚀 Guía de Inicio Rápido

### 1. Ejecución del Backend en Kali Linux o WSL2

```bash
# Instalar dependencias opcionales
pip install -r requirements.txt

# Ejecutar las pruebas automatizadas del motor defensivo y seguridad
python3 test_honeygate.py

# (Opcional) Definir un token propio para el daemon; si se omite, se genera uno efímero por arranque
export HONEYGATE_API_TOKEN="tu_token_seguro"

# Iniciar el framework completo (CLI interactiva + Servidor Web en 127.0.0.1:8888)
python3 run_framework.py
```

* **Consola Interactiva**: Disponible de inmediato en la terminal con comandos `status`, `honeywall-stats`, `isolate <ip>`, `unblock <ip>`.
* **API y Dashboard**: Accesible localmente en `http://127.0.0.1:8888`. Para conectar un teléfono físico vía USB, ejecutá `adb reverse tcp:8888 tcp:8888` y apuntá la app a `http://127.0.0.1:8888` con el token configurado.

### 2. Ejecución y Compilación de la Aplicación Android

La aplicación Android está configurada con Gradle (Kotlin DSL) y Jetpack Compose:

```bash
# Compilar la aplicación y verificar la base de datos Room
gradle assembleDebug

# Ejecutar pruebas unitarias locales
gradle :app:testDebugUnitTest
```

---

## 🔄 Procedimiento de Rollback y Control de Versiones

Para revertir cambios ante incidencias, se incluye el script `rollback.sh` que exige especificar explícitamente el commit o etiqueta destino (realizando respaldo automático con `git stash` si hay cambios pendientes):

```bash
# Consultar historial reciente para elegir el destino
git log --oneline -n 5

# Restaurar archivos al commit o tag indicado (argumento obligatorio)
./rollback.sh <COMMIT_HASH_O_TAG>

# Restaurar forzando descarte de cambios locales
./rollback.sh --hard <COMMIT_HASH_O_TAG>
```

---

## ⚖️ Marco Legal y Ética Operacional

Este software ha sido diseñado exclusivamente para auditorías de seguridad autorizadas, entornos de laboratorio, investigación forense y defensa perimetral corporativa.
* **Ley 25.326 (República Argentina)**: Garantiza la protección integral de datos personales almacenados en archivos o bancos de datos.
* **Ley 26.388 (República Argentina)**: Tipifica los delitos informáticos y sanciona el acceso no autorizado a sistemas informáticos.

El uso de **HoneyGate** debe realizarse siempre en infraestructuras propias o con autorización explícita y por escrito de sus propietarios.
