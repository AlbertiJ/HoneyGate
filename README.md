# 🛡️ HoneyGate — Framework Defensivo de Decepción, Contención y Telemetría Forense

[![Python](https://img.shields.io/badge/Python-3.11%2B%20(epoll%20ET)-06b6d4.svg)](#)
[![Android](https://img.shields.io/badge/Android-Jetpack%20Compose%20%7C%20Room-10b981.svg)](#)
[![Privilegios](https://img.shields.io/badge/Ejecución-Non--Root%20User%20Space-f59e0b.svg)](#)

**HoneyGate** es un daemon defensivo sin privilegios `root` para Linux (`select.epoll` + `inotify` nativo vía `ctypes` + SQLite) acompañado de un panel de control en Android (Jetpack Compose + Room). Permite operar un portal cautivo liviano con verificación OTP, servicios de decepción con perfil unificado **Debian 12**, registro forense con mapeo MITRE ATT&CK externo, exportación de informes (`/api/report`) y purga de datos personales.

---

## ⚠️ Qué NO hace el daemon (Alcance Explícito)

HoneyGate se ejecuta en espacio de usuario **sin privilegios `root`**. Por diseño:

1. **NO redirige el WiFi ni el tráfico DNS/HTTP de la red:** La captura o redirección de clientes hacia el portal cautivo o los puertos señuelo la realiza el router, punto de acceso (AP) o firewall de borde.
2. **NO limita el ancho de banda:** El campo `bandwidth_kbps` es únicamente un valor **sugerido (no aplicado por el daemon)**; el control real de QoS / tráfico lo aplica el router.
3. **NO corta la salida a internet de los clientes ni administra DHCP real:** El campo `dhcp_lease_sec` también es **sugerido (no aplicado por el daemon)**. HoneyGate no modifica `iptables`/`nftables` ni configura interfaces de red; ante anomalías o aislamiento manual, cierra sus propios descriptores de socket con `shutdown(SHUT_RDWR)` y marca la IP en su tabla interna de contención.

---

## 📋 Requisitos e Instalación

### Backend Linux (Kali Linux / Debian / Ubuntu / WSL2)
- Python **3.11+** (las pruebas y el núcleo operan con librería estándar; `requirements.txt` agrega utilidades opcionales para CLI y pruebas).
- Kernel Linux con `epoll` e `inotify` (`libc.so.6`).

```bash
# 1. Instalar dependencias Python opcionales (ej. prompt_toolkit para consola interactiva)
pip install -r requirements.txt

# 2. (Opcional) Crear archivo de entorno sin secretos desde la plantilla
cp .env.example .env
chmod 600 .env
```

> **Importante:** Las carpetas `data/` y `logs/` contienen estado local (`honeygate.db`, `portal_secret`, bitácoras) y están excluidas de Git en `.gitignore`.

### Aplicación Android (Panel de Control)
- Android Studio / Gradle con JDK 11+ y Android SDK configurado.

```bash
# Compilar APK debug
gradle assembleDebug

# Ejecutar pruebas unitarias y Robolectric en JVM
gradle :app:testDebugUnitTest
```

---

## 🚀 Arranque y Pruebas

### 1. Ejecución manual interactiva (terminal con CLI)
```bash
# Token administrativo recomendado (si se omite, genera uno efímero en cada arranque)
export HONEYGATE_API_TOKEN="tu_token_largo_aleatorio"

python3 run_framework.py
```

### 2. Ejecución headless (sin consola interactiva)
```bash
HONEYGATE_HEADLESS=1 python3 run_framework.py
```
Cuando no hay TTY interactiva (por ejemplo bajo `systemd`), `run_framework.py` entra automáticamente en modo headless y espera señales `SIGINT`/`SIGTERM`.

### 3. Servicio `systemd` de usuario (con endurecimiento)
El repositorio incluye una unidad de ejemplo endurecida en [`deploy/systemd/honeygate.service`](deploy/systemd/honeygate.service) con:
- `NoNewPrivileges=yes`
- `PrivateTmp=yes`
- `ProtectSystem=strict`
- `ReadWritePaths=%h/HoneyGate/data %h/HoneyGate/logs` (acceso de escritura restringido exclusivamente a `data/` y `logs/`)

Instalación para el usuario actual (ajustando la ruta si el repo no está en `~/HoneyGate`):
```bash
mkdir -p ~/.config/systemd/user data logs
cp deploy/systemd/honeygate.service ~/.config/systemd/user/honeygate.service
systemctl --user daemon-reload
systemctl --user enable --now honeygate.service
systemctl --user status honeygate.service
```

### 4. Batería de pruebas automáticas
```bash
python3 test_honeygate.py
```

---

## 🔧 Variables de Entorno

Todas las variables son configurables vía entorno o `.env` (ver [`.env.example`](.env.example), que se distribuye con valores vacíos y sin secretos):

| Variable | Valor por defecto | Descripción |
| --- | --- | --- |
| `HONEYGATE_API_TOKEN` | *(generado con `secrets.token_urlsafe(32)`)* | Token obligatorio en cabecera `X-Auth-Token` para todos los endpoints `/api/*`. |
| `HONEYGATE_API_HOST` | `127.0.0.1` | Interfaz de escucha del panel web y API REST administrativa. |
| `HONEYGATE_API_PORT` | `8888` | Puerto TCP de la API REST y panel web administrativo. |
| `HONEYGATE_EPOLL_HOST` | `127.0.0.1` | Interfaz de escucha de los puertos emulados (`epoll`). Cambiar solo explícitamente. |
| `HONEYGATE_HEADLESS` | `0` (`1` auto si no hay TTY) | `1`/`true` desactiva la consola CLI interactiva para correr como daemon/systemd. |
| `HONEYGATE_PORTAL_HOST` | `127.0.0.1` | Interfaz de escucha del servidor HTTP del portal cautivo (Modo 1). |
| `HONEYGATE_PORTAL_PORT` | `8090` | Puerto TCP del portal cautivo (debe ser distinto a `HONEYGATE_API_PORT`). |
| `HONEYGATE_PORTAL_SECRET` | *(generado en `data/portal_secret`, chmod `600`)* | Clave HMAC-SHA256 para hashear correos en `otp_challenges` y `portal_registrations`. |
| `HONEYGATE_PORTAL_LAB_MODE` | `0` | Si es `1`/`true`/`yes`, registra el código OTP en log de laboratorio (desactivado en producción). |
| `HONEYGATE_PORTAL_OTP_OPTIONAL` | `0` | Si es `1`/`true`/`yes`, habilita `/portal/register` sin OTP previo y marca la sesión `"mail sin verificar"`. |
| `HONEYGATE_SMTP_HOST` | `""` *(vacío)* | Servidor SMTP para entregar códigos OTP del portal. Obligatorio si no está en modo laboratorio. |
| `HONEYGATE_SMTP_PORT` | `587` | Puerto del servidor SMTP. |
| `HONEYGATE_SMTP_USER` | `""` *(vacío)* | Usuario de autenticación SMTP. |
| `HONEYGATE_SMTP_PASS` | `""` *(vacío)* | Contraseña SMTP (leída únicamente desde variable de entorno, nunca en SQLite ni logs). |
| `HONEYGATE_SMTP_PASSWORD` | `""` *(vacío)* | Alias alternativo de `HONEYGATE_SMTP_PASS` si este último está vacío. |
| `HONEYGATE_SMTP_FROM` | `HONEYGATE_SMTP_USER` o `noreply@honeygate.local` | Dirección remitente (`From`) de los correos OTP. |
| `HONEYGATE_SMTP_USE_TLS` | `1` | `1` habilita `STARTTLS` en la conexión SMTP saliente (`0`/`false`/`no` para desactivar). |
| `HONEYGATE_SMTP_USE_SSL` | `0` | `1`/`true`/`yes` utiliza `SMTP_SSL` en lugar de SMTP plano + `STARTTLS`. |
| `HONEYGATE_MITRE_RULES_PATH` | `honeygate/mitre_rules.json` | Ruta al archivo JSON externo de reglas MITRE ATT&CK validado al iniciar. |

---

## 🌐 Puertos y Servicios Abiertos

Por defecto, todos los servicios escuchan únicamente en `127.0.0.1` en puertos no privilegiados (`>1024`):

| Puerto | Servicio | Interfaz por defecto | Comportamiento real |
| --- | --- | --- | --- |
| `8888/TCP` | API REST + Panel Web | `127.0.0.1` | Endpoints `/api/*` protegidos por `X-Auth-Token`. |
| `8090/TCP` | Portal Cautivo (Modo 1) | `127.0.0.1` | HTML estático con CSP estricta (`script-src 'none'`), OTP y Anti-Sybil. Sin acceso al token ni a `/api/*`. |
| `2222/TCP` | SSH emulado | `127.0.0.1` | Banner Debian 12 (`SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`) y tabla fija sin ejecución. |
| `2323/TCP` | Telnet emulado | `127.0.0.1` | Banner Debian 12 (`srv-app-02`) con comandos de lectura fija y límites por sesión/línea. |
| `8080/TCP` | HTTP emulado | `127.0.0.1` | Cabecera `Apache/2.4.57 (Debian)`, respuestas estáticas y detección de honeytokens. |
| `8443/TCP` | HTTPS-señuelo (HTTP plano) | `127.0.0.1` | Sirve respuestas HTTP emuladas con el mismo perfil Debian 12 (no termina TLS nativo). |
| `3306/TCP` | MySQL emulado | `127.0.0.1` | Saludo binario real `Protocol::HandshakeV10` (`8.0.39-0+deb12u1`) y respuestas binarias `ERR_Packet`. |

---

## 📱 Conexión desde el Celular Físico (Túnel ADB) y Emulador

La app Android restringe HTTP en texto claro mediante `network_security_config.xml` exclusivamente a `127.0.0.1` y `10.0.2.2` (y bloquea copias de seguridad de la base Room en `backup_rules.xml` / `data_extraction_rules.xml`):

- **Emulador Android:** Configurar el endpoint en la app como `http://10.0.2.2:8888` e ingresar el `HONEYGATE_API_TOKEN` activo en el daemon.
- **Celular físico por USB (Depuración USB activa):**
  1. Redirigir el puerto del teléfono hacia el daemon local en Linux:
     ```bash
     adb reverse tcp:8888 tcp:8888
     ```
  2. En la app Android (diálogo del conector en la barra superior), configurar:
     - **Endpoint:** `http://127.0.0.1:8888`
     - **Token (`X-Auth-Token`):** el mismo valor de `HONEYGATE_API_TOKEN` que usa el daemon.

---

## 🛡️ Límites Conocidos

1. **Sin control real de red del router:** Como corre sin `root`, HoneyGate no intercepta paquetes de terceros, no redirige WiFi, no corta acceso a internet en LAN y no aplica `dhcp_lease_sec` ni `bandwidth_kbps` (son valores sugeridos para orquestación externa).
2. **Sin TLS nativo integrado:** La API administrativa, el portal cautivo y el puerto `8443` operan en HTTP plano sobre `127.0.0.1`. Para exponer en red local o internet se requiere un proxy inverso TLS (Nginx/Caddy) o túnel `adb reverse` / SSH.
3. **Componentes parciales de `device_id`:** El portal cautivo mide en el navegador `user_agent`, `screen`, `timezone`, `language` y `canvas_hash`; los campos `ja3` y `dhcp_option_55` solo se incorporan si una sonda externa o router los envía, quedando vacíos cuando no están disponibles.
4. **Dependencia de kernel Linux:** `select.epoll` e `inotify` vía `libc.so.6` requieren Linux o WSL2 (no funciona de forma nativa en Windows ni macOS sin contenedor Linux).
5. **Modo DEMO en la app Android:** Está desactivado por defecto y su única finalidad es probar flujos locales en el teléfono cuando no hay un daemon conectado; al desactivarlo elimina los registros marcados `isDemo=true`.

---

## ⚖️ Marco Legal y Privacidad (República Argentina)

- **Ley 26.388 (Delitos Informáticos):** HoneyGate debe desplegarse únicamente en redes propias o infraestructuras donde exista autorización expresa y documentada del titular. Los servicios emulados nunca ejecutan comandos reales ni abren conexiones salientes.
- **Ley 25.326 (Protección de Datos Personales):**
  - El portal cautivo solicita consentimiento informado explícito, solo recolecta correo de contacto y metadatos técnicos mínimos, y **nunca** solicita ni almacena contraseñas de usuarios.
  - Los honeytokens deben contener exclusivamente identificadores ficticios (el daemon rechaza dominios reales conocidos).
  - Los correos en `otp_challenges` y `portal_registrations` se protegen con HMAC-SHA256 (`HONEYGATE_PORTAL_SECRET`).
  - Los informes (`GET /api/report` en JSON, CSV y Markdown) enmascaran correos por defecto (`j***@dominio`) salvo solicitud explícita (`include_full_email=1`).
  - La retención configurable (`POST /api/privacy/retention-purge`) y el borrado por visitante (`POST /api/privacy/forget-visitor`) exigen confirmación explícita, eliminan sesiones, eventos, registros y desafíos OTP asociados, y registran un evento de auditoría sin PII.

---

## 📁 Estructura del Repositorio

```text
├── honeygate/
│   ├── __init__.py
│   ├── cli_console.py         # Consola interactiva non-blocking y auditoría /proc/net
│   ├── dashboard_api.py       # API REST autenticada (127.0.0.1:8888) y panel HTML5
│   ├── deception.py           # Perfil único Debian 12, MySQL HandshakeV10 binario y respuestas fijas
│   ├── forensic_monitor.py    # Vigilancia inotify de bajo nivel (libc.so.6 vía ctypes)
│   ├── honeywall_core.py      # Bucle epoll Edge-Triggered, rate-limiter y shutdown(SHUT_RDWR)
│   ├── mitre.py               # Cargador y validador de reglas MITRE ATT&CK
│   ├── mitre_rules.json       # Mapeo externo editable de técnicas MITRE ATT&CK
│   ├── portal.py              # Portal cautivo Modo 1 (127.0.0.1:8090), OTP, Anti-Sybil y CSP
│   ├── reporting.py           # Generación de informes JSON/CSV/Markdown con sanitización y masking
│   └── storage.py             # Persistencia única en SQLite y purgas de privacidad
├── deploy/systemd/
│   └── honeygate.service      # Unidad systemd de usuario endurecida
├── .github/workflows/
│   └── tests.yml              # CI de solo lectura (python3 test_honeygate.py)
├── modules/                   # Scripts auxiliares de laboratorio
├── app/                       # App Android (Jetpack Compose + Room + Robolectric)
├── data/                      # Base SQLite y secreto HMAC en runtime (fuera de git)
├── logs/                      # Bitácoras locales en runtime (fuera de git)
├── .env.example               # Variables de entorno documentadas con valores vacíos
├── run_framework.py           # Lanzador principal (CLI interactiva o headless)
└── test_honeygate.py          # Pruebas automáticas de integración y seguridad
```
