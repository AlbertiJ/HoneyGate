# HoneyGate

Framework defensivo de decepción ("puerta de miel"): une un portal cautivo con trazabilidad y un honeypot contenido, con un panel de control en Android.

- **Motor (daemon):** Python 3.11+, sin `root`, para Linux (Kali, Debian, Ubuntu o WSL2). Usa `epoll`, `inotify` y SQLite.
- **Panel:** app Android (Jetpack Compose + Room). Configura el motor y muestra su telemetría.

> **Uso autorizado únicamente.** Desplegar solo en redes propias o con autorización escrita del titular (Ley 26.388). Los datos de visitantes se tratan con consentimiento (Ley 25.326). Ver [Marco legal](#marco-legal).

---

## Índice

1. [Qué hace y qué no hace](#qué-hace-y-qué-no-hace)
2. [Arquitectura](#arquitectura)
3. [Inicio rápido](#inicio-rápido)
4. [Instalar y arrancar el daemon](#instalar-y-arrancar-el-daemon)
5. [Obtener el APK](#obtener-el-apk)
6. [Instalar el APK en el celular](#instalar-el-apk-en-el-celular)
7. [Conectar la app con el daemon](#conectar-la-app-con-el-daemon)
8. [Usar la app](#usar-la-app)
9. [Los tres modos](#los-tres-modos)
10. [Consola del daemon](#consola-del-daemon)
11. [API REST](#api-rest)
12. [Variables de entorno](#variables-de-entorno)
13. [Puertos](#puertos)
14. [Servicio systemd](#servicio-systemd)
15. [Pruebas](#pruebas)
16. [Solución de problemas](#solución-de-problemas)
17. [Límites conocidos](#límites-conocidos)
18. [Marco legal](#marco-legal)
19. [Estructura del repositorio](#estructura-del-repositorio)

---

## Qué hace y qué no hace

### Qué hace

| Modo | Para qué sirve |
| --- | --- |
| **1 — Portal cautivo** | Registro con mail + código OTP (sin contraseña), consentimiento informado, huella del dispositivo y reglas anti-Sybil que marcan sesiones "en observación". |
| **2 — Honeypot** | Servicios emulados (SSH, Telnet, HTTP, MySQL) con el perfil de un único servidor Debian 12. Registra comandos, los mapea a MITRE ATT&CK y alerta cuando se toca un honeytoken. |
| **3 — Mixto** | Portal opcional más el panel completo del modo 2, sobre el mismo esquema de datos. |

En los tres modos: informe de auditoría exportable (JSON, CSV, Markdown), borrado de datos por antigüedad o por visitante, y aislamiento de una IP con confirmación.

### Qué NO hace

El daemon corre sin `root`, así que por diseño:

1. **No redirige el WiFi** ni el tráfico DNS/HTTP hacia el portal. Eso lo hace el router o el punto de acceso.
2. **No limita el ancho de banda.** `bandwidth_kbps` es un valor sugerido, no aplicado.
3. **No corta la salida a internet de los clientes** ni administra DHCP. `dhcp_lease_sec` también es sugerido. "Aislar" una IP cierra las conexiones de esa IP *contra el daemon* y la anota en su tabla interna; no toca `iptables`/`nftables`.
4. **No ejecuta nada de lo que escribe un atacante.** Las respuestas de los servicios emulados salen de una tabla fija y el daemon no abre conexiones salientes por ellos.

---

## Arquitectura

```text
   Celular Android                         Equipo Linux (Kali / Debian / WSL2)
 ┌──────────────────┐   adb reverse      ┌───────────────────────────────────────┐
 │  App HoneyGate   │ ─────────────────► │ 127.0.0.1:8888  API REST + panel web   │
 │  (panel)         │   HTTP + token     │ 127.0.0.1:8090  Portal cautivo (modo 1)│
 └──────────────────┘                    │ 127.0.0.1:2222  SSH emulado            │
                                         │ 127.0.0.1:2323  Telnet emulado         │
   Visitante / Red Team ───────────────► │ 127.0.0.1:8080  HTTP emulado           │
   (lo acerca el router o un túnel)      │ 127.0.0.1:8443  HTTP señuelo           │
                                         │ 127.0.0.1:3306  MySQL emulado          │
                                         │ data/honeygate.db  (SQLite)            │
                                         └───────────────────────────────────────┘
```

El daemon es el dueño de los datos. La app no inventa nada: guarda en Room una copia de lo que recibe y avisa cuando está sin conexión.

---

## Inicio rápido

```bash
# 1. En el equipo Linux
git clone https://github.com/AlbertiJ/HoneyGate.git
cd HoneyGate
python3 run_framework.py        # anotá el token que muestra al arrancar

# 2. Con el celular conectado por USB (depuración USB activada)
adb install app-debug.apk       # ver "Obtener el APK"
adb reverse tcp:8888 tcp:8888

# 3. En la app: botón "Conectar"
#    URL:   http://127.0.0.1:8888
#    Token: el que mostró el daemon
```

---

## Instalar y arrancar el daemon

### Requisitos

- Linux con `epoll` e `inotify`: Kali, Debian, Ubuntu o WSL2. No funciona nativo en Windows ni macOS.
- Python 3.11 o superior.
- El núcleo usa solo la librería estándar. `requirements.txt` agrega `prompt_toolkit` (consola interactiva) y `requests` (scripts de `modules/`).

### Instalación

```bash
git clone https://github.com/AlbertiJ/HoneyGate.git
cd HoneyGate
python3 -m venv .venv && source .venv/bin/activate     # opcional
pip install -r requirements.txt                        # opcional
```

### Arranque

```bash
python3 run_framework.py
```

Al arrancar, el daemon informa dónde escucha y, si no definiste un token, genera uno para esa sesión:

```text
[WEB-API] HONEYGATE_API_TOKEN no definido; token generado para esta sesión: <token>
[WEB-API] Dashboard y Endpoints JSON activos en http://127.0.0.1:8888
[PORTAL-HTTP] Portal Cautivo activo en http://127.0.0.1:8090
```

Ese token cambia en cada arranque y queda escrito en `logs/honeywall.log`. Para un token fijo, definilo vos:

```bash
cp .env.example .env && chmod 600 .env
# Editá .env y completá, por ejemplo:
#   HONEYGATE_API_TOKEN=<valor largo y aleatorio>
# Generar uno:  python3 -c "import secrets; print(secrets.token_urlsafe(32))"

set -a; . ./.env; set +a      # el daemon no lee .env por sí solo
python3 run_framework.py
```

Sin consola interactiva (para dejarlo corriendo):

```bash
HONEYGATE_HEADLESS=1 python3 run_framework.py
```

Para detenerlo: `Ctrl+C` (o `SIGTERM`).

`data/` y `logs/` guardan el estado local (`honeygate.db`, `portal_secret`, bitácoras) y están fuera de git.

---

## Obtener el APK

Hay tres caminos. El primero es el más simple.

### Opción A — Desde Google AI Studio (recomendada)

El proyecto se desarrolla en AI Studio, que ya tiene las claves de firma configuradas.

1. Abrí el proyecto HoneyGate en AI Studio.
2. Arriba a la derecha, botón **Install**.
3. Seguí las instrucciones para instalar en el celular o descargar el APK.

### Opción B — Android Studio

Requisitos:

- Android Studio reciente (trae su propio JDK).
- **Android SDK Platform 36.1** instalado desde *SDK Manager* (`compileSdk` 36.1, `minSdk` 24).
- JDK 17 o superior si usás uno propio (el proyecto usa Gradle 9.3.1 y Android Gradle Plugin 9.1.1).

Pasos:

1. Cloná el repositorio y abrí la carpeta raíz en Android Studio.
2. **Creá el keystore de depuración.** El proyecto firma el APK debug con `debug.keystore` en la raíz, que no está en git:

   ```bash
   keytool -genkeypair -v \
     -keystore debug.keystore \
     -storepass android -keypass android \
     -alias androiddebugkey \
     -keyalg RSA -keysize 2048 -validity 10000 \
     -dname "CN=Android Debug,O=Android,C=US"
   ```

3. Esperá a que termine la sincronización de Gradle.
4. Menú **Build → Build App Bundle(s) / APK(s) → Build APK(s)**.
5. El APK queda en `app/build/outputs/apk/debug/app-debug.apk`.

No hace falta `google-services.json`: el plugin está configurado para avisar y seguir si falta.

### Opción C — Línea de comandos

El repositorio no incluye el script `gradlew`, así que necesitás Gradle 9.3.1 instalado (o generarlo una vez con `gradle wrapper`).

```bash
# Variables del SDK (ajustá la ruta)
export ANDROID_HOME="$HOME/Android/Sdk"

# Keystore de depuración (una sola vez), igual que en la opción B
keytool -genkeypair -v -keystore debug.keystore -storepass android -keypass android \
  -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Android Debug,O=Android,C=US"

gradle :app:assembleDebug            # genera el APK debug
gradle :app:testDebugUnitTest        # pruebas unitarias (opcional)
```

Resultado: `app/build/outputs/apk/debug/app-debug.apk`.

### APK de publicación (release)

Para uso propio alcanza con el APK debug. El release requiere tu propio keystore, que se pasa por variables de entorno y **nunca se sube al repositorio**:

```bash
export KEYSTORE_PATH=/ruta/a/tu-keystore.jks
export STORE_PASSWORD=...      # no lo escribas en archivos versionados
export KEY_PASSWORD=...
gradle :app:assembleRelease    # alias de la clave: "upload"
```

> Los pasos de las opciones B y C salen de la configuración de Gradle del repositorio. La compilación está verificada dentro de AI Studio; si en tu máquina falla, revisá [Solución de problemas](#solución-de-problemas).

---

## Instalar el APK en el celular

### Por USB con adb

1. En el celular: *Ajustes → Acerca del teléfono* → tocá siete veces **Número de compilación** para activar las opciones de desarrollador.
2. *Ajustes → Opciones de desarrollador* → activá **Depuración USB**.
3. Conectá el cable y aceptá la huella del equipo en el celular.

```bash
adb devices                      # debe aparecer tu dispositivo como "device"
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### Copiando el archivo

Pasá `app-debug.apk` al celular, abrilo desde el gestor de archivos y permití "instalar apps de origen desconocido" para esa app. Android 7.0 (API 24) o superior.

---

## Conectar la app con el daemon

La app solo permite HTTP sin cifrar hacia `127.0.0.1` y `10.0.2.2`. Por eso el celular físico se conecta por un túnel USB y el daemon sigue escuchando únicamente en `127.0.0.1`.

### Celular físico

```bash
adb reverse tcp:8888 tcp:8888
```

En la app, tocá **Conectar** (barra superior) y completá:

| Campo | Valor |
| --- | --- |
| URL del daemon | `http://127.0.0.1:8888` |
| Token (`X-Auth-Token`) | el token del daemon |

Después **Probar**, **Guardar** y **Sincronizar**.

El túnel se pierde al desconectar el cable o reiniciar `adb`; repetí `adb reverse`.

### Emulador de Android

Usá `http://10.0.2.2:8888` como URL. No hace falta `adb reverse`.

Si el token está vacío, la app no llama al daemon y muestra "Configurá el token".

---

## Usar la app

| Pestaña | Qué muestra |
| --- | --- |
| **Eventos** | Eventos forenses del daemon, con severidad, técnica MITRE y buscador por IP, `device_id` o tipo. |
| **Operación** | Selector de modo (1, 2 o 3) y sus opciones. Cada cambio se escribe en el daemon. |
| **Sesiones** | Sesiones registradas. Permite marcar "en observación", aislar o desbloquear, siempre con confirmación. |
| **Informe** | Informe de auditoría generado por el daemon, para ver y compartir. |

Indicadores:

- **Sin conexión:** la app muestra la última copia guardada, marcada como desactualizada.
- **Modo DEMO:** apagado por defecto. Sirve para recorrer las pantallas sin daemon; sus datos llevan la marca "DEMO" y se borran al apagarlo.
- **mail sin verificar:** sesión registrada con OTP opcional (solo laboratorio).
- **sugerido (no aplicado por el daemon):** acompaña a lease DHCP y ancho de banda.

El panel web del daemon (`http://127.0.0.1:8888/` desde el mismo equipo) muestra lo mismo en el navegador.

---

## Los tres modos

Se cambian desde la pestaña **Operación** de la app o por API:

```bash
T="tu_token"; B="http://127.0.0.1:8888"
curl -s -X PUT -H "X-Auth-Token: $T" -H "Content-Type: application/json" \
     -d '{"mode": 2, "honeypot_enabled": true}' "$B/api/config"
```

### Modo 1 — Portal cautivo

1. El visitante abre `http://127.0.0.1:8090/portal` (en una red real, lo redirige el router).
2. Acepta el consentimiento, escribe su mail y pide el código.
3. Recibe el OTP por correo, lo ingresa y queda registrado.

Reglas del OTP: 6 dígitos, vence a los 5 minutos, 3 intentos, un solo uso, guardado como hash.

Límites de pedidos (responde `429`): 3 códigos por mail cada 15 minutos, 10 por IP por hora, 20 registros por IP por hora.

Anti-Sybil: los dominios de mail descartables se rechazan. Varios mails desde un mismo dispositivo, muchas altas seguidas o la misma huella con MAC cambiante dejan la sesión **en observación** y generan una alerta. Nunca bloquea solo.

Para enviar correos hay que configurar SMTP (ver [Variables de entorno](#variables-de-entorno)). Sin SMTP, el portal responde `503` salvo en modo laboratorio:

```bash
HONEYGATE_PORTAL_LAB_MODE=1 python3 run_framework.py   # el OTP se escribe en el log, sin el mail
```

El portal está disponible en los modos 1 y 3 con `portal_enabled: true`. En modo 2 responde `503`.

### Modo 2 — Honeypot

Activá `honeypot_enabled` y probá los servicios desde el mismo equipo:

```bash
nc 127.0.0.1 2323                 # Telnet emulado: banner Debian 12 y "login:"
nc 127.0.0.1 2222                 # SSH emulado: banner OpenSSH
curl -I http://127.0.0.1:8080/    # HTTP emulado: "Server: Apache/2.4.57 (Debian)"
```

Cada entrada queda como evento, con su técnica MITRE:

```bash
curl -s -H "X-Auth-Token: $T" "$B/api/events?limit=5"
```

Límites por sesión: 512 bytes por línea, 20 comandos, 120 segundos.

**Honeytokens.** Son señuelos que definís vos; al tocarlos se dispara un evento crítico. Deben ser ficticios: el daemon rechaza dominios reales y acepta solo `.invalid`, `.test`, `.example` y `example.com`.

```bash
curl -s -X PUT -H "X-Auth-Token: $T" -H "Content-Type: application/json" -d '{
  "honeytokens": [
    {"name": "backup_creds.txt", "value": "svc_backup@corp.example / clave-ficticia-001", "kind": "decoy"}
  ]
}' "$B/api/config"
```

Máximo 20 honeytokens.

**Reglas MITRE.** Están en `honeygate/mitre_rules.json`; se pueden ampliar sin tocar código. Otra ruta: `HONEYGATE_MITRE_RULES_PATH`.

**Portal del cliente.** `portal_template` (`title`, `subtitle`, `footer`) permite adaptar los textos. Se sirve como HTML estático con CSP estricta; se rechazan scripts y recursos externos.

### Modo 3 — Mixto

`{"mode": 3, "portal_enabled": true, "honeypot_enabled": true}`. El portal es opcional (`portal_enabled`) y el panel del modo 2 queda completo.

### Informe y privacidad

```bash
curl -s -H "X-Auth-Token: $T" "$B/api/report?format=markdown" -o informe.md
curl -s -H "X-Auth-Token: $T" "$B/api/report?format=csv"      -o informe.csv
curl -s -H "X-Auth-Token: $T" "$B/api/report?format=json"     -o informe.json
```

Los mails salen enmascarados (`j***@dominio`). Para verlos completos: `&include_full_email=1`. En CSV, las celdas que empiezan con `=`, `+`, `-` o `@` llevan un apóstrofo delante para que una planilla no las ejecute como fórmula.

Borrado de datos (ambos exigen `"confirm": true`):

```bash
# Todo lo anterior a retention_days
curl -s -X POST -H "X-Auth-Token: $T" -H "Content-Type: application/json" \
     -d '{"confirm": true}' "$B/api/privacy/retention-purge"

# Todo lo de un visitante (indicá email, device_id o ip)
curl -s -X POST -H "X-Auth-Token: $T" -H "Content-Type: application/json" \
     -d '{"confirm": true, "ip": "192.0.2.10"}' "$B/api/privacy/forget-visitor"
```

---

## Consola del daemon

Al arrancar sin `HONEYGATE_HEADLESS`, queda una consola interactiva:

| Comando | Qué hace |
| --- | --- |
| `help` | Lista los comandos. |
| `status` | Estado general del daemon. |
| `honeywall-stats` | Contadores de conexiones, aislamientos y violaciones de tasa. |
| `connections` | Conexiones activas. |
| `isolate <ip>` | Aísla una IP. |
| `unblock <ip>` | Quita el aislamiento. |
| `audit <objetivo>` | Auditoría en espacio de usuario (`help` lista los objetivos). |
| `run-module <archivo.py>` | Ejecuta un script de laboratorio de `modules/`. |
| `logs` | Muestra la bitácora. |
| `clear` | Limpia la pantalla. |

---

## API REST

Base: `http://127.0.0.1:8888`. **Todos** los endpoints `/api/*` exigen la cabecera `X-Auth-Token`; sin ella responden `401`. No hay CORS.

| Método | Ruta | Descripción |
| --- | --- | --- |
| `GET` | `/api/status` | Estado, contadores, sesiones activas, IPs aisladas y configuración. |
| `GET` | `/api/connections` | Conexiones abiertas. |
| `GET` | `/api/alerts` | Alertas del monitor forense. |
| `GET` | `/api/config` | Configuración actual. |
| `PUT` | `/api/config` | Cambia la configuración (ver campos abajo). |
| `GET` | `/api/sessions` | Sesiones. Filtros: `status`, `ip`, `device_id`, `service`, `mode`; `limit` y `offset`. |
| `GET` | `/api/events` | Eventos. Filtros: `severity`, `event_type`, `ip`, `device_id`, `mitre_technique`, `session_id`, `mode`, `since`, `until`; `limit` y `offset`. |
| `POST` | `/api/sessions/{id}/observe` | Marca una sesión "en observación". |
| `POST` | `/api/isolate` | Aísla una IP: `{"ip": "..."}`. |
| `POST` | `/api/unblock` | Quita el aislamiento: `{"ip": "..."}`. |
| `GET` | `/api/report` | Informe. `format=json\|csv\|markdown`, `include_full_email=1`. |
| `POST` | `/api/privacy/retention-purge` | Borra lo anterior a `retention_days`. Requiere `confirm`. |
| `POST` | `/api/privacy/forget-visitor` | Borra los datos de un visitante. Requiere `confirm`. |

Campos de `PUT /api/config`:

| Campo | Por defecto | Notas |
| --- | --- | --- |
| `mode` | `1` | `1`, `2` o `3`. |
| `portal_enabled` | `true` | Portal activo en modos 1 y 3. |
| `honeypot_enabled` | `false` | Servicios emulados y captura. |
| `retention_days` | `30` | Entre 1 y 3650. |
| `max_outbound_per_minute` | `10` | Umbral de tasa por conexión. |
| `egress_whitelist` | `[]` | Lista de destinos permitidos (dato para orquestación externa). |
| `sybil_max_emails_per_device` | `3` | Mails distintos por dispositivo antes de observar. |
| `sybil_window_seconds` | `600` | Ventana de la regla anterior. |
| `honeytokens` | `[]` | Hasta 20, solo valores ficticios. |
| `portal_template` | textos por defecto | `title`, `subtitle`, `footer`. |

El cuerpo máximo de una petición es de 64 KB (`413` si se supera).

Portal (puerto 8090, sin token y sin acceso a `/api/*`): `GET /portal`, `POST /portal/otp/request`, `POST /portal/register`.

---

## Variables de entorno

Todas son opcionales. `.env.example` las lista vacías; el daemon no lee `.env` por sí solo (usá `set -a; . ./.env; set +a` o el servicio systemd).

| Variable | Por defecto | Descripción |
| --- | --- | --- |
| `HONEYGATE_API_TOKEN` | generado en cada arranque | Token de `X-Auth-Token`. |
| `HONEYGATE_API_HOST` | `127.0.0.1` | Interfaz de la API y el panel web. |
| `HONEYGATE_API_PORT` | `8888` | Puerto de la API. |
| `HONEYGATE_EPOLL_HOST` | `127.0.0.1` | Interfaz de los servicios emulados. |
| `HONEYGATE_HEADLESS` | `0` (automático sin terminal) | `1` desactiva la consola. |
| `HONEYGATE_PORTAL_HOST` | `127.0.0.1` | Interfaz del portal. |
| `HONEYGATE_PORTAL_PORT` | `8090` | Puerto del portal (distinto al de la API). |
| `HONEYGATE_PORTAL_SECRET` | generado en `data/portal_secret` (permisos 600) | Clave HMAC para proteger los mails. |
| `HONEYGATE_PORTAL_LAB_MODE` | `0` | `1` escribe el OTP en el log. Solo laboratorio. |
| `HONEYGATE_PORTAL_OTP_OPTIONAL` | `0` | `1` permite registrar sin OTP; la sesión queda "mail sin verificar". |
| `HONEYGATE_SMTP_HOST` | vacío | Servidor SMTP para enviar el OTP. |
| `HONEYGATE_SMTP_PORT` | `587` | Puerto SMTP. |
| `HONEYGATE_SMTP_USER` | vacío | Usuario SMTP. |
| `HONEYGATE_SMTP_PASS` | vacío | Clave SMTP. Solo por variable de entorno; nunca va a SQLite ni a logs. |
| `HONEYGATE_SMTP_PASSWORD` | vacío | Alias de la anterior. |
| `HONEYGATE_SMTP_FROM` | usuario SMTP o `noreply@honeygate.local` | Remitente. |
| `HONEYGATE_SMTP_USE_TLS` | `1` | STARTTLS. |
| `HONEYGATE_SMTP_USE_SSL` | `0` | `1` usa SMTP sobre SSL. |
| `HONEYGATE_MITRE_RULES_PATH` | `honeygate/mitre_rules.json` | Archivo de reglas MITRE. |

Cambiar un `*_HOST` a otra interfaz expone el servicio a la red. La API y el portal van en HTTP plano: para eso se necesita un proxy con TLS delante.

---

## Puertos

Todos en `127.0.0.1` y por encima del 1024.

| Puerto | Servicio | Comportamiento |
| --- | --- | --- |
| `8888` | API REST + panel web | `/api/*` con token. |
| `8090` | Portal cautivo | HTML estático, OTP y anti-Sybil. Sin token ni `/api/*`. |
| `2222` | SSH emulado | Banner `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2`; respuestas fijas. |
| `2323` | Telnet emulado | Banner Debian 12 (`srv-app-02`) y `login:`. |
| `8080` | HTTP emulado | `Server: Apache/2.4.57 (Debian)`. |
| `8443` | HTTP señuelo | Mismo perfil; HTTP plano, sin TLS. |
| `3306` | MySQL emulado | Saludo binario real del protocolo (`8.0.39-0+deb12u1`). |

---

## Servicio systemd

Unidad de usuario de ejemplo en `deploy/systemd/honeygate.service`, con `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict` y escritura solo en `data/` y `logs/`. Supone el repositorio en `~/HoneyGate`; si está en otro lado, ajustá las rutas del archivo.

```bash
mkdir -p ~/.config/systemd/user
cp deploy/systemd/honeygate.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now honeygate.service
systemctl --user status honeygate.service
journalctl --user -u honeygate.service -f
```

Lee las variables de `~/HoneyGate/.env` si existe.

---

## Pruebas

```bash
python3 test_honeygate.py
```

Son 14 bloques de integración y seguridad: banner, límite de tasa, token obligatorio, ausencia de CORS, validación de entradas, persistencia, portal y OTP, anti-Sybil, servicios emulados sin ejecución ni salida, informe y borrado, y archivos de despliegue.

Pruebas de la app:

```bash
gradle :app:testDebugUnitTest
```

Cada push y pull request corre las pruebas de Python en GitHub Actions (`.github/workflows/tests.yml`).

---

## Solución de problemas

| Síntoma | Causa probable | Qué hacer |
| --- | --- | --- |
| La app dice "Sin conexión" | Falta el túnel o el daemon no corre | `adb reverse tcp:8888 tcp:8888` y verificá que el daemon esté activo. |
| La app dice "Configurá el token" | Token vacío | Cargalo en **Conectar**. |
| La API responde `401` | Token incorrecto o de un arranque anterior | Usá el token actual o definí `HONEYGATE_API_TOKEN`. |
| Funcionaba y dejó de conectar | El túnel se cayó al desenchufar | Repetí `adb reverse`. |
| El portal responde `503` | Modo 2, portal apagado o sin SMTP | Pasá a modo 1 o 3, activá `portal_enabled`, configurá SMTP o usá modo laboratorio. |
| El portal responde `429` | Se superó el límite de pedidos | Esperá a que venza la ventana. |
| `Address already in use` | Otro proceso usa el puerto | Cambiá `HONEYGATE_API_PORT` / `HONEYGATE_PORTAL_PORT` o cerrá el otro proceso. |
| `Keystore file ... debug.keystore not found` al compilar | Falta el keystore de depuración | Crealo con el comando `keytool` de [Obtener el APK](#obtener-el-apk). |
| `gradlew: command not found` | El repo no trae el wrapper | Usá Android Studio, o instalá Gradle 9.3.1 y corré `gradle wrapper`. |
| Falla por versión de Java o del SDK | JDK viejo o falta la plataforma | JDK 17+ y Android SDK Platform 36.1. |
| `adb devices` muestra `unauthorized` | No se aceptó la huella | Desbloqueá el celular y aceptá el aviso. |
| La vista previa de AI Studio muestra una versión vieja | Compilación en caché de la plataforma | Instalá el APK en un celular para ver la versión real. |

---

## Límites conocidos

1. **Sin control de la red.** No redirige, no limita ancho de banda y no corta internet. Lo que el daemon sugiere lo tiene que aplicar el router.
2. **Sin TLS propio.** API, portal y puerto 8443 van en HTTP plano sobre `127.0.0.1`. Para otra interfaz hace falta un proxy inverso con TLS o un túnel.
3. **Huella parcial.** El portal mide de verdad la MAC (por tabla ARP), las cabeceras HTTP y su orden, y con JavaScript activo la pantalla, zona horaria, idioma, canvas y fuentes. SSID, JA3/JA4 y DHCP quedan vacíos salvo que una sonda externa los aporte.
4. **El panel web entrega el token** a quien abra `http://127.0.0.1:8888/`. Es aceptable mientras escuche solo en `127.0.0.1`; hay que resolverlo antes de exponerlo a una red.
5. **Emulación de baja interacción.** Los servicios responden desde una tabla fija; no son un sistema real ni una máquina sacrificial.
6. **Solo Linux** (o WSL2).
7. **Sin prueba de campo todavía:** el envío por un SMTP real, el servicio systemd y el uso con celular físico deben validarse en cada instalación.

---

## Marco legal

- **Ley 26.388 (delitos informáticos).** Usar solo en redes propias o con autorización expresa y documentada del titular. En una auditoría, acordá por escrito alcance, fechas y contactos.
- **Ley 25.326 (datos personales).**
  - El portal pide consentimiento explícito y recolecta el mail y metadatos técnicos mínimos. Nunca pide ni guarda contraseñas, ni el contenido del tráfico.
  - Los mails se protegen con HMAC-SHA256 y los informes los enmascaran por defecto.
  - Los honeytokens deben ser ficticios; nunca datos de personas reales.
  - La retención es configurable y existe el borrado por visitante, con registro de auditoría sin datos personales.
- Toda acción de bloqueo o borrado pide confirmación.

---

## Estructura del repositorio

```text
├── honeygate/
│   ├── cli_console.py        # Consola interactiva del operador
│   ├── dashboard_api.py      # API REST con token y panel web (8888)
│   ├── deception.py          # Servicios emulados, perfil Debian 12, honeytokens
│   ├── forensic_monitor.py   # Vigilancia con inotify y alertas
│   ├── honeywall_core.py     # Motor epoll, límite de tasa y aislamiento
│   ├── mitre.py              # Carga y validación de reglas MITRE
│   ├── mitre_rules.json      # Reglas MITRE ATT&CK editables
│   ├── portal.py             # Portal cautivo, OTP y anti-Sybil (8090)
│   ├── reporting.py          # Informes JSON / CSV / Markdown
│   └── storage.py            # Persistencia SQLite y borrado de datos
├── app/                      # App Android (Jetpack Compose + Room)
├── modules/                  # Scripts de laboratorio
├── deploy/systemd/           # Unidad systemd de usuario
├── .github/workflows/        # Pruebas automáticas
├── data/  logs/              # Estado local (fuera de git)
├── .env.example              # Variables de entorno, sin secretos
├── run_framework.py          # Lanzador del daemon
└── test_honeygate.py         # Pruebas de integración y seguridad
```
