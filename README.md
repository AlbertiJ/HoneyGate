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
  * Validación obligatoria de tokens en cabecera `X-Auth-Token` para acciones destructivas (`/api/isolate`, `/api/unblock`), devolviendo `401 Unauthorized` ante solicitudes no autenticadas.
  * Verificación estricta de direcciones IP con el módulo `ipaddress`.
  * Sanitización contra XSS en el panel web (sustitución de `innerHTML` por asignaciones seguras de `textContent` y escape de entidades HTML).

---

## 📁 Estructura del Repositorio

```text
├── undahwoar/                 # Núcleo de red y decepción en Python
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
│   │   ├── data/repository/   # Lógica de invariantes, Anti-Sybil y correlación
│   │   ├── ui/screens/        # Pantallas: LazyColumn forense, Honeygate 3 Modos, Sesiones, Blue Team Report
│   │   └── ui/theme/          # Sistema de diseño Eye-Care M3
├── REGLAS_DEL_PROYECTO.md     # Normas fundamentales y directrices de desarrollo
├── run_framework.py           # Lanzador unificado del backend defensivo
├── test_undahwoar.py          # Batería de pruebas automatizadas de integración
└── requirements.txt           # Dependencias Python
```

---

## 🚀 Guía de Inicio Rápido

### 1. Ejecución del Backend en Kali Linux o WSL2

```bash
# Instalar dependencias opcionales
pip install -r requirements.txt

# Ejecutar las pruebas automatizadas del motor defensivo
python3 test_undahwoar.py

# Iniciar el framework completo (CLI interactiva + Servidor Web en 127.0.0.1:8888)
python3 run_framework.py
```

* **Consola Interactiva**: Disponible de inmediato en la terminal con comandos `status`, `honeywall-stats`, `isolate <ip>`, `unblock <ip>`.
* **API y Dashboard**: Accesible localmente en `http://127.0.0.1:8888`.

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

Para garantizar la estabilidad operacional y permitir revertir cualquier cambio ante incidencias en auditorías o producción, HoneyGate cuenta con puntos de restauración etiquetados (*checkpoints*) y un script automatizado:

### 1. Tag de Restauración Estable (Checkpoint)
* **Tag Actual**: `v1.0.0-checkpoint`
* **Commit Base**: `e7ec5d6` (*"feat(honeygate): mejoras en UI/UX, barra tactica, validacion OTP, auditoria SQLi y branding corporativo"*)

### 2. Ejecutar Rollback Automático
Se incluye el script `rollback.sh` para volver al estado estable con respaldo previo automático (`git stash`):

```bash
# Restaurar al punto v1.0.0-checkpoint
./rollback.sh

# Restaurar forzando descarte de cambios locales no confirmados
./rollback.sh --hard v1.0.0-checkpoint
```

### 3. Rollback Manual mediante Git
```bash
# Opción A (Recomendada): Volver temporalmente al estado del checkpoint
git checkout v1.0.0-checkpoint

# Opción B (Reversión Limpia): Crear un commit inverso que deshaga los cambios recientes
git revert HEAD --no-edit

# Opción C (Forzar la rama main al commit estable anterior):
git reset --hard v1.0.0-checkpoint
```

### 4. Sincronización con GitHub (Push)
Para publicar este lanzamiento y sus etiquetas de restauración en tu repositorio de GitHub:
```bash
# 1. Configurar la URL de tu repositorio remoto:
git remote add origin https://github.com/<TU_USUARIO>/<TU_REPOSITORIO>.git

# 2. Subir la rama main y los tags de checkpoint:
git push -u origin main --tags
```

---

## ⚖️ Marco Legal y Ética Operacional

Este software ha sido diseñado exclusivamente para auditorías de seguridad autorizadas, entornos de laboratorio, investigación forense y defensa perimetral corporativa.
* **Ley 25.326 (República Argentina)**: Garantiza la protección integral de datos personales almacenados en archivos o bancos de datos.
* **Ley 26.388 (República Argentina)**: Tipifica los delitos informáticos y sanciona el acceso no autorizado a sistemas informáticos.

El uso de **HoneyGate** debe realizarse siempre en infraestructuras propias o con autorización explícita y por escrito de sus propietarios.
