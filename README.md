# HoneyGate

**Framework Defensivo de Decepción, Contención Perimetral y Telemetría Forense para Kali Linux (Non-Root / WSL2)**

---

## Descripción del Proyecto

**Undahwoar Honeywall** es un framework de ciberseguridad defensiva diseñado para operar en espacio de usuario (*Non-Root*). Combina un núcleo asíncrono de alto rendimiento basado en **Edge-Triggered epoll**, un controlador perimetral con mitigación activa por límite de tasa (*Rate-Limiting*), una consola interactiva avanzada no bloqueante con autocompletado en tiempo real, un subsistema forense reactivo gobernado por llamadas nativas al kernel con **inotify** (`libc.so.6`), un servidor web asíncrono con telemetría visual y una aplicación móvil complementaria en Jetpack Compose.

---

## Módulos Principales

### 1. Núcleo de Red y Honeywall (`undahwoar/honeywall_core.py`)
* **Sockets Asíncronos**: Descriptores configurados en modo no bloqueante mediante `fcntl` (`O_NONBLOCK`).
* **Bucle epoll Edge-Triggered (`EPOLLET`)**: Monitoreo de puertos altos no privilegiados (`2222` para simulación SSH, `8080` para HTTP, `8443` para HTTPS).
* **Mitigación Perimetral**:
  * Resolución de direcciones físicas MAC en espacio de usuario leyendo `/proc/net/arp`.
  * Umbral estricto: **10 peticiones salientes por minuto** por sesión interactiva.
  * Ante infracción por escaneo o pivoteo, se invoca de forma inmediata la llamada nativa `shutdown(socket.SHUT_RDWR)` y `close()`, aislando la IP infractora.

### 2. Consola Interactiva Avanzada No Bloqueante (`undahwoar/cli_console.py`)
* **Concurrencia Thread-Safe**: Opera en un hilo secundario dedicado (`threading.Thread`) sincronizado con colas seguras para evitar bloqueos en el bucle epoll.
* **Interfaz con prompt_toolkit**: Diseñada con estética de terminal táctica para Kali Linux.
* **Autocompletado Predictivo de 3 Niveles (`Completer`)**:
  * **Nivel 1 (Gestión)**: `status`, `honeywall-stats`, `isolate <ip>`, `unblock <ip>`, `connections`, `logs`, `exit`.
  * **Nivel 2 (Auditoría de Espacio de Usuario)**: Parsing nativo de `/proc/net/tcp` (conversión de hex a IPv4 y estados del socket como ESTABLISHED, LISTEN, TIME_WAIT) y `/proc/net/arp`.
  * **Nivel 3 (Laboratorio)**: Indexación dinámica en caliente de archivos `.py` en `./modules/`.

### 3. Subsistema Forense inotify y Dashboard Web (`undahwoar/forensic_monitor.py` y `undahwoar/dashboard_api.py`)
* **Vigilancia por Eventos del Kernel**: Enlace nativo con `libc.so.6` vía `ctypes` (`inotify_init1`, `inotify_add_watch`) con máscara `IN_MODIFY | IN_CLOSE_WRITE` para supervisar logs sin consumo de CPU.
* **Motor de Patrones Regex**: Identificación inmediata de `Failed password`, `Accepted password` y alertas de bloqueo de Undahwoar.
* **Despacho Visual**: Alertas gráficas en el escritorio de Kali Linux mediante `notify-send`.
* **API y Dashboard Asíncrono**: Servidor en tiempo real (puerto `8888`) con endpoints JSON (`/api/status`, `/api/connections`, `/api/alerts`, `/api/isolate`) y panel web HTML5/JS integrado.

### 4. Módulos de Capacitación y Laboratorio (`./modules/`)
* `test_port_scan.py`: Sondeo de puertos defensivos.
* `brute_force_sim.py`: Generador de intentos de autenticación para disparar alertas inotify.
* `honeywall_probe.py`: Ráfaga interactiva para validar el corte forzado por *rate-limiting*.

---

## Requisitos e Instalación

### En Kali Linux o WSL2

```bash
# Clonar o copiar el repositorio
git clone <URL_DE_TU_REPOSITORIO>
cd undahwoar

# Instalar dependencias opcionales para la CLI estética
pip install -r requirements.txt
```

### Ejecutar Pruebas Automatizadas

```bash
python3 test_undahwoar.py
```

### Iniciar el Framework Completo

```bash
python3 run_framework.py
```

* **CLI Interactiva**: Disponible de inmediato en la terminal.
* **Dashboard Web**: Acceder desde el navegador a `http://localhost:8888`.

---

## Estructura del Repositorio

```text
├── undahwoar/               # Módulos del núcleo defensivo Python
│   ├── __init__.py
│   ├── honeywall_core.py    # Motor epoll ET y Honeywall
│   ├── cli_console.py       # Consola interactiva y autocompletador de 3 niveles
│   ├── forensic_monitor.py  # inotify con ctypes, regex y notify-send
│   └── dashboard_api.py     # Servidor web y panel de telemetría HTML5
├── modules/                 # Scripts de entrenamiento y pruebas
├── logs/                    # Directorio de logs forenses
├── app/                     # Aplicación móvil Android (Jetpack Compose)
├── REGLAS_DEL_PROYECTO.md   # Normas y directrices del proyecto
├── run_framework.py         # Punto de entrada unificado
├── test_undahwoar.py        # Pruebas de integración
└── requirements.txt         # Dependencias Python
```

---

## Licencia y Uso
Desarrollado exclusivamente con fines de ciberseguridad defensiva, educación, investigación de decepción y laboratorios de respuesta a incidentes.
