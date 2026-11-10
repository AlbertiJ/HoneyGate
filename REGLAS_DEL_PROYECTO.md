# Reglas del Proyecto - HoneyGate

Este documento establece las directrices fundamentales de desarrollo, arquitectura defensiva, documentación y comunicación para el proyecto **HoneyGate**.

---

### Regla 1: Idioma y Comunicación
* **Comunicación unificada en español**: Todas las interacciones, explicaciones, documentación, guías de arquitectura, mensajes en terminal, logs y respuestas del sistema se redactarán estrictamente en español (o en el idioma exacto utilizado en la solicitud).
* **Sugerencias y recomendaciones técnicas**: Cualquier propuesta de mejora, análisis de vulnerabilidad, mitigación defensiva o comando recomendado debe presentarse siempre en español.
* **Consistencia terminológica**: Las bitácoras forenses, nombres de módulos e interfaces de usuario mantendrán coherencia bajo el nombre de **HoneyGate**.

---

### Regla 2: Invariantes Obligatorios de HoneyGate
1. **Identidad del Visitante (Composite Fingerprint)**:
   * Nunca identificar únicamente por IP o MAC física (debido a aleatorización MAC y NAT compartido).
   * Generar `device_id` compuesto: `MAC-por-SSID + Fingerprint de Navegador (User-Agent, Canvas, Fuentes, Pantalla, Zona Horaria, Idioma) + Fingerprint de Red (JA3/JA4, orden de cabeceras) + DHCP Option 55`.
2. **Contención Estricta de Salida (Data Control)**:
   * El honeypot NUNCA tiene salida irrestricta a Internet.
   * La salida solo se permite hacia destinos en lista blanca explícita o se redirige a sinkhole local. Default: contenida, monitoreada y logueada.
3. **Honeytokens Controlados por el Operador**:
   * Todos los datos señuelo (correos canarios, credenciales señuelo, tokens, falsos registros shadow/secrets) son estrictamente ficticios y controlados por el operador.
   * Su lectura o intento de uso dispara inmediatamente una alerta crítica y correlación forense.
4. **Cumplimiento Legal y Consentimiento Informado (AR)**:
   * Para usuarios en portal cautivo, solo se capturan metadatos de telemetría y conexión con consentimiento explícito bajo **Ley 25.326** (Protección de Datos Personales, Argentina).
   * Operación defensiva exclusiva en infraestructura propia o con autorización expresa bajo **Ley 26.388** (Delitos Informáticos, Argentina).
5. **Confirmación Obligatoria en Acciones Destructivas**:
   * Toda acción de bloqueo, revocación de acceso, aislamiento o purga de registros exige diálogo de confirmación explícito del operador administrador.

---

### Regla 3: Tres Modos de Operación
* **Modo 1: Portal Cautivo con Trazabilidad (Monitoreo Básico)**:
  * Registro ágil con correo electrónico como etiqueta identificatoria.
  * Control Anti-Sybil (máximo 3 registros/hora por `device_id`).
  * Bloqueo de dominios temporales/desechables.
  * Detección de rotación MAC con modo de observación silenciosa (sin bloquear navegación).
  * Arrendamiento DHCP acotado (300 segundos) para forzar re-evaluación periódica de fingerprint.
* **Modo 2: Honeypot para Auditoría / Red Team (Assume-Breach)**:
  * Simulación de 3 usuarios señuelo (Administración, Finanzas, TI) con contraseñas señuelo.
  * Emulación de servicios señuelo (MySQL 3306, Apache 80/443, SSH 2222, Telnet 23).
  * Falsos secretos y shadow files con canarios.
  * Captura de TTPs bajo matriz MITRE ATT&CK.
* **Modo 3: Modo Mixto (Portal + Honeypot)**:
  * Portal cautivo opcional con acceso nominal a Internet (medido y filtrado).
  * Escáner activo de red que mapea dispositivos y correlaciona fingerprints anómalos.

---

### Regla 4: Persistencia Forense y Trazabilidad (Room DB)
* **Persistencia reactiva con Flow**: Todos los eventos forenses (`ForensicEvent`), sesiones (`MonitoredSessionEntity`) y configuraciones (`HoneygateConfigEntity`) se persisten en base de datos Room versión 2.
* **Categorización Canónica**: Los eventos se etiquetan en `'Blocked'` (Contención estricta), `'Alerted'` (Bajo observación y auditoría activa) y `'Normal'` (Tráfico nominal verificado).
* **Diseño UX Eye-Care**: Interfaz en Jetpack Compose construida con paleta oscura de bajo contraste y descanso visual (Slate oscuro `#0F141C`, Esmeralda suave `#10B981`, Cian calmo `#06B6D4`, Ámbar `#F59E0B`, Coral suave `#EF4444`) que previene fatiga ocular durante guardias SOC/Blue Team.

---

### Regla 5: Procedimiento de Rollback y Puntos de Restauración (Checkpoints)
* **Puntos de Restauración Obligatorios**: Tras cada hito o iteración funcional validada, se debe generar un tag de Git identificable (ej. `v1.0.0-checkpoint`) que sirva como ancla de recuperación.
* **Preservación ante Reversiones**: Todo procedimiento de rollback debe resguardar automáticamente las modificaciones no confirmadas mediante `git stash` antes de alterar el árbol de trabajo.
* **Herramienta Integrada**: Se debe mantener operativo y ejecutable el script `rollback.sh` para facilitar la vuelta atrás a cualquier operador sin requerir comandos destructivos directos.
