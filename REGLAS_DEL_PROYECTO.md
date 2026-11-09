# Reglas del Proyecto - Undahwoar Honeywall

Este documento establece las directrices fundamentales de desarrollo, documentación y comunicación para el proyecto **Undahwoar Honeywall**. Se irá actualizando a medida que se definan nuevos requerimientos y estándares.

---

### Regla 1: Idioma y Comunicación
* **Comunicación unificada en español**: Todas las interacciones, explicaciones, documentación, guías de arquitectura, mensajes en terminal y respuestas del sistema se redactarán estrictamente en español (o en el idioma exacto utilizado en la solicitud).
* **Sugerencias y recomendaciones**: Cualquier propuesta de mejora, análisis de vulnerabilidad, sugerencia técnica o comando recomendado debe presentarse siempre en el mismo idioma de comunicación del proyecto (español).
* **Consistencia en código y logs**: Las salidas por consola, descripciones de módulos, comentarios explicativos y bitácoras forenses respetarán esta directriz para asegurar coherencia operativa en entornos hispanohablantes.

---

### Regla 2: Persistencia Forense y Trazabilidad Local (Room DB)
* **Persistencia reactiva con Flow**: Todos los eventos forenses, sesiones capturadas y estados de contención deben persistirse localmente mediante Android Room, exponiendo `Flow<T>` en DAOs y `StateFlow<T>` en ViewModels.
* **Estados canónicos de contención**: Todo registro de seguridad debe categorizarse bajo los tres estados canónicos: `'Blocked'` (Contención estricta), `'Alerted'` (Bajo observación y auditoría activa) y `'Normal'` (Tráfico nominal verificado).
* **Correlación IP/MAC**: Se debe preservar el historial de direcciones físicas MAC y sus asignaciones de IP dinámicas, manteniendo el rastreo de múltiples identidades asociadas para evitar elusión por renovación DHCP.

---

### Regla 3: Arquitectura Honeygate (Puertas de Miel de Decepción)
* **Navegación permisiva engañosa**: Si un host genera anomalías (múltiples registros, fallo de credenciales), el sistema no debe cortar la conexión inmediatamente; debe mantener la navegación permitida en modo engañoso auditando los destinos para recopilar inteligencia de amenazas (IoCs).
* **Contención de inyecciones**: Los intentos de Inyección SQL (SQLi) deben ser correlacionados de inmediato con las identidades de la MAC y reportados al panel de administración para bloqueo en cascada.
* **Estándar de Informes de Ingeniería**: Los informes para el equipo defensivo (Blue Team) deben apegarse a la taxonomía MITRE ATT&CK, matriz de correlación forense y planes de mitigación accionables.
