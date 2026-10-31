# BOOTCAMP ANALISTA SOC NIVEL 2 · RETO FINAL
## Título: Investigación de un posible incidente de seguridad
### De los logs del SIEM a un informe técnico profesional, con una aplicación web asistida por IA

================================================================================
1. CONTEXTO Y MISIÓN
================================================================================
- Escenario: Consultora de ciberseguridad en Estocolmo, Suecia. Usted es el nuevo Analista SOC Nivel 2.
- Reporte del cliente: Posible incidente en su infraestructura. Entrega un archivo Excel con logs exportados de su SIEM.
- Misión: Buscar indicadores de compromiso (IoC), correlacionar eventos y establecer si hubo uno o varios incidentes.

================================================================================
2. QUÉ DEBE DETECTAR LA APLICACIÓN
================================================================================
1. Fuerza bruta: Intentos de acceso no autorizados (ej. Password spraying a DC-01).
2. Inicios sospechosos: Sesiones anómalas por origen, horario o patrón (ej. RDP desde IP externa a APP-SRV01).
3. Escalamiento: Elevación de privilegios (ej. Asignación de privilegios especiales Event 4672).
4. Comandos y procesos: Ejecución sospechosa en equipos (ej. PowerShell EncodedCommand, whoami, discovery).
5. Movimiento lateral: Saltos entre sistemas de la red (ej. de APP-SRV01 a FS-SRV01 vía SMB).
6. Otras anomalías: Cualquier comportamiento fuera de lo normal (ej. borrado de shadow copies con vssadmin, exfiltración HTTPS a proxy, persistencia con servicio wuhelper.exe, webshell en WEB-01).

================================================================================
3. SEIS FUNCIONALIDADES REQUERIDAS
================================================================================
01. Carga de archivos: Importar y visualizar el Excel (.xlsx / .csv).
02. Análisis de seguridad: Identificar eventos sospechosos y correlacionarlos.
03. Dashboard: Estadísticas y gráficos interactivos por criticidad.
04. Clasificación de riesgos: Crítico, Alto, Medio o Bajo, con justificación.
05. Informe técnico: Documento estructurado y completo.
06. Exportación: Descarga del informe en PDF.

================================================================================
4. CONTENIDO OBLIGATORIO DEL INFORME TÉCNICO (PDF)
================================================================================
El PDF generado debe contener obligatoriamente estas 8 secciones:
1. Resumen ejecutivo.
2. Hallazgos identificados.
3. Explicación técnica de cada hallazgo.
4. Evidencias encontradas en los logs (Citar Log_IDs reales, hosts, usuarios, IPs).
5. Criticidad y justificación.
6. Posible impacto en la organización.
7. Plan de acción: investigar, contener y remediar.
8. Recomendaciones generales de seguridad.

================================================================================
5. REQUISITOS ADICIONALES DEL EVALUADOR
================================================================================
- Interfaz: Moderna, intuitiva y fácil de utilizar (Estilo Dark Cyberpunk / Falcon / Linear).
- IA integrada: Apoya el análisis de datos y la redacción del informe.
- Sin Sentinel: No se requiere integración con Microsoft Sentinel.
- Rigor analítico: NO INVENTAR HALLAZGOS: cada conclusión debe estar sustentada estrictamente en los registros proporcionados.

================================================================================
6. ENTREGABLES FINALES
================================================================================
1. Informe de seguridad (PDF): Generado directamente por la aplicación.
2. Video demostrativo: Máximo 5 minutos (de la carga del Excel al análisis y la generación del PDF).
