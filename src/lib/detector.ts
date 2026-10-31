/**
 * Motor de deteccion y correlacion SOC N2 (SKILL 3).
 *
 * Principio rector: *toda* conclusion nace de una fila real del dataset. No hay
 * hallazgos precocinados ni IoCs cableados; las reglas son genericas y lo que se
 * cita como evidencia es siempre el Log_ID, host, usuario y comando tal y como
 * aparecen en el fichero cargado. Si una tecnica no esta en los logs, no se
 * reporta.
 *
 * Cobertura (las 6 familias del enunciado):
 *   1. BRUTE_FORCE          - fuerza bruta y password spraying
 *   2. SUSPICIOUS_LOGON     - inicios anomalos por origen, horario o patron
 *   3. PRIVILEGE_ESCALATION - elevacion de privilegios
 *   4. COMMAND_EXECUTION    - comandos y procesos sospechosos
 *   5. LATERAL_MOVEMENT     - saltos entre sistemas
 *   6. ANOMALY              - resto de comportamiento anomalo (impacto,
 *                             persistencia, exfiltracion, evasion...)
 */

import {
  isMachineAccount,
  isPublicIp,
  maxSeverity,
  normalizeUser,
  SEVERITY_RANK,
  severityFromScore,
  topCounts,
  uniq,
} from "./utils";
import type {
  AnalysisResult,
  AnalysisStats,
  Confidence,
  DetectionCategory,
  Evidence,
  Finding,
  Incident,
  KillChainPhase,
  LogEvent,
  MitreRef,
  ParsedDataset,
  Severity,
  TimelineBucket,
} from "./types";

/** Maximo de evidencias citadas por hallazgo (el total real se conserva aparte). */
const MAX_EVIDENCE = 12;

const BASE_SCORE: Record<Severity, number> = {
  CRITICAL: 88,
  HIGH: 66,
  MEDIUM: 44,
  LOW: 22,
};

// ---------------------------------------------------------------------------
// Utilidades internas
// ---------------------------------------------------------------------------

interface Match {
  event: LogEvent;
  detail: string;
}

/** Texto unificado en minusculas sobre el que corren las firmas. */
function eventText(e: LogEvent): string {
  return [
    e.process,
    e.parentProcess,
    e.commandLine,
    e.target,
    e.action,
    e.status,
    e.message,
  ]
    .filter(Boolean)
    .join(" | ")
    .toLowerCase();
}

/** Descripcion mas informativa disponible de un evento, para citarlo. */
function describe(e: LogEvent): string {
  return (
    e.commandLine ||
    e.target ||
    e.message ||
    [e.process, e.action, e.status].filter(Boolean).join(" ") ||
    `EventID ${e.eventId}`
  );
}

function toEvidence(m: Match): Evidence {
  return {
    logId: m.event.logId,
    timestamp: m.event.timestamp ?? m.event.rawTimestamp,
    eventId: m.event.eventId,
    host: m.event.host,
    user: m.event.user,
    ip: m.event.sourceIp || m.event.destIp,
    detail: m.detail,
  };
}

function byTime(a: LogEvent, b: LogEvent): number {
  return (a.epoch ?? Number.MAX_SAFE_INTEGER) - (b.epoch ?? Number.MAX_SAFE_INTEGER);
}

function spanOf(events: readonly LogEvent[]): { first: string | null; last: string | null } {
  const epochs = events.map((e) => e.epoch).filter((e): e is number => e !== null);
  if (!epochs.length) return { first: null, last: null };
  return {
    first: new Date(Math.min(...epochs)).toISOString(),
    last: new Date(Math.max(...epochs)).toISOString(),
  };
}

/** Numero maximo de eventos dentro de una ventana deslizante. */
function peakInWindow(events: readonly LogEvent[], windowMs: number): number {
  const stamps = events
    .map((e) => e.epoch)
    .filter((e): e is number => e !== null)
    .sort((a, b) => a - b);
  if (stamps.length === 0) return events.length;
  let best = 0;
  let left = 0;
  for (let right = 0; right < stamps.length; right += 1) {
    while (stamps[right] - stamps[left] > windowMs) left += 1;
    best = Math.max(best, right - left + 1);
  }
  return best;
}

function groupBy<T>(items: readonly T[], key: (item: T) => string): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    if (!k) continue;
    const bucket = map.get(k);
    if (bucket) bucket.push(item);
    else map.set(k, [item]);
  }
  return map;
}

// ---------------------------------------------------------------------------
// Clasificadores de eventos (agnosticos del SIEM concreto)
// ---------------------------------------------------------------------------

const FAILED_LOGON_IDS = new Set(["4625", "4771", "4776", "529", "530", "531", "535", "539"]);
const SUCCESS_LOGON_IDS = new Set(["4624", "4768", "528", "540"]);
const FILE_ACCESS_IDS = new Set(["4663", "4656", "4660", "5145"]);
const SHARE_ACCESS_IDS = new Set(["5140", "5145"]);

function isFailedLogon(e: LogEvent, text: string): boolean {
  if (FAILED_LOGON_IDS.has(e.eventId)) return true;
  const authContext = /(logon|log-on|sign-?in|inicio de sesion|authentic|autentic|login|credential|kerberos)/.test(text);
  const failed = /(fail|fallid|fallo|denied|denegad|incorrect|invalid|rejected|rechaz|bad password|error)/.test(text);
  return authContext && failed;
}

function isSuccessfulLogon(e: LogEvent, text: string): boolean {
  if (SUCCESS_LOGON_IDS.has(e.eventId)) return true;
  if (FAILED_LOGON_IDS.has(e.eventId)) return false;
  const authContext = /(logon|log-on|sign-?in|inicio de sesion|authentic|autentic|login)/.test(text);
  const ok = /(success|correct|exitos|granted|concedid|accepted|permitid)/.test(text);
  return authContext && ok;
}

/** Etiqueta legible del LogonType de Windows. */
function logonTypeLabel(type: string): string {
  const map: Record<string, string> = {
    "2": "Interactivo (consola)",
    "3": "Red (SMB/recursos compartidos)",
    "4": "Batch",
    "5": "Servicio",
    "7": "Desbloqueo",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
  };
  return map[type.trim()] ?? (type.trim() ? `Tipo ${type.trim()}` : "No especificado");
}

const URL_HOST = /https?:\/\/([a-z0-9._:-]+)/i;
const UNC_PATH = /\\\\([\w.$-]+)\\([^\\\s"';|]+)/;
const FILE_PATH = /[a-z]:\\[^\s"';|]+\.[a-z0-9]{2,5}\b|\\\\[^\s"';|]+\.[a-z0-9]{2,5}\b/i;

/** Destino externo de un evento de red: IP publica o host de una URL publica. */
/**
 * Segmento de ruta con informacion de negocio sensible (`\\FS-SRV01\Finance`,
 * `Finance\Budget2027.xlsx`, `Finance\FY2026\...`). Se exige que vaya pegado a
 * un separador de ruta para no disparar con texto libre.
 */
const SENSITIVE_DATA_PATH =
  /(?:^|[\\/:\s])(?:finance|finanzas|budget|presupuesto|payroll|nominas?|contabilidad|accounting|fy20\d{2})[\w-]*(?:[\\/]|\.(?:xlsx?|csv|docx?|pdf)\b)|\\(?:finance|finanzas|payroll|contabilidad|accounting)\s*$/im;

/** Ruta del objeto accedido, para listar los ficheros sensibles. */
function sensitiveObject(e: LogEvent): string {
  const text = `${e.target} ${e.message} ${e.commandLine}`;
  const path = /\\\\[^\s"']+|[\w$-]+(?:\\[^\s"'\\]+)+/.exec(text);
  return path ? path[0] : e.target || e.message;
}

function outboundTarget(e: LogEvent): string | null {
  if (isPublicIp(e.destIp)) return e.destIp;
  const haystack = `${e.target} ${e.message} ${e.commandLine}`;
  const url = URL_HOST.exec(haystack);
  if (url) {
    const host = url[1].split(":")[0];
    if (isPublicIp(host) || /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(host)) return host;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Catalogo de firmas
// ---------------------------------------------------------------------------

interface Signature {
  id: string;
  title: string;
  category: DetectionCategory;
  severity: Severity;
  phase: KillChainPhase;
  mitre: MitreRef[];
  /** Firma textual; se evalua contra `eventText`. */
  test?: RegExp;
  /** IDs de evento que disparan la firma por si solos. */
  eventIds?: readonly string[];
  /** Predicado a medida cuando la firma no es puramente textual. */
  predicate?: (e: LogEvent, text: string) => boolean;
  explanation: string;
  impact: string;
  investigation: string[];
  containment: string[];
  remediation: string[];
  /** Firmas con el mismo grupo se consolidan en un unico hallazgo. */
  group?: string;
}

const T = (tactic: string, techniqueId: string, technique: string): MitreRef => ({
  tactic,
  techniqueId,
  technique,
});

const SIGNATURES: readonly Signature[] = [
  // --- Ejecucion y ofuscacion -------------------------------------------
  {
    id: "powershell-encoded",
    title: "PowerShell ofuscado con -EncodedCommand",
    category: "COMMAND_EXECUTION",
    severity: "CRITICAL",
    phase: "Ejecucion",
    mitre: [
      T("Ejecucion", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
      T("Evasion de defensas", "T1027", "Obfuscated Files or Information"),
    ],
    test: /-encodedcommand\b|(?:^|[\s"'])-e(?:nc?)?\s+[a-z0-9+/=]{24,}/,
    explanation:
      "Se ha ejecutado PowerShell pasando la carga util codificada en Base64 mediante -EncodedCommand. " +
      "Esta tecnica no tiene uso administrativo legitimo habitual: su proposito es impedir que el comando real " +
      "aparezca en los registros de linea de comandos y evadir reglas de deteccion basadas en cadenas. El texto " +
      "codificado debe decodificarse durante la investigacion para recuperar el script original.",
    impact:
      "Ejecucion de codigo arbitrario no auditable en el endpoint, habitualmente usada para descargar la siguiente " +
      "etapa del ataque o establecer un canal de mando y control.",
    investigation: [
      "Decodificar en Base64 el payload de cada comando citado y preservar el script resultante como evidencia.",
      "Revisar el proceso padre que invoco a PowerShell para determinar el vector de entrada.",
      "Buscar conexiones de red salientes del mismo host en los 10 minutos posteriores a cada ejecucion.",
    ],
    containment: [
      "Aislar el host de la red manteniendolo encendido para preservar memoria volatil.",
      "Terminar los procesos PowerShell en ejecucion asociados y bloquear los hashes observados.",
    ],
    remediation: [
      "Activar Script Block Logging (EventID 4104) y Module Logging en toda la flota.",
      "Aplicar PowerShell Constrained Language Mode y AppLocker/WDAC en estaciones de usuario.",
    ],
  },
  {
    id: "powershell-stealth",
    title: "PowerShell con parametros de ejecucion sigilosa",
    category: "COMMAND_EXECUTION",
    severity: "HIGH",
    phase: "Evasion de defensas",
    mitre: [
      T("Ejecucion", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
      T("Evasion de defensas", "T1562.001", "Impair Defenses: Disable or Modify Tools"),
    ],
    test: /-nop\b|-noprofile\b|-w(?:indowstyle)?\s+hidden|-executionpolicy\s+bypass|-ep\s+bypass|-noni\b|-noninteractive\b/,
    explanation:
      "Los modificadores observados (ventana oculta, omision de la politica de ejecucion, sin perfil ni interaccion) " +
      "se combinan para que el script se ejecute sin que el usuario lo perciba y sin las restricciones configuradas. " +
      "Es el patron estandar de los loaders y de la post-explotacion automatizada.",
    impact:
      "Ejecucion silenciosa de scripts que el usuario no puede advertir ni interrumpir, saltandose la politica de ejecucion corporativa.",
    investigation: [
      "Recuperar el contenido completo del script invocado en cada comando citado.",
      "Comprobar si la politica de ejecucion esta efectivamente forzada por GPO en el host afectado.",
    ],
    containment: ["Bloquear la ejecucion de PowerShell para las cuentas implicadas hasta cerrar el analisis."],
    remediation: ["Forzar ExecutionPolicy por GPO (no por sesion) y registrar bloques de script."],
  },
  {
    id: "powershell-download",
    title: "Descarga de carga util mediante PowerShell",
    category: "COMMAND_EXECUTION",
    severity: "HIGH",
    phase: "Ejecucion",
    mitre: [T("Mando y control", "T1105", "Ingress Tool Transfer")],
    test: /downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|\biwr\b|net\.webclient|start-bitstransfer/,
    explanation:
      "Se invocan primitivas de descarga de PowerShell para traer contenido remoto al endpoint. Combinadas con " +
      "ejecucion en memoria permiten introducir herramientas sin escribirlas en disco, evitando el antivirus basado en ficheros.",
    impact: "Introduccion de herramienta ofensiva adicional o de la siguiente etapa del implante.",
    investigation: [
      "Extraer las URL o IPs de destino de cada comando y contrastarlas con inteligencia de amenazas.",
      "Revisar los logs de proxy para confirmar si la descarga se completo y con que volumen.",
    ],
    containment: ["Bloquear en proxy y firewall los destinos identificados."],
    remediation: ["Restringir la salida a Internet de servidores mediante lista blanca."],
  },
  {
    id: "iex-execution",
    title: "Ejecucion en memoria con Invoke-Expression",
    category: "COMMAND_EXECUTION",
    severity: "HIGH",
    phase: "Ejecucion",
    mitre: [T("Ejecucion", "T1059.001", "Command and Scripting Interpreter: PowerShell")],
    test: /invoke-expression|\biex\s*[("'$]/,
    explanation:
      "Invoke-Expression evalua una cadena como codigo. Encadenado con una descarga remota ejecuta el payload " +
      "directamente en memoria, sin dejar artefactos en el sistema de ficheros.",
    impact: "Ejecucion sin fichero (fileless) que deja poca traza forense en disco.",
    investigation: ["Volcar la memoria del proceso implicado antes de reiniciar el host."],
    containment: ["Aislar el host preservando la memoria volatil."],
    remediation: ["Habilitar AMSI y verificar que el EDR inspecciona el contenido de los bloques de script."],
  },
  {
    id: "lolbin-abuse",
    title: "Abuso de binarios legitimos del sistema (LOLBins)",
    category: "COMMAND_EXECUTION",
    severity: "HIGH",
    phase: "Evasion de defensas",
    mitre: [
      T("Evasion de defensas", "T1218", "System Binary Proxy Execution"),
      T("Mando y control", "T1105", "Ingress Tool Transfer"),
    ],
    test: /certutil(?:\.exe)?[^|]*-urlcache|certutil(?:\.exe)?[^|]*-decode|bitsadmin[^|]*\/transfer|mshta\s+(?:http|javascript)|regsvr32[^|]*\/i:http|rundll32[^|]*javascript:|msbuild[^|]*\.xml/,
    explanation:
      "Binarios firmados por Microsoft se estan usando para descargar, decodificar o ejecutar contenido. Al estar " +
      "firmados superan los controles de lista blanca, por eso son el vehiculo preferido para evadir AppLocker.",
    impact: "Evasion de controles de ejecucion y transferencia de herramientas fuera de los canales monitorizados.",
    investigation: ["Identificar el artefacto descargado o decodificado y analizarlo en entorno aislado."],
    containment: ["Bloquear los destinos de red implicados."],
    remediation: ["Desplegar reglas WDAC que restrinjan el uso de LOLBins conocidos."],
  },
  {
    id: "credential-dumping",
    title: "Intento de volcado de credenciales",
    category: "COMMAND_EXECUTION",
    severity: "CRITICAL",
    phase: "Acceso a credenciales",
    mitre: [
      T("Acceso a credenciales", "T1003.001", "OS Credential Dumping: LSASS Memory"),
      T("Acceso a credenciales", "T1003.003", "OS Credential Dumping: NTDS"),
    ],
    test: /mimikatz|sekurlsa|lsadump|procdump[^|]*lsass|comsvcs\.dll[^|]*minidump|reg(?:\.exe)?\s+save\s+hk(?:lm|ey_local_machine)|ntdsutil|ntds\.dit|\bsamdump\b|\bhashdump\b/,
    explanation:
      "Se observan herramientas o comandos orientados a extraer material de autenticacion de la memoria de LSASS o " +
      "de la base de datos de Active Directory. Un volcado exitoso entrega al atacante hashes o tickets reutilizables.",
    impact:
      "Compromiso potencial de todas las credenciales cacheadas en el sistema, incluidas cuentas de dominio " +
      "privilegiadas. Habilita Pass-the-Hash y escalada a control total del dominio.",
    investigation: [
      "Determinar que cuentas tenian sesion iniciada en el host en el momento del volcado.",
      "Revisar si el fichero de volcado resultante fue exfiltrado.",
    ],
    containment: [
      "Forzar el restablecimiento de contrasena de todas las cuentas con sesion en el host.",
      "Restablecer dos veces la contrasena de la cuenta krbtgt si hay indicios de acceso a NTDS.",
    ],
    remediation: [
      "Habilitar Credential Guard y proteccion LSA (RunAsPPL).",
      "Aplicar el modelo de niveles administrativos (tiering) para que cuentas de dominio no inicien sesion en estaciones.",
    ],
  },

  // --- Descubrimiento (se consolidan en un unico hallazgo) ---------------
  {
    id: "discovery-whoami",
    group: "discovery",
    title: "Enumeracion del contexto de usuario",
    category: "COMMAND_EXECUTION",
    severity: "MEDIUM",
    phase: "Descubrimiento",
    mitre: [T("Descubrimiento", "T1033", "System Owner/User Discovery")],
    test: /\bwhoami\b/,
    explanation: "",
    impact: "",
    investigation: [],
    containment: [],
    remediation: [],
  },
  {
    id: "discovery-network",
    group: "discovery",
    title: "Enumeracion de red y recursos compartidos",
    category: "COMMAND_EXECUTION",
    severity: "MEDIUM",
    phase: "Descubrimiento",
    mitre: [T("Descubrimiento", "T1135", "Network Share Discovery")],
    test: /net(?:\.exe)?\s+view\b|net(?:\.exe)?\s+share\b|get-smbshare|\barp\s+-a\b|\bnetstat\s+-an/,
    explanation: "",
    impact: "",
    investigation: [],
    containment: [],
    remediation: [],
  },
  {
    id: "discovery-accounts",
    group: "discovery",
    title: "Enumeracion de cuentas y grupos",
    category: "COMMAND_EXECUTION",
    severity: "MEDIUM",
    phase: "Descubrimiento",
    mitre: [T("Descubrimiento", "T1087", "Account Discovery")],
    test: /get-localgroupmember|get-aduser|get-adgroupmember|get-adcomputer|get-domainuser|net(?:\.exe)?\s+(?:user|group|localgroup)\b(?![^|]*\/add)/,
    explanation: "",
    impact: "",
    investigation: [],
    containment: [],
    remediation: [],
  },
  {
    id: "discovery-domain",
    group: "discovery",
    title: "Enumeracion de la topologia de dominio",
    category: "COMMAND_EXECUTION",
    severity: "MEDIUM",
    phase: "Descubrimiento",
    mitre: [T("Descubrimiento", "T1018", "Remote System Discovery")],
    test: /\bnltest\b|\bdsquery\b|\bsharphound\b|\bbloodhound\b|get-netdomain|\badfind\b/,
    explanation: "",
    impact: "",
    investigation: [],
    containment: [],
    remediation: [],
  },
  {
    id: "discovery-system",
    group: "discovery",
    title: "Inventario del sistema",
    category: "COMMAND_EXECUTION",
    severity: "MEDIUM",
    phase: "Descubrimiento",
    mitre: [T("Descubrimiento", "T1082", "System Information Discovery")],
    test: /\bsysteminfo\b|ipconfig\s+\/all|\btasklist\b|\bquser\b|\bqwinsta\b|get-computerinfo/,
    explanation: "",
    impact: "",
    investigation: [],
    containment: [],
    remediation: [],
  },

  // --- Movimiento lateral -------------------------------------------------
  {
    id: "remote-exec-tool",
    title: "Ejecucion remota sobre otro sistema",
    category: "LATERAL_MOVEMENT",
    severity: "CRITICAL",
    phase: "Movimiento lateral",
    mitre: [
      T("Movimiento lateral", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
      T("Ejecucion", "T1047", "Windows Management Instrumentation"),
      T("Movimiento lateral", "T1021.006", "Remote Services: WinRM"),
    ],
    test: /\bpsexec\b|\bpaexec\b|wmic[^|]*\/node:|invoke-command[^|]*-computername|enter-pssession|\bwinrs\b|sc(?:\.exe)?\s+\\\\|schtasks[^|]*\/s\s+\\\\|\bimpacket\b|\bsmbexec\b|\bwmiexec\b/,
    explanation:
      "Se han empleado utilidades de ejecucion remota para lanzar codigo en un sistema distinto al de origen. " +
      "Es la mecanica central del movimiento lateral: el atacante reutiliza credenciales validas para expandirse " +
      "sin necesidad de explotar vulnerabilidades.",
    impact:
      "Expansion del compromiso a sistemas adicionales, incluidos potencialmente servidores de ficheros y controladores de dominio.",
    investigation: [
      "Reconstruir el grafo origen -> destino de cada ejecucion remota citada.",
      "Verificar en cada destino que procesos se crearon tras la conexion.",
    ],
    containment: [
      "Segmentar la red bloqueando SMB (445) y WinRM (5985/5986) entre estaciones de usuario.",
      "Deshabilitar las cuentas utilizadas para el salto.",
    ],
    remediation: [
      "Implantar LAPS para que las contrasenas de administrador local sean unicas por equipo.",
      "Prohibir el inicio de sesion de cuentas privilegiadas de dominio en equipos de usuario.",
    ],
  },
  {
    id: "admin-share-access",
    title: "Acceso a recursos compartidos administrativos",
    category: "LATERAL_MOVEMENT",
    severity: "HIGH",
    phase: "Movimiento lateral",
    mitre: [T("Movimiento lateral", "T1021.002", "Remote Services: SMB/Windows Admin Shares")],
    test: /\\\\[\w.$-]+\\(?:admin\$|c\$|ipc\$|d\$)/,
    explanation:
      "Se ha accedido a recursos compartidos ocultos (ADMIN$, C$, IPC$) que solo existen para administracion remota. " +
      "Su uso fuera de una ventana de mantenimiento documentada es un indicador fiable de movimiento lateral.",
    impact: "Lectura y escritura arbitraria en el sistema de ficheros del equipo remoto.",
    investigation: ["Confirmar con el area de sistemas si existia una tarea de mantenimiento planificada."],
    containment: ["Restringir el acceso a recursos administrativos a una red de gestion dedicada."],
    remediation: ["Aplicar segmentacion y autenticacion reforzada para administracion remota."],
  },

  // --- Impacto, persistencia, evasion y exfiltracion ----------------------
  {
    id: "shadow-copy-deletion",
    title: "Eliminacion de instantaneas de volumen (Shadow Copies)",
    category: "ANOMALY",
    severity: "CRITICAL",
    phase: "Impacto",
    mitre: [T("Impacto", "T1490", "Inhibit System Recovery")],
    test: /vssadmin[^|]*delete\s+shadows|wmic[^|]*shadowcopy\s+delete|win32_shadowcopy[^|]*delete|wbadmin[^|]*delete\s+(?:catalog|systemstatebackup|backup)|bcdedit[^|]*recoveryenabled\s+no|bcdedit[^|]*ignoreallfailures|delete\s+shadows\s+\/all/,
    explanation:
      "La eliminacion masiva de instantaneas de volumen destruye el mecanismo nativo de Windows para restaurar " +
      "ficheros a un estado anterior. No existe ningun escenario operativo legitimo que requiera borrar todas las " +
      "instantaneas de forma silenciosa. En la practica totalidad de los casos documentados este comando se ejecuta " +
      "inmediatamente antes del cifrado de ransomware, precisamente para impedir la recuperacion sin pagar el rescate.",
    impact:
      "Perdida de la capacidad de recuperacion local. Si se materializa el cifrado, la restauracion dependera " +
      "exclusivamente de las copias de seguridad externas y el RTO se dispara de horas a dias.",
    investigation: [
      "Verificar el estado actual de las instantaneas y de las copias de seguridad offline en los hosts afectados.",
      "Buscar en los minutos siguientes procesos de cifrado, extensiones anomalas o notas de rescate.",
      "Determinar que cuenta ejecuto el comando y como obtuvo privilegios administrativos.",
    ],
    containment: [
      "ACTIVAR EL PROTOCOLO DE RANSOMWARE: aislar inmediatamente los hosts implicados de la red.",
      "Poner las copias de seguridad en modo solo lectura y verificar que no son alcanzables desde la red comprometida.",
    ],
    remediation: [
      "Implantar copias inmutables con regla 3-2-1-1-0 y verificacion periodica de restauracion.",
      "Bloquear vssadmin, wbadmin y bcdedit mediante reglas de reduccion de superficie de ataque (ASR) del EDR.",
    ],
  },
  {
    id: "archive-staging",
    title: "Compresion de datos para preparar la exfiltracion",
    category: "ANOMALY",
    severity: "HIGH",
    phase: "Recoleccion",
    mitre: [T("Recoleccion", "T1560.001", "Archive Collected Data: Archive via Utility")],
    test: /\b(?:7z|7za|7zr|7zip)(?:\.exe)?\s+a\b|\brar(?:\.exe)?\s+a\b|\btar(?:\.exe)?\s+[-]?[a-z]*c[a-z]*\b|compress-archive|\bmakecab\b|\bzip\s+-r\b|winrar[^|]*\ba\b/,
    explanation:
      "Se han creado archivos comprimidos mediante utilidades de linea de comandos. En la fase de recoleccion de una " +
      "intrusion, el atacante agrupa la informacion seleccionada en un unico contenedor para reducir el numero de " +
      "conexiones de salida y dificultar la inspeccion del trafico por parte del DLP.",
    impact:
      "Consolidacion de informacion sensible en un paquete listo para salir de la organizacion. Es el paso previo " +
      "inmediato a la exfiltracion.",
    investigation: [
      "Localizar los archivos generados, calcular su hash y determinar exactamente que ficheros contienen.",
      "Correlacionar el momento de creacion con el trafico de salida posterior.",
    ],
    containment: ["Preservar y retirar los contenedores creados antes de que se transfieran."],
    remediation: ["Desplegar DLP con inspeccion de contenido y alertas sobre creacion de archivos de gran tamano."],
  },
  {
    id: "persistence-scheduled-task",
    title: "Persistencia mediante tarea programada",
    category: "ANOMALY",
    severity: "CRITICAL",
    phase: "Persistencia",
    mitre: [T("Persistencia", "T1053.005", "Scheduled Task/Job: Scheduled Task")],
    eventIds: ["4698", "4699", "4702", "106"],
    test: /schtasks[^|]*\/create|register-scheduledtask|new-scheduledtask|\bat\s+\d{1,2}:\d{2}\s/,
    explanation:
      "Se ha registrado una tarea programada nueva. Las tareas programadas sobreviven a reinicios y a cierres de " +
      "sesion, por lo que son uno de los mecanismos de persistencia mas utilizados. El uso de nombres que imitan " +
      "componentes legitimos de Windows es una tecnica deliberada de camuflaje.",
    impact:
      "El atacante recupera el acceso automaticamente aunque se reinicie el equipo o se cierre su sesion. " +
      "Una remediacion que no elimine la tarea deja la puerta abierta.",
    investigation: [
      "Exportar el XML de cada tarea citada y analizar la accion configurada y el usuario bajo el que se ejecuta.",
      "Buscar la misma tarea en el resto de la flota para medir el alcance.",
    ],
    containment: ["Deshabilitar (no borrar aun) la tarea para preservar la evidencia, y bloquear su binario."],
    remediation: ["Auditar la creacion de tareas (EventID 4698) y alertar sobre tareas creadas fuera del inventario aprobado."],
  },
  {
    id: "persistence-service",
    title: "Persistencia mediante instalacion de servicio",
    category: "ANOMALY",
    severity: "CRITICAL",
    phase: "Persistencia",
    mitre: [T("Persistencia", "T1543.003", "Create or Modify System Process: Windows Service")],
    eventIds: ["7045", "4697"],
    test: /sc(?:\.exe)?\s+(?:\\\\[^\s]+\s+)?create\b|new-service|service\s+(?:was\s+)?(?:installed|instalado|creado)/,
    explanation:
      "Se ha instalado un servicio de Windows nuevo. Un servicio arranca con el sistema y normalmente con privilegios " +
      "SYSTEM, lo que proporciona al atacante persistencia y maximos privilegios de forma simultanea. Los nombres que " +
      "evocan componentes de actualizacion o de soporte del sistema son una senal de suplantacion intencionada.",
    impact:
      "Persistencia a nivel SYSTEM que sobrevive a reinicios y que a menudo pasa desapercibida en revisiones manuales.",
    investigation: [
      "Identificar la ruta del binario del servicio, calcular su hash y analizarlo en un entorno aislado.",
      "Comprobar si el binario esta firmado y donde reside (rutas fuera de %SystemRoot% son muy sospechosas).",
      "Buscar el mismo nombre de servicio en el resto de sistemas.",
    ],
    containment: ["Detener y deshabilitar el servicio, conservando el binario para analisis forense."],
    remediation: ["Alertar sobre EventID 7045 en el SIEM y aplicar lista blanca de servicios autorizados."],
  },
  {
    id: "persistence-autorun",
    title: "Persistencia mediante claves de arranque automatico",
    category: "ANOMALY",
    severity: "HIGH",
    phase: "Persistencia",
    mitre: [T("Persistencia", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys")],
    test: /currentversion\\run|\\runonce\\|reg(?:\.exe)?\s+add[^|]*\\run|new-itemproperty[^|]*\\run|\\start menu\\programs\\startup/,
    explanation:
      "Se ha modificado una clave Run/RunOnce o la carpeta de inicio para ejecutar un binario al iniciar sesion. " +
      "Es un mecanismo de persistencia sencillo pero eficaz, que no requiere privilegios administrativos en su variante HKCU.",
    impact: "Reejecucion del codigo del atacante en cada inicio de sesion del usuario afectado.",
    investigation: ["Enumerar todas las entradas de arranque del host y contrastarlas con una linea base limpia."],
    containment: ["Eliminar la entrada tras documentarla y poner en cuarentena el binario referenciado."],
    remediation: ["Monitorizar cambios en claves de arranque con el EDR."],
  },
  {
    id: "persistence-wmi",
    title: "Persistencia mediante suscripcion de eventos WMI",
    category: "ANOMALY",
    severity: "HIGH",
    phase: "Persistencia",
    mitre: [T("Persistencia", "T1546.003", "Event Triggered Execution: WMI Event Subscription")],
    test: /root\\subscription|__eventfilter|commandlineeventconsumer|__filtertoconsumerbinding/,
    explanation:
      "Las suscripciones de eventos WMI permiten ejecutar codigo cuando se cumple una condicion del sistema. " +
      "Residen en el repositorio WMI y no en el sistema de ficheros, por lo que son especialmente dificiles de detectar.",
    impact: "Persistencia sigilosa que sobrevive a limpiezas convencionales del sistema de ficheros.",
    investigation: ["Enumerar filtros, consumidores y bindings WMI en el host afectado."],
    containment: ["Eliminar el binding tras exportarlo como evidencia."],
    remediation: ["Auditar periodicamente el repositorio WMI en servidores criticos."],
  },
  {
    id: "webshell-execution",
    title: "Ejecucion de comandos desde el servidor web (Web Shell)",
    category: "ANOMALY",
    severity: "CRITICAL",
    phase: "Persistencia",
    mitre: [
      T("Persistencia", "T1505.003", "Server Software Component: Web Shell"),
      T("Ejecucion", "T1059.003", "Command and Scripting Interpreter: Windows Command Shell"),
    ],
    predicate: (e, text) => {
      const identity = `${e.user} ${e.parentProcess}`.toLowerCase();
      const webContext =
        /iis\s*apppool|defaultapppool|\biusr\b|www-data|\bapache\b|w3wp\.exe|httpd|tomcat|php-cgi|nginx/.test(identity) ||
        /w3wp\.exe|httpd|tomcat|php-cgi/.test(text);
      if (!webContext) return false;
      const spawnsShell = /cmd\.exe|powershell|\bpwsh\b|\/bin\/(?:ba)?sh|\bwscript\b|\bcscript\b/.test(
        `${e.process} ${e.commandLine} ${text}`.toLowerCase(),
      );
      return spawnsShell;
    },
    explanation:
      "El proceso del servidor web (o su identidad de grupo de aplicaciones) esta lanzando un interprete de comandos. " +
      "Un servidor web legitimo sirve contenido; no genera shells. Este patron es la firma inequivoca de una web shell: " +
      "un fichero subido a la aplicacion que permite al atacante ejecutar comandos a traves de peticiones HTTP, sin " +
      "necesidad de credenciales y atravesando el firewall perimetral por un puerto permitido.",
    impact:
      "Canal de acceso remoto persistente y no autenticado sobre un sistema expuesto a Internet. Permite al atacante " +
      "reentrar en la red aunque se restablezcan todas las credenciales, y suele ser el punto de partida de una nueva " +
      "campana si no se erradica.",
    investigation: [
      "Localizar el fichero de web shell en el directorio de la aplicacion comparando con el ultimo despliegue limpio.",
      "Revisar los logs de IIS/Apache para identificar la IP del atacante y todas las peticiones a la web shell.",
      "Determinar el vector de subida original (vulnerabilidad de carga de ficheros, credencial comprometida, deserializacion).",
    ],
    containment: [
      "Retirar el servidor web de balanceo y aislarlo preservando disco y memoria.",
      "Eliminar la web shell tras preservar una copia forense y revocar los tokens de sesion de la aplicacion.",
    ],
    remediation: [
      "Restaurar la aplicacion desde un artefacto de despliegue verificado, nunca limpiando el servidor comprometido en caliente.",
      "Desplegar un WAF y monitorizar la integridad del directorio web (FIM).",
      "Ejecutar el grupo de aplicaciones con la minima identidad posible y sin permisos de escritura en su propio directorio.",
    ],
  },
  {
    id: "log-clearing",
    title: "Borrado de registros de auditoria",
    category: "ANOMALY",
    severity: "CRITICAL",
    phase: "Evasion de defensas",
    mitre: [T("Evasion de defensas", "T1070.001", "Indicator Removal: Clear Windows Event Logs")],
    eventIds: ["1102", "104"],
    test: /wevtutil(?:\.exe)?\s+cl\b|clear-eventlog|audit\s+log\s+was\s+cleared|registro.{0,20}borrad/,
    explanation:
      "Se ha vaciado uno o varios registros de eventos. Es una accion antiforense deliberada cuyo unico proposito es " +
      "destruir la trazabilidad de las acciones previas del atacante.",
    impact:
      "Perdida irreversible de evidencia. El alcance real de la intrusion puede ser mayor que el observable, lo que " +
      "obliga a asumir el peor escenario durante la respuesta.",
    investigation: [
      "Recuperar los eventos desde el reenvio centralizado (WEF/SIEM), que no se ve afectado por el borrado local.",
      "Acotar la ventana ciega: desde el ultimo evento conservado hasta el borrado.",
    ],
    containment: ["Aislar el host y preservar el disco para recuperacion forense de registros residuales."],
    remediation: [
      "Garantizar el reenvio de logs en tiempo real a un almacen inmutable fuera del alcance de las cuentas locales.",
      "Alertar en el SIEM sobre EventID 1102 con prioridad maxima.",
    ],
  },
  {
    id: "defense-evasion-tooling",
    title: "Desactivacion de controles de seguridad",
    category: "ANOMALY",
    severity: "HIGH",
    phase: "Evasion de defensas",
    mitre: [T("Evasion de defensas", "T1562.001", "Impair Defenses: Disable or Modify Tools")],
    test: /set-mppreference[^|]*disable|add-mppreference[^|]*exclusionpath|netsh\s+advfirewall\s+set[^|]*state\s+off|netsh\s+firewall\s+set\s+opmode\s+disable|sc(?:\.exe)?\s+(?:stop|delete)\s+(?:windefend|sense|wscsvc|mpssvc)|taskkill[^|]*(?:msmpeng|sense|mbam)|uninstall-windowsfeature[^|]*defender/,
    explanation:
      "Se han ejecutado comandos que desactivan el antivirus, el firewall o anaden exclusiones. Preparar el terreno " +
      "desactivando defensas precede habitualmente al despliegue de la carga util principal.",
    impact: "El endpoint queda sin proteccion en tiempo real durante la fase mas destructiva del ataque.",
    investigation: ["Verificar el estado actual de Defender/EDR y las exclusiones configuradas en los hosts citados."],
    containment: ["Reactivar las protecciones y forzar un analisis completo."],
    remediation: ["Activar la proteccion contra manipulaciones (Tamper Protection) y gestionar las exclusiones solo por politica central."],
  },
  {
    id: "ransomware-artifacts",
    title: "Artefactos compatibles con cifrado de ransomware",
    category: "ANOMALY",
    severity: "CRITICAL",
    phase: "Impacto",
    mitre: [T("Impacto", "T1486", "Data Encrypted for Impact")],
    test: /\.(?:locked|encrypted|crypted|lockbit|conti|ryuk|basta)\b|readme[_-]?(?:restore|decrypt)|how[_-]?to[_-]?decrypt|restore[_-]?(?:my[_-]?)?files|decrypt[_-]?instruction|_recover_/,
    explanation:
      "Aparecen extensiones de fichero o notas de rescate asociadas a familias de ransomware. Indica que la fase de " +
      "impacto ya se ha iniciado, al menos parcialmente.",
    impact: "Indisponibilidad de los datos afectados y activacion inmediata del plan de continuidad de negocio.",
    investigation: ["Delimitar el alcance exacto del cifrado por host y por recurso compartido."],
    containment: ["Desconectar los recursos compartidos afectados y detener el proceso de cifrado."],
    remediation: ["Restaurar desde copias verificadas y realizar un analisis de causa raiz completo antes de reconectar."],
  },
  {
    id: "remote-access-tooling",
    title: "Herramienta de acceso remoto o tunelizacion no corporativa",
    category: "ANOMALY",
    severity: "HIGH",
    phase: "Mando y control",
    mitre: [T("Mando y control", "T1219", "Remote Access Software")],
    test: /\banydesk\b|\bteamviewer\b|\bngrok\b|\bchisel\b|\bfrpc?\.exe\b|\bplink\.exe\b|\bradmin\b|\bscreenconnect\b/,
    explanation:
      "Se detecta software de acceso remoto o de tunelizacion que no forma parte del catalogo corporativo. " +
      "Los atacantes lo emplean como canal de mando y control de respaldo porque su trafico se confunde con el legitimo.",
    impact: "Canal de control alternativo que sobrevive al bloqueo de la infraestructura de C2 principal.",
    investigation: ["Confirmar con el area de TI si la herramienta esta autorizada para ese host y usuario."],
    containment: ["Bloquear los dominios y puertos de la herramienta en el perimetro."],
    remediation: ["Mantener una lista blanca de software de acceso remoto y bloquear el resto por politica."],
  },
];

// ---------------------------------------------------------------------------
// Constructor de hallazgos
// ---------------------------------------------------------------------------

interface Seed {
  rule: string;
  category: DetectionCategory;
  title: string;
  severity: Severity;
  confidence: Confidence;
  phase: KillChainPhase;
  summary: string;
  technicalExplanation: string;
  justification: string;
  impact: string;
  mitre: MitreRef[];
  matches: Match[];
  investigation: string[];
  containment: string[];
  remediation: string[];
}

function buildFinding(seed: Seed, sequence: number, flagged: Set<number>): Finding {
  const events = seed.matches.map((m) => m.event);
  for (const e of events) flagged.add(e.rowIndex);

  const sorted = [...seed.matches].sort((a, b) => byTime(a.event, b.event));
  const { first, last } = spanOf(events);
  const volumeBonus = Math.min(10, Math.round(Math.log2(seed.matches.length + 1) * 2.5));

  return {
    id: `F-${String(sequence).padStart(3, "0")}`,
    rule: seed.rule,
    category: seed.category,
    title: seed.title,
    severity: seed.severity,
    riskScore: Math.min(100, BASE_SCORE[seed.severity] + volumeBonus),
    confidence: seed.confidence,
    killChainPhase: seed.phase,
    summary: seed.summary,
    technicalExplanation: seed.technicalExplanation,
    justification: seed.justification,
    impact: seed.impact,
    mitre: seed.mitre,
    evidence: sorted.slice(0, MAX_EVIDENCE).map(toEvidence),
    evidenceCount: seed.matches.length,
    entities: {
      hosts: uniq(events.map((e) => e.host)).slice(0, 25),
      users: uniq(events.map((e) => e.user)).slice(0, 25),
      ips: uniq(events.flatMap((e) => [e.sourceIp, e.destIp])).slice(0, 25),
    },
    firstSeen: first,
    lastSeen: last,
    investigation: seed.investigation,
    containment: seed.containment,
    remediation: seed.remediation,
  };
}

// ---------------------------------------------------------------------------
// Reglas
// ---------------------------------------------------------------------------

interface Ctx {
  events: LogEvent[];
  texts: string[];
  /** Cuentas con indicios de compromiso; alimenta la severidad de otras reglas. */
  compromisedUsers: Set<string>;
}

/** 1. Fuerza bruta y password spraying. */
function ruleBruteForce(ctx: Ctx): Seed[] {
  const failures = ctx.events.filter((e, i) => isFailedLogon(e, ctx.texts[i]));
  if (failures.length === 0) return [];

  const successes = ctx.events.filter((e, i) => isSuccessfulLogon(e, ctx.texts[i]));
  const seeds: Seed[] = [];

  // Agrupamos por origen: la IP si la hay, si no el host atacado.
  const groups = groupBy(failures, (e) => e.sourceIp || e.host || "origen-desconocido");

  for (const [origin, events] of groups) {
    if (events.length < 8) continue;

    const sorted = [...events].sort(byTime);
    const users = uniq(events.map((e) => e.user).filter((u) => !isMachineAccount(u)));
    const targets = uniq(events.map((e) => e.host));
    const peak = peakInWindow(sorted, 15 * 60 * 1000);
    const { first, last } = spanOf(sorted);
    const external = isPublicIp(origin);

    const spraying = users.length >= 5;
    let severity: Severity = spraying ? "CRITICAL" : events.length >= 15 ? "HIGH" : "MEDIUM";

    const matches: Match[] = sorted.map((e) => ({
      event: e,
      detail: `Autenticacion fallida para "${e.user || "(sin usuario)"}" en ${e.host || "(host no indicado)"}`,
    }));

    // ¿Alguno de esos intentos acabo en acceso concedido?
    const firstFailure = sorted[0]?.epoch ?? null;
    const sprayedUsers = new Set(users.map(normalizeUser));
    const compromises = successes.filter((s) => {
      const afterAttack = firstFailure === null || s.epoch === null || s.epoch >= firstFailure;
      if (!afterAttack) return false;
      return s.sourceIp === origin || sprayedUsers.has(normalizeUser(s.user));
    });

    let successNote = "";
    if (compromises.length > 0) {
      severity = "CRITICAL";
      for (const c of compromises) ctx.compromisedUsers.add(normalizeUser(c.user));
      successNote =
        ` El ataque tuvo exito: se registran ${compromises.length} inicio(s) de sesion correcto(s) posteriores ` +
        `para ${uniq(compromises.map((c) => c.user)).join(", ") || "cuentas del dominio"}, lo que confirma el ` +
        `compromiso efectivo de credenciales y eleva el hallazgo a severidad critica.`;
      for (const c of compromises.slice(0, 6)) {
        matches.push({
          event: c,
          detail: `ACCESO CONCEDIDO tras la rafaga: "${c.user}" en ${c.host || "(host no indicado)"}`,
        });
      }
    }

    const title = spraying
      ? `Password spraying desde ${origin}`
      : `Ataque de fuerza bruta desde ${origin}`;

    const technique = spraying
      ? "El atacante prueba una o pocas contrasenas contra un gran numero de cuentas distintas. Al repartir los " +
        "intentos entre muchos usuarios evita disparar las politicas de bloqueo por cuenta, que cuentan fallos " +
        "individuales y no agregados por origen."
      : "El atacante concentra multiples intentos de autenticacion contra un conjunto reducido de cuentas, " +
        "buscando acertar la contrasena por repeticion.";

    seeds.push({
      rule: spraying ? "brute-force.password-spraying" : "brute-force.repeated-failures",
      category: "BRUTE_FORCE",
      title,
      severity,
      confidence: events.length >= 15 || spraying ? "ALTA" : "MEDIA",
      phase: "Acceso inicial",
      summary:
        `${events.length} autenticaciones fallidas desde ${origin} contra ${users.length} cuenta(s) ` +
        `distinta(s) en ${targets.join(", ") || "sistemas no identificados"}.`,
      technicalExplanation:
        `${technique} En este dataset se contabilizan ${events.length} eventos de autenticacion fallida procedentes ` +
        `de ${origin}${external ? " (direccion publica, externa a la red corporativa)" : " (direccion interna)"}, ` +
        `dirigidos a ${users.length} cuenta(s) sobre ${targets.length} sistema(s): ${targets.join(", ") || "n/d"}. ` +
        `El pico de intensidad alcanza ${peak} intentos en una ventana de 15 minutos, un ritmo incompatible con el ` +
        `error humano.${successNote}`,
      justification:
        severity === "CRITICAL" && compromises.length > 0
          ? `Se clasifica como CRITICO porque el ataque no solo se produjo sino que culmino en accesos validos: ` +
            `hay ${compromises.length} inicio(s) de sesion correcto(s) correlacionados. El atacante dispone de ` +
            `credenciales funcionales del dominio.`
          : severity === "CRITICAL"
            ? `Se clasifica como CRITICO por tratarse de password spraying confirmado contra ${users.length} cuentas ` +
              `desde un unico origen, patron asociado a acceso inicial de actores organizados.`
            : severity === "HIGH"
              ? `Se clasifica como ALTO por el volumen (${events.length} intentos) y la concentracion temporal ` +
                `(${peak} en 15 minutos), muy por encima de un olvido de contrasena legitimo.`
              : `Se clasifica como MEDIO: el volumen (${events.length} intentos) es anomalo pero aun compatible con ` +
                `un problema de credenciales cacheadas o una cuenta de servicio mal configurada. Requiere verificacion.`,
      impact:
        `Un acceso inicial exitoso por esta via entrega al atacante una identidad valida del dominio, con la que ` +
        `puede moverse por la red sin explotar ninguna vulnerabilidad y confundiendose con la actividad legitima. ` +
        `El origen ${origin} debe considerarse hostil${external ? " y bloquearse en el perimetro" : ""}.`,
      mitre: [
        T("Acceso inicial", "T1110.003", "Brute Force: Password Spraying"),
        T("Acceso inicial", "T1078", "Valid Accounts"),
      ],
      matches,
      investigation: [
        `Determinar el alcance completo: listar todas las cuentas objetivo desde ${origin} y su estado actual.`,
        "Verificar si alguna de las cuentas atacadas tiene privilegios administrativos o acceso a datos regulados.",
        "Revisar si existe MFA habilitada en el servicio expuesto y si se eludio.",
        first && last ? `Acotar la ventana del ataque: de ${first} a ${last}.` : "Reconstruir la cronologia del ataque.",
      ],
      containment: [
        `Bloquear ${origin} en el firewall perimetral y en el proveedor de identidad.`,
        compromises.length > 0
          ? `Deshabilitar y restablecer la contrasena de las cuentas comprometidas (${uniq(compromises.map((c) => c.user)).slice(0, 5).join(", ")}) y revocar sus sesiones y tokens activos.`
          : "Forzar el cambio de contrasena de las cuentas objetivo como medida preventiva.",
        "Activar bloqueo temporal de cuenta y retardo progresivo en el servicio de autenticacion expuesto.",
      ],
      remediation: [
        "Implantar MFA obligatoria en todos los accesos de autenticacion expuestos a Internet.",
        "Desplegar politicas de contrasena robustas con listas de contrasenas prohibidas.",
        "Configurar en el SIEM una alerta por umbral de fallos agregados por IP de origen, no solo por cuenta.",
        "Restringir geograficamente o por lista blanca el acceso a los servicios de autenticacion expuestos.",
      ],
    });
  }

  return seeds;
}

/** 2. Inicios de sesion sospechosos por origen o por horario. */
function ruleSuspiciousLogon(ctx: Ctx): Seed[] {
  const seeds: Seed[] = [];
  const successes = ctx.events.filter((e, i) => isSuccessfulLogon(e, ctx.texts[i]));
  if (successes.length === 0) return seeds;

  // (a) Acceso correcto desde una direccion publica.
  const external = successes.filter((e) => isPublicIp(e.sourceIp));
  const extGroups = groupBy(external, (e) => `${e.sourceIp}|${e.host}|${e.logonType}`);

  for (const [, events] of extGroups) {
    const sample = events[0];
    const ip = sample.sourceIp;
    const host = sample.host || "(host no indicado)";
    const type = sample.logonType.trim();
    const typeText = `${eventText(sample)}`;
    const isRdp = type === "10" || /rdp|remoteinteractive|terminal\s*services|3389/.test(typeText);
    const isNetwork = type === "3";
    const severity: Severity = isRdp ? "CRITICAL" : "HIGH";
    const users = uniq(events.map((e) => e.user));

    for (const u of users) ctx.compromisedUsers.add(normalizeUser(u));

    seeds.push({
      rule: isRdp ? "suspicious-logon.external-rdp" : "suspicious-logon.external-source",
      category: "SUSPICIOUS_LOGON",
      title: isRdp
        ? `Acceso RDP exitoso desde IP externa ${ip} a ${host}`
        : `Inicio de sesion exitoso desde IP externa ${ip} a ${host}`,
      severity,
      confidence: "ALTA",
      phase: "Acceso inicial",
      summary:
        `${events.length} inicio(s) de sesion correcto(s) en ${host} como ${users.join(", ") || "n/d"} ` +
        `desde la direccion publica ${ip} (${logonTypeLabel(type)}).`,
      technicalExplanation:
        `Se ha autenticado correctamente la cuenta ${users.join(", ") || "n/d"} en ${host} desde ${ip}, una ` +
        `direccion IP fuera de los rangos privados RFC1918 y por tanto externa a la red corporativa. El tipo de ` +
        `inicio de sesion es ${logonTypeLabel(type)}. ` +
        (isRdp
          ? "Un acceso RemoteInteractive (RDP) directo desde Internet implica que el puerto 3389 esta expuesto o " +
            "que existe un salto no controlado: es una de las vias de entrada mas explotadas en incidentes de " +
            "ransomware. A diferencia de un intento fallido, aqui la autenticacion fue aceptada, por lo que el " +
            "atacante obtuvo una sesion interactiva completa sobre el servidor, con escritorio y capacidad de " +
            "ejecutar cualquier herramienta."
          : isNetwork
            ? "Un inicio de tipo Red desde una direccion publica indica acceso a recursos compartidos o servicios " +
              "SMB desde fuera del perimetro, algo que no deberia ser posible en una arquitectura segmentada."
            : "Un acceso correcto desde fuera del perimetro requiere validar si existe una VPN o un salto " +
              "legitimo que justifique el origen.") +
        ` No se observa ninguna aprobacion previa en los registros aportados, por lo que debe tratarse como acceso ` +
        `no autorizado hasta que el cliente lo descarte expresamente.`,
      justification:
        isRdp
          ? "CRITICO: sesion interactiva remota concedida a un origen externo sobre un servidor corporativo. " +
            "Combina acceso confirmado (no intento), control total del escritorio y un vector asociado " +
            "historicamente al despliegue de ransomware."
          : "ALTO: autenticacion aceptada desde fuera del perimetro. El acceso es real, pero el nivel de control " +
            "obtenido es menor que en una sesion interactiva completa.",
      impact:
        `El atacante dispone de una cabeza de puente operativa en ${host}. Desde ahi puede enumerar la red interna, ` +
        `recolectar credenciales y desplazarse lateralmente. Si ${host} participa en procesos de negocio, existe ` +
        `riesgo directo de manipulacion o robo de la informacion que gestiona.`,
      mitre: [
        T("Acceso inicial", "T1078", "Valid Accounts"),
        ...(isRdp ? [T("Acceso inicial", "T1133", "External Remote Services")] : []),
        ...(isRdp ? [T("Movimiento lateral", "T1021.001", "Remote Services: Remote Desktop Protocol")] : []),
      ],
      matches: events.map((e) => ({
        event: e,
        detail: `Inicio de sesion ${logonTypeLabel(e.logonType)} correcto para "${e.user}" desde ${e.sourceIp}`,
      })),
      investigation: [
        `Determinar si ${ip} corresponde a una VPN corporativa, un proveedor autorizado o es completamente desconocido.`,
        `Reconstruir todo lo ejecutado en ${host} durante la sesion iniciada desde ${ip}.`,
        `Comprobar si la cuenta ${users.join(", ")} aparece tambien en intentos de fuerza bruta previos.`,
        "Verificar si el servicio expuesto requeria MFA y si se completo el segundo factor.",
      ],
      containment: [
        `Cerrar las sesiones activas de ${users.join(", ")} en ${host} y bloquear ${ip} en el perimetro.`,
        `Retirar ${host} de la exposicion directa a Internet.`,
        "Restablecer las credenciales de las cuentas implicadas y revocar tickets Kerberos.",
      ],
      remediation: [
        "Eliminar toda exposicion directa de RDP a Internet; publicarlo unicamente tras VPN con MFA o mediante un gateway RDS endurecido.",
        "Aplicar restricciones de origen (geo-bloqueo y lista blanca) en los accesos remotos.",
        "Habilitar Network Level Authentication y registrar todas las sesiones remotas.",
      ],
    });
  }

  // (b) Accesos fuera del horario laboral.
  const offHours = successes.filter((e) => {
    if (e.epoch === null || isMachineAccount(e.user)) return false;
    const hour = new Date(e.epoch).getUTCHours();
    return hour < 6 || hour >= 22;
  });

  if (offHours.length >= 3) {
    const users = uniq(offHours.map((e) => e.user));
    const hosts = uniq(offHours.map((e) => e.host));
    seeds.push({
      rule: "suspicious-logon.off-hours",
      category: "SUSPICIOUS_LOGON",
      title: "Inicios de sesion fuera del horario laboral",
      severity: "MEDIUM",
      confidence: "MEDIA",
      phase: "Acceso inicial",
      summary: `${offHours.length} inicios de sesion correctos entre las 22:00 y las 06:00 (UTC) sobre ${hosts.length} sistema(s).`,
      technicalExplanation:
        `Se registran ${offHours.length} autenticaciones correctas en franja nocturna (22:00-06:00 UTC) para las ` +
        `cuentas ${users.slice(0, 8).join(", ")}${users.length > 8 ? " y otras" : ""} sobre ${hosts.join(", ")}. ` +
        `La actividad fuera de horario es un indicador clasico de uso no autorizado de credenciales: el atacante ` +
        `opera cuando la vigilancia es menor y cuando el titular legitimo no detectara la sesion concurrente. ` +
        `Por si sola no es concluyente (guardias, turnos o husos horarios distintos la explican), pero gana peso ` +
        `al correlacionarse con el resto de hallazgos de este informe.`,
      justification:
        "MEDIO: el patron horario es anomalo y respalda la hipotesis de uso no autorizado, pero admite explicaciones " +
        "operativas legitimas. No se eleva la criticidad sin confirmacion del cliente sobre turnos y guardias.",
      impact:
        "Si las sesiones no corresponden a los titulares, el atacante opera con identidad valida en una franja de " +
        "baja supervision, lo que retrasa la deteccion y amplia su margen de maniobra.",
      mitre: [T("Acceso inicial", "T1078", "Valid Accounts")],
      matches: offHours.map((e) => ({
        event: e,
        detail: `Inicio de sesion de "${e.user}" en ${e.host} a las ${e.timestamp?.slice(11, 19) ?? e.rawTimestamp} UTC`,
      })),
      investigation: [
        "Contrastar con RR.HH. y con el area de TI los turnos, guardias y husos horarios de las cuentas implicadas.",
        "Comparar la IP de origen de estas sesiones con la de la actividad diurna habitual del mismo usuario.",
      ],
      containment: ["Contactar con los titulares para confirmar o descartar cada sesion nocturna."],
      remediation: [
        "Definir en el SIEM una linea base de horario por usuario y alertar sobre desviaciones.",
        "Aplicar politicas de acceso condicional basadas en hora y ubicacion.",
      ],
    });
  }

  return seeds;
}

/** 3. Escalada de privilegios. */
function rulePrivilegeEscalation(ctx: Ctx): Seed[] {
  const seeds: Seed[] = [];

  // (a) Asignacion de privilegios especiales (4672).
  const special = ctx.events.filter(
    (e, i) =>
      (e.eventId === "4672" || /special privileges|privilegios especiales/.test(ctx.texts[i])) &&
      !isMachineAccount(e.user),
  );

  if (special.length > 0) {
    const users = uniq(special.map((e) => e.user));
    const hosts = uniq(special.map((e) => e.host));
    const tainted = users.filter((u) => ctx.compromisedUsers.has(normalizeUser(u)));
    const severity: Severity = tainted.length > 0 ? "CRITICAL" : "HIGH";

    seeds.push({
      rule: "privilege-escalation.special-privileges",
      category: "PRIVILEGE_ESCALATION",
      title: "Asignacion de privilegios especiales a cuentas de usuario",
      severity,
      confidence: "ALTA",
      phase: "Escalada de privilegios",
      summary:
        `${special.length} evento(s) de asignacion de privilegios especiales para ${users.join(", ")} ` +
        `en ${hosts.join(", ") || "n/d"}.`,
      technicalExplanation:
        `El evento 4672 se genera cuando una sesion recien iniciada recibe privilegios sensibles (SeDebugPrivilege, ` +
        `SeTakeOwnershipPrivilege, SeBackupPrivilege, SeTcbPrivilege u otros equivalentes a control administrativo). ` +
        `Estos privilegios permiten leer la memoria de otros procesos, apropiarse de ficheros ajenos y eludir las ` +
        `ACL del sistema. En este dataset lo reciben ${users.join(", ")} sobre ${hosts.join(", ") || "n/d"}.` +
        (tainted.length > 0
          ? ` Es determinante que ${tainted.join(", ")} figure tambien entre las cuentas con indicios de compromiso ` +
            `previo en este mismo informe: la secuencia acceso no autorizado -> elevacion de privilegios es la ` +
            `progresion esperada de una intrusion, no una coincidencia administrativa.`
          : ` Debe contrastarse con el inventario de cuentas administrativas aprobadas: si alguna de estas cuentas ` +
            `no deberia ostentar esos privilegios, estamos ante una escalada efectiva.`),
      justification:
        tainted.length > 0
          ? `CRITICO: la elevacion recae sobre cuenta(s) (${tainted.join(", ")}) con compromiso previo documentado ` +
            `en este informe. El atacante ha pasado de acceso de usuario a control administrativo.`
          : `ALTO: la asignacion de privilegios administrativos es legitima en cuentas de administracion, pero su ` +
            `aparicion dentro de una ventana con actividad maliciosa obliga a validarla una por una.`,
      impact:
        "Con privilegios administrativos el atacante puede desactivar controles de seguridad, volcar credenciales, " +
        "instalar persistencia a nivel de sistema y acceder a cualquier dato del equipo sin restriccion de ACL.",
      mitre: [
        T("Escalada de privilegios", "T1078.002", "Valid Accounts: Domain Accounts"),
        T("Escalada de privilegios", "T1134", "Access Token Manipulation"),
      ],
      matches: special.map((e) => ({
        event: e,
        detail: `Privilegios especiales asignados a "${e.user}" en ${e.host || "n/d"}`,
      })),
      investigation: [
        "Contrastar cada cuenta con el inventario autorizado de administradores y con su rol declarado.",
        "Revisar que acciones concretas se ejecutaron en la sesion elevada.",
        "Comprobar si el grupo privilegiado se modifico recientemente.",
      ],
      containment: [
        "Retirar los privilegios no justificados y revocar las sesiones elevadas.",
        "Restablecer las credenciales de las cuentas implicadas.",
      ],
      remediation: [
        "Implantar administracion Just-In-Time (JIT) con aprobacion y caducidad automatica.",
        "Revisar trimestralmente la pertenencia a grupos privilegiados.",
        "Aplicar el modelo de tiering de Active Directory.",
      ],
    });
  }

  // (b) Altas en grupos privilegiados y creacion de cuentas.
  const groupAdds = ctx.events.filter((e, i) => {
    const byId = ["4728", "4732", "4756", "4727", "4731", "4754", "4720"].includes(e.eventId);
    const byCmd =
      /net(?:\.exe)?\s+(?:localgroup|group)[^|]*\/add|add-localgroupmember|add-adgroupmember|net(?:\.exe)?\s+user[^|]*\/add/.test(
        ctx.texts[i],
      );
    return byId || byCmd;
  });

  if (groupAdds.length > 0) {
    const hosts = uniq(groupAdds.map((e) => e.host));
    seeds.push({
      rule: "privilege-escalation.group-membership",
      category: "PRIVILEGE_ESCALATION",
      title: "Alta de cuentas en grupos privilegiados",
      severity: "CRITICAL",
      confidence: "ALTA",
      phase: "Escalada de privilegios",
      summary: `${groupAdds.length} modificacion(es) de pertenencia a grupos o creacion de cuentas en ${hosts.join(", ") || "n/d"}.`,
      technicalExplanation:
        `Se han registrado cambios en la composicion de grupos privilegiados o creacion de cuentas nuevas. ` +
        `Anadir una cuenta controlada a Administradores locales o a un grupo privilegiado de dominio es la forma ` +
        `mas directa y duradera de consolidar el control: el acceso sobrevive al cambio de contrasena de la cuenta ` +
        `originalmente comprometida y se confunde con la administracion rutinaria.`,
      justification:
        "CRITICO: un cambio de pertenencia a grupo privilegiado concede control administrativo persistente. " +
        "Si no se corresponde con un ticket de cambio aprobado, constituye por si solo un compromiso confirmado del dominio.",
      impact:
        "Control administrativo persistente sobre los sistemas afectados. Si el grupo es de dominio (Domain Admins, " +
        "Enterprise Admins), el alcance es la totalidad del directorio y la recuperacion exige una reconstruccion " +
        "controlada del bosque.",
      mitre: [
        T("Persistencia", "T1098", "Account Manipulation"),
        T("Escalada de privilegios", "T1078.002", "Valid Accounts: Domain Accounts"),
      ],
      matches: groupAdds.map((e) => ({ event: e, detail: describe(e) })),
      investigation: [
        "Identificar quien realizo cada cambio y si existe un ticket de cambio aprobado que lo respalde.",
        "Enumerar la composicion actual completa de todos los grupos privilegiados y compararla con la linea base.",
      ],
      containment: [
        "Revertir las altas no autorizadas y deshabilitar las cuentas creadas.",
        "Restablecer las credenciales de las cuentas que realizaron el cambio.",
      ],
      remediation: [
        "Alertar en tiempo real sobre los eventos 4728/4732/4756 en el SIEM.",
        "Exigir aprobacion de doble control para cambios en grupos privilegiados.",
      ],
    });
  }

  return seeds;
}

/** 4 y 6. Firmas de comandos, persistencia, evasion e impacto. */
function ruleSignatures(ctx: Ctx): Seed[] {
  const seeds: Seed[] = [];
  const groupedMatches = new Map<string, { signature: Signature; matches: Match[] }[]>();

  for (const sig of SIGNATURES) {
    const matches: Match[] = [];
    for (let i = 0; i < ctx.events.length; i += 1) {
      const e = ctx.events[i];
      const text = ctx.texts[i];
      const hit =
        (sig.predicate?.(e, text) ?? false) ||
        (sig.eventIds?.includes(e.eventId) ?? false) ||
        (sig.test?.test(text) ?? false);
      if (hit) matches.push({ event: e, detail: describe(e) });
    }
    if (matches.length === 0) continue;

    if (sig.group) {
      const bucket = groupedMatches.get(sig.group) ?? [];
      bucket.push({ signature: sig, matches });
      groupedMatches.set(sig.group, bucket);
      continue;
    }

    const hosts = uniq(matches.map((m) => m.event.host));
    const users = uniq(matches.map((m) => m.event.user));

    seeds.push({
      rule: `signature.${sig.id}`,
      category: sig.category,
      title: sig.title,
      severity: sig.severity,
      confidence: matches.length >= 2 ? "ALTA" : "MEDIA",
      phase: sig.phase,
      summary:
        `${matches.length} evento(s) coincidentes en ${hosts.join(", ") || "n/d"}` +
        `${users.length ? ` bajo ${users.slice(0, 4).join(", ")}` : ""}.`,
      technicalExplanation: sig.explanation,
      justification:
        `Severidad ${sig.severity} asignada por la tecnica detectada (${sig.mitre.map((m) => m.techniqueId).join(", ")}), ` +
        `confirmada por ${matches.length} evento(s) reales del dataset en ${hosts.length} sistema(s). ` +
        (sig.severity === "CRITICAL"
          ? "La tecnica no admite explicacion operativa benigna en el contexto observado y exige respuesta inmediata."
          : sig.severity === "HIGH"
            ? "La tecnica puede tener usos administrativos puntuales, pero en este contexto y junto al resto de hallazgos la evidencia apunta a actividad maliciosa."
            : "Requiere validacion con el equipo de TI antes de concluir intencionalidad maliciosa."),
      impact: sig.impact,
      mitre: sig.mitre,
      matches,
      investigation: sig.investigation,
      containment: sig.containment,
      remediation: sig.remediation,
    });
  }

  // Consolidacion del grupo de descubrimiento en un unico hallazgo.
  const discovery = groupedMatches.get("discovery");
  if (discovery && discovery.length > 0) {
    const matches = discovery.flatMap((d) => d.matches);
    const distinctTechniques = discovery.length;
    const hosts = uniq(matches.map((m) => m.event.host));
    const users = uniq(matches.map((m) => m.event.user));
    const severity: Severity = distinctTechniques >= 3 || matches.length >= 10 ? "HIGH" : "MEDIUM";

    seeds.push({
      rule: "signature.discovery",
      category: "COMMAND_EXECUTION",
      title: "Reconocimiento interno del entorno (discovery)",
      severity,
      confidence: distinctTechniques >= 3 ? "ALTA" : "MEDIA",
      phase: "Descubrimiento",
      summary:
        `${matches.length} comando(s) de reconocimiento de ${distinctTechniques} tipo(s) distinto(s) ` +
        `en ${hosts.join(", ") || "n/d"}.`,
      technicalExplanation:
        `Se ha ejecutado una bateria de comandos de reconocimiento que cubre ${distinctTechniques} categorias ` +
        `diferentes: ${discovery.map((d) => d.signature.title.toLowerCase()).join("; ")}. Cada comando por separado ` +
        `es una utilidad administrativa legitima, pero su ejecucion encadenada en un corto espacio de tiempo y desde ` +
        `las mismas cuentas (${users.slice(0, 5).join(", ") || "n/d"}) dibuja el patron clasico de la fase de ` +
        `descubrimiento: el atacante acaba de obtener acceso, desconoce el entorno y necesita cartografiarlo para ` +
        `decidir hacia donde moverse. Un administrador que conoce su propia infraestructura no necesita enumerarla ` +
        `de forma sistematica.`,
      justification:
        severity === "HIGH"
          ? `ALTO: la combinacion de ${distinctTechniques} familias de reconocimiento distintas en la misma ventana ` +
            `descarta el uso administrativo puntual y confirma una fase de descubrimiento activa.`
          : `MEDIO: el volumen es limitado y los comandos son herramientas nativas de administracion. Se eleva la ` +
            `atencion pero se requiere contraste con el equipo de sistemas.`,
      impact:
        "El atacante obtiene el mapa de la red, las cuentas, los grupos privilegiados y los recursos compartidos " +
        "disponibles. Esta informacion es la que determina los objetivos del movimiento lateral posterior y el " +
        "camino hacia los datos de mayor valor.",
      mitre: discovery.flatMap((d) => d.signature.mitre),
      matches,
      investigation: [
        "Reconstruir la secuencia temporal completa de comandos por sesion y por usuario.",
        "Determinar que informacion quedo expuesta: que grupos, recursos y sistemas se enumeraron con exito.",
        "Verificar si las cuentas que ejecutan el reconocimiento aparecen en otros hallazgos de este informe.",
      ],
      containment: [
        "Revisar las sesiones activas de las cuentas implicadas y cerrarlas si no estan justificadas.",
      ],
      remediation: [
        "Restringir las herramientas de enumeracion de dominio en estaciones de usuario mediante AppLocker/WDAC.",
        "Habilitar la auditoria de creacion de procesos con linea de comandos (EventID 4688) en toda la flota.",
        "Crear reglas de correlacion en el SIEM que alerten sobre rafagas de comandos de discovery por sesion.",
      ],
    });
  }

  return seeds;
}

/** 5. Movimiento lateral por comportamiento (no por firma). */
function ruleLateralMovement(ctx: Ctx): Seed[] {
  const seeds: Seed[] = [];

  // (a) Acceso a recursos compartidos de red (excluyendo los administrativos,
  //     que ya cubre la firma `admin-share-access`).
  const shareEvents = ctx.events.filter((e) => {
    if (SHARE_ACCESS_IDS.has(e.eventId)) return true;
    const haystack = `${e.target} ${e.commandLine} ${e.message}`;
    return UNC_PATH.test(haystack);
  });

  const shares = groupBy(shareEvents, (e) => {
    const m = UNC_PATH.exec(`${e.target} ${e.commandLine} ${e.message}`);
    if (!m) return "";
    const share = m[2];
    if (/^[a-z]\$$|^admin\$$|^ipc\$$/i.test(share)) return ""; // admin shares aparte
    return `\\\\${m[1]}\\${share}`;
  });

  for (const [share, events] of shares) {
    if (events.length < 2) continue;
    const users = uniq(events.map((e) => e.user));
    const hosts = uniq(events.map((e) => e.host));

    seeds.push({
      rule: "lateral-movement.share-access",
      category: "LATERAL_MOVEMENT",
      title: `Acceso a recurso compartido ${share}`,
      severity: "HIGH",
      confidence: "MEDIA",
      phase: "Movimiento lateral",
      summary: `${events.length} acceso(s) al recurso ${share} desde ${hosts.join(", ") || "n/d"} por ${users.join(", ") || "n/d"}.`,
      technicalExplanation:
        `Se registran ${events.length} operaciones sobre el recurso compartido ${share}, realizadas por ` +
        `${users.join(", ") || "n/d"}. El acceso a recursos compartidos mediante SMB es el mecanismo mas comun de ` +
        `movimiento lateral en entornos Windows porque no requiere explotar ninguna vulnerabilidad: basta con una ` +
        `credencial valida. En el contexto de una intrusion, este acceso marca el paso del sistema inicialmente ` +
        `comprometido al almacenamiento donde reside la informacion de valor.`,
      justification:
        "ALTO: el acceso a recursos compartidos puede ser rutinario, pero aqui se produce dentro de una ventana con " +
        "actividad maliciosa confirmada y desde cuentas implicadas en otros hallazgos, lo que lo convierte en un " +
        "eslabon del movimiento lateral y no en trafico de negocio.",
      impact:
        `Exposicion del contenido de ${share}. Si el recurso almacena informacion financiera, de clientes o datos ` +
        `personales, el incidente adquiere dimension regulatoria ademas de operativa.`,
      mitre: [
        T("Movimiento lateral", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
        T("Recoleccion", "T1039", "Data from Network Shared Drive"),
      ],
      matches: events.map((e) => ({ event: e, detail: describe(e) })),
      investigation: [
        `Inventariar que ficheros concretos de ${share} se abrieron, copiaron o modificaron y clasificar su sensibilidad.`,
        "Comprobar si las cuentas implicadas tenian necesidad de negocio de acceder a ese recurso.",
        "Revisar las ACL del recurso y si se modificaron durante el incidente.",
      ],
      containment: [
        `Restringir temporalmente el acceso a ${share} a las cuentas estrictamente necesarias.`,
        "Habilitar auditoria detallada de acceso a objetos sobre el recurso.",
      ],
      remediation: [
        "Aplicar el principio de minimo privilegio sobre los recursos compartidos y revisar las ACL periodicamente.",
        "Segmentar el acceso SMB por VLAN y rol, impidiendo el acceso directo desde estaciones de usuario a servidores de ficheros sensibles.",
      ],
    });
  }

  // (b) Una misma cuenta autenticandose en multiples sistemas.
  const successes = ctx.events.filter((e, i) => isSuccessfulLogon(e, ctx.texts[i]) && !isMachineAccount(e.user));
  const perUser = groupBy(successes, (e) => normalizeUser(e.user));

  for (const [user, events] of perUser) {
    const hosts = uniq(events.map((e) => e.host));
    if (hosts.length < 3) continue;
    const { first, last } = spanOf(events);

    seeds.push({
      rule: "lateral-movement.multi-host-auth",
      category: "LATERAL_MOVEMENT",
      title: `Autenticacion de "${user}" en ${hosts.length} sistemas distintos`,
      severity: "HIGH",
      confidence: "MEDIA",
      phase: "Movimiento lateral",
      summary: `La cuenta "${user}" se autentica correctamente en ${hosts.length} hosts: ${hosts.join(", ")}.`,
      technicalExplanation:
        `La cuenta "${user}" registra inicios de sesion correctos en ${hosts.length} sistemas distintos ` +
        `(${hosts.join(", ")}) dentro del periodo analizado. Un usuario de negocio opera habitualmente contra uno o ` +
        `dos equipos; el recorrido secuencial por multiples servidores es la huella caracteristica del movimiento ` +
        `lateral, en el que el atacante reutiliza una credencial valida para ir saltando hacia los activos de mayor valor.`,
      justification:
        "ALTO: la dispersion de la cuenta por multiples sistemas se aparta claramente de un patron de uso normal. " +
        "No se eleva a CRITICO porque las cuentas de administracion legitimas pueden presentar este patron; " +
        "requiere confirmacion del rol real de la cuenta.",
      impact:
        "Si la cuenta esta comprometida, el alcance del incidente se extiende a todos los sistemas donde se ha " +
        "autenticado, y en cada uno de ellos pueden haber quedado credenciales cacheadas adicionales.",
      mitre: [
        T("Movimiento lateral", "T1021", "Remote Services"),
        T("Acceso inicial", "T1078", "Valid Accounts"),
      ],
      matches: events.map((e) => ({
        event: e,
        detail: `Sesion ${logonTypeLabel(e.logonType)} en ${e.host} desde ${e.sourceIp || "origen no indicado"}`,
      })),
      investigation: [
        `Confirmar con el area de TI si "${user}" es una cuenta de administracion con alcance multi-servidor legitimo.`,
        first && last ? `Reconstruir la ruta del salto en orden cronologico entre ${first} y ${last}.` : "Reconstruir la ruta del salto en orden cronologico.",
        "Revisar en cada host que procesos se ejecutaron bajo esa sesion.",
      ],
      containment: [
        `Restablecer la contrasena de "${user}", revocar sus tickets Kerberos y cerrar sus sesiones activas.`,
      ],
      remediation: [
        "Aplicar el modelo de tiering para que las cuentas administrativas no puedan autenticarse en cualquier nivel.",
        "Desplegar LAPS y cuentas administrativas diferenciadas por ambito.",
      ],
    });
  }

  // (c) Uso de credenciales explicitas para conexion remota (4648).
  const explicit = ctx.events.filter((e) => e.eventId === "4648");
  if (explicit.length >= 2) {
    const users = uniq(explicit.map((e) => e.user));
    seeds.push({
      rule: "lateral-movement.explicit-credentials",
      category: "LATERAL_MOVEMENT",
      title: "Uso de credenciales explicitas para conexiones remotas",
      severity: "MEDIUM",
      confidence: "MEDIA",
      phase: "Movimiento lateral",
      summary: `${explicit.length} conexiones iniciadas con credenciales distintas a las de la sesion (EventID 4648).`,
      technicalExplanation:
        `El evento 4648 se genera cuando un proceso se conecta a otro sistema usando credenciales diferentes a las ` +
        `de la sesion actual (equivalente a runas o a una conexion con usuario explicito). Es exactamente lo que ` +
        `ocurre cuando un atacante dispone de un par usuario/contrasena robado y lo emplea para alcanzar un sistema ` +
        `distinto desde el equipo que ya controla.`,
      justification:
        "MEDIO: el evento tiene usos administrativos legitimos frecuentes. Se reporta por su valor como eslabon de " +
        "correlacion del movimiento lateral, pendiente de validar los pares origen-destino concretos.",
      impact: "Posible reutilizacion de credenciales robadas para alcanzar nuevos sistemas.",
      mitre: [T("Movimiento lateral", "T1021", "Remote Services"), T("Acceso inicial", "T1078", "Valid Accounts")],
      matches: explicit.map((e) => ({ event: e, detail: describe(e) })),
      investigation: [`Validar para cada evento el par origen-destino y si ${users.join(", ")} debia realizar esa conexion.`],
      containment: ["Bloquear las rutas de conexion no justificadas entre segmentos."],
      remediation: ["Restringir el uso de credenciales explicitas mediante politicas de inicio de sesion."],
    });
  }

  return seeds;
}

/** 6b. Anomalias de comportamiento: recoleccion masiva y exfiltracion. */
function ruleDataMovement(ctx: Ctx): Seed[] {
  const seeds: Seed[] = [];

  // (a) Acceso masivo a ficheros por la misma cuenta en el mismo host.
  const fileEvents = ctx.events.filter((e) => {
    if (FILE_ACCESS_IDS.has(e.eventId)) return true;
    const haystack = `${e.target} ${e.message}`;
    return FILE_PATH.test(haystack);
  });

  const perActor = groupBy(fileEvents, (e) => `${normalizeUser(e.user)}@${e.host}`);
  for (const [actor, events] of perActor) {
    if (events.length < 20) continue;
    const peak = peakInWindow(events, 30 * 60 * 1000);
    const severity: Severity = events.length >= 50 || peak >= 30 ? "CRITICAL" : "HIGH";
    const [user, host] = actor.split("@");
    const { first, last } = spanOf(events);

    seeds.push({
      rule: "anomaly.mass-file-access",
      category: "ANOMALY",
      title: `Acceso masivo a ficheros por "${user}" en ${host || "n/d"}`,
      severity,
      confidence: "ALTA",
      phase: "Recoleccion",
      summary: `${events.length} accesos a ficheros (pico de ${peak} en 30 minutos) por "${user}" en ${host || "n/d"}.`,
      technicalExplanation:
        `La cuenta "${user}" registra ${events.length} operaciones de acceso a ficheros en ${host || "n/d"}, con un ` +
        `pico de ${peak} accesos en una ventana de 30 minutos. Este ritmo es propio de un proceso automatizado que ` +
        `recorre un arbol de directorios, no de una persona abriendo documentos para trabajar con ellos. ` +
        `En la cadena de ataque corresponde a la fase de recoleccion: el atacante, una vez dentro y con privilegios, ` +
        `enumera y lee de forma sistematica el contenido de valor antes de empaquetarlo y sacarlo de la red. ` +
        `El mismo patron precede tanto a la exfiltracion como al cifrado por ransomware, porque ambos requieren ` +
        `recorrer exhaustivamente el sistema de ficheros.`,
      justification:
        severity === "CRITICAL"
          ? `CRITICO: el volumen (${events.length} accesos, pico de ${peak} en 30 minutos) excede cualquier uso ` +
            `humano plausible y encaja con enumeracion automatizada previa a exfiltracion o cifrado.`
          : `ALTO: el volumen (${events.length} accesos) es claramente anomalo frente al uso ofimatico habitual y ` +
            `justifica tratarlo como fase de recoleccion activa.`,
      impact:
        "Exposicion potencialmente completa del contenido accedido. Si incluye datos personales, la organizacion " +
        "entra en el supuesto de violacion de seguridad de datos con las obligaciones de notificacion asociadas.",
      mitre: [
        T("Recoleccion", "T1005", "Data from Local System"),
        T("Descubrimiento", "T1083", "File and Directory Discovery"),
      ],
      matches: events.map((e) => ({ event: e, detail: e.target || describe(e) })),
      investigation: [
        "Obtener el inventario completo de ficheros accedidos y clasificarlos por sensibilidad y marco regulatorio.",
        first && last ? `Acotar la ventana de recoleccion: de ${first} a ${last}.` : "Acotar la ventana de recoleccion.",
        "Determinar si el acceso termino en copia, compresion o transferencia de los ficheros.",
        "Evaluar con el DPO si se cumplen los criterios de notificacion a la autoridad de control.",
      ],
      containment: [
        `Revocar el acceso de "${user}" a los recursos implicados y cerrar sus sesiones.`,
        "Preservar los registros de acceso a objetos antes de que roten.",
      ],
      remediation: [
        "Desplegar UEBA con linea base de volumen de acceso a ficheros por usuario.",
        "Aplicar clasificacion y etiquetado de informacion con controles DLP asociados.",
      ],
    });
  }

  // (b) Transferencias salientes a destinos externos.
  const outbound: { event: LogEvent; dest: string }[] = [];
  for (const e of ctx.events) {
    const dest = outboundTarget(e);
    if (dest) outbound.push({ event: e, dest });
  }

  const perDest = groupBy(outbound, (o) => o.dest);
  for (const [dest, items] of perDest) {
    if (items.length < 3) continue;
    const events = items.map((i) => i.event);
    const uploadVerbs = events.filter((e) =>
      /\b(post|put|upload|subida|send|transfer)\b/i.test(`${e.action} ${e.message} ${e.commandLine} ${e.target}`),
    );
    const totalBytes = events.reduce((sum, e) => sum + (e.bytes ?? 0), 0);
    const ports = uniq(events.map((e) => e.port));
    const hosts = uniq(events.map((e) => e.host));
    const peak = peakInWindow(events, 30 * 60 * 1000);

    const isUpload = uploadVerbs.length >= Math.max(3, Math.floor(items.length * 0.5));
    const severity: Severity = isUpload && items.length >= 5 ? "CRITICAL" : items.length >= 10 ? "HIGH" : "MEDIUM";

    seeds.push({
      rule: isUpload ? "anomaly.data-exfiltration" : "anomaly.outbound-traffic",
      category: "ANOMALY",
      title: isUpload
        ? `Exfiltracion de datos hacia ${dest}`
        : `Conexiones salientes repetidas hacia ${dest}`,
      severity,
      confidence: isUpload ? "ALTA" : "MEDIA",
      phase: "Exfiltracion",
      summary:
        `${items.length} conexion(es) saliente(s) desde ${hosts.join(", ") || "n/d"} hacia ${dest}` +
        `${ports.filter(Boolean).length ? ` (puerto ${ports.filter(Boolean).join(", ")})` : ""}` +
        `${totalBytes > 0 ? `, ${totalBytes.toLocaleString("es-ES")} bytes` : ""}.`,
      technicalExplanation:
        `Se contabilizan ${items.length} conexiones salientes hacia ${dest}, un destino externo a la red ` +
        `corporativa, con un pico de ${peak} en 30 minutos` +
        `${ports.filter(Boolean).length ? ` sobre el puerto ${ports.filter(Boolean).join(", ")}` : ""}. ` +
        (isUpload
          ? `${uploadVerbs.length} de ellas son operaciones de subida (POST/PUT/upload). La repeticion sostenida de ` +
            `subidas hacia un unico destino externo es el patron canonico de exfiltracion por fragmentacion: el ` +
            `atacante trocea el contenedor de datos para que cada peticion individual pase desapercibida frente a ` +
            `los umbrales de volumen del DLP. El uso de HTTPS sobre un puerto permitido en el perimetro hace que el ` +
            `trafico se confunda con navegacion legitima y no sea inspeccionable sin interceptacion TLS.`
          : `El patron regular de conexiones hacia un unico destino externo puede corresponder a un canal de mando y ` +
            `control con intervalos de llamada (beaconing) o a una transferencia de datos. Debe caracterizarse el ` +
            `contenido y la periodicidad para distinguir ambos casos.`) +
        `${totalBytes > 0 ? ` El volumen total registrado asciende a ${totalBytes.toLocaleString("es-ES")} bytes.` : ""}`,
      justification:
        severity === "CRITICAL"
          ? `CRITICO: ${uploadVerbs.length} subidas consecutivas a un unico destino externo constituyen exfiltracion ` +
            `activa. Es el punto de no retorno del incidente: la informacion ya esta fuera del control de la organizacion.`
          : severity === "HIGH"
            ? `ALTO: el volumen de conexiones (${items.length}) hacia un unico destino externo es anomalo y compatible ` +
              `con un canal de mando y control o con transferencia de datos.`
            : `MEDIO: se observa comunicacion externa repetida pendiente de caracterizar. Puede tratarse de un ` +
              `servicio legitimo no inventariado.`,
      impact:
        isUpload
          ? "Perdida de confidencialidad consumada sobre la informacion transferida. Activa las obligaciones de " +
            "notificacion del RGPD (72 horas a la autoridad de control) si incluye datos personales, expone a la " +
            "organizacion a extorsion por publicacion y puede suponer perdida de ventaja competitiva si incluye " +
            "informacion estrategica."
          : "Canal de comunicacion no autorizado con el exterior, utilizable para control remoto o para sacar informacion.",
      mitre: isUpload
        ? [
            T("Exfiltracion", "T1041", "Exfiltration Over C2 Channel"),
            T("Exfiltracion", "T1567.002", "Exfiltration to Cloud Storage"),
          ]
        : [T("Mando y control", "T1071.001", "Application Layer Protocol: Web Protocols")],
      matches: items.map((i) => ({
        event: i.event,
        detail: `${i.event.action || "Conexion"} hacia ${dest}${i.event.port ? `:${i.event.port}` : ""}${i.event.bytes ? ` (${i.event.bytes} bytes)` : ""}`,
      })),
      investigation: [
        `Caracterizar ${dest}: titularidad, reputacion, geolocalizacion y antecedentes en inteligencia de amenazas.`,
        "Recuperar del proxy el volumen real transferido y, si es posible, el contenido o los metadatos de cada peticion.",
        "Correlacionar con los archivos comprimidos creados previamente para determinar que datos salieron.",
        "Cuantificar el alcance exacto de la informacion afectada para el analisis de notificacion regulatoria.",
      ],
      containment: [
        `Bloquear ${dest} en el firewall perimetral, el proxy y el DNS de forma inmediata.`,
        `Aislar los hosts origen (${hosts.join(", ") || "n/d"}) de la red.`,
        "Preservar las capturas de trafico y los logs de proxy del periodo afectado.",
      ],
      remediation: [
        "Implantar DLP con inspeccion de contenido en el canal HTTPS mediante interceptacion TLS controlada.",
        "Restringir la salida a Internet de los servidores mediante lista blanca de destinos.",
        "Desplegar deteccion de beaconing basada en periodicidad de conexiones en el SIEM.",
      ],
    });
  }

  // (c) Acceso a informacion de negocio sensible (staging previo a ransomware /
  //     exfiltracion). Cubre lo que (a) y el acceso a recursos compartidos no
  //     ven por umbral: un unico acceso a un presupuesto o a un share de
  //     finanzas ya es relevante si lo hace una cuenta comprometida.
  const sensitiveEvents = ctx.events.filter(
    (e) =>
      (FILE_ACCESS_IDS.has(e.eventId) || SHARE_ACCESS_IDS.has(e.eventId)) &&
      // Algunos SIEM vuelcan la ruta del 4663 en la columna de comando.
      SENSITIVE_DATA_PATH.test(`${e.target} ${e.message} ${e.commandLine}`),
  );

  for (const [host, events] of groupBy(sensitiveEvents, (e) => e.host)) {
    const users = uniq(events.map((e) => e.user));
    const tainted = users.filter((u) => ctx.compromisedUsers.has(normalizeUser(u)));
    const objects = uniq(events.map(sensitiveObject));
    const severity: Severity = tainted.length > 0 || objects.length >= 10 ? "CRITICAL" : "HIGH";
    const { first, last } = spanOf(events);

    seeds.push({
      rule: "anomaly.sensitive-data-access",
      category: "ANOMALY",
      title: `Acceso a informacion financiera sensible en ${host || "n/d"} (staging)`,
      severity,
      confidence: tainted.length > 0 ? "ALTA" : "MEDIA",
      phase: "Recoleccion",
      summary:
        `${events.length} acceso(s) a ${objects.length} objeto(s) sensible(s) en ${host || "n/d"} ` +
        `por ${users.join(", ") || "n/d"}: ${objects.slice(0, 3).join(", ")}${objects.length > 3 ? ", ..." : ""}.`,
      technicalExplanation:
        `Se registran ${events.length} operaciones de acceso a ficheros o recursos compartidos (EventID ` +
        `${uniq(events.map((e) => e.eventId)).join(", ")}) sobre rutas que contienen informacion financiera o de ` +
        `negocio sensible en ${host || "n/d"}: ${objects.slice(0, 6).join(", ")}` +
        `${objects.length > 6 ? ` y ${objects.length - 6} mas` : ""}. ` +
        (tainted.length > 0
          ? `Los accesos los realiza ${tainted.join(", ")}, cuenta implicada en otros hallazgos de compromiso, por lo ` +
            `que no pueden atribuirse a actividad de negocio. `
          : "") +
        `En la cadena de ataque este paso es la seleccion de objetivos de la fase de recoleccion: el atacante ` +
        `localiza los datos de mayor valor (presupuestos, ejercicios fiscales) para empaquetarlos y extraerlos, y ` +
        `para maximizar la presion de una posterior extorsion por ransomware. Debe leerse junto a los hallazgos de ` +
        `compresion de datos y de eliminacion de instantaneas de volumen.`,
      justification:
        severity === "CRITICAL"
          ? `CRITICO: ` +
            (tainted.length > 0
              ? `el acceso a datos financieros lo realiza una cuenta comprometida (${tainted.join(", ")}), `
              : `se accede a ${objects.length} objetos sensibles distintos, `) +
            `lo que confirma la exposicion de informacion confidencial dentro de una intrusion activa.`
          : `ALTO: se accede a informacion financiera sensible; aunque las cuentas no figuran como comprometidas, ` +
            `el acceso debe validarse con el propietario de los datos.`,
      impact:
        "Exposicion de informacion financiera confidencial (presupuestos, ejercicios fiscales). Si se exfiltra, " +
        "facilita la doble extorsion y puede activar obligaciones regulatorias y contractuales de notificacion.",
      mitre: [
        T("Recoleccion", "T1039", "Data from Network Shared Drive"),
        T("Descubrimiento", "T1083", "File and Directory Discovery"),
      ],
      matches: events.map((e) => ({ event: e, detail: sensitiveObject(e) })),
      investigation: [
        `Confirmar con el propietario de los datos si ${users.join(", ") || "las cuentas implicadas"} tenia necesidad de negocio de acceder a esos ficheros.`,
        first && last ? `Revisar toda la actividad de esas cuentas en ${host || "el servidor"} entre ${first} y ${last}.` : "Revisar toda la actividad de esas cuentas en el servidor.",
        "Determinar si los ficheros accedidos se copiaron, comprimieron o transfirieron despues del acceso.",
      ],
      containment: [
        `Restringir temporalmente el acceso a los recursos financieros de ${host || "el servidor"} a las cuentas estrictamente necesarias.`,
        "Tomar instantanea o copia inmutable de los datos afectados antes de cualquier cifrado.",
      ],
      remediation: [
        "Clasificar los repositorios financieros y aplicar alertas de acceso especificas en el SIEM.",
        "Revisar las ACL de los recursos financieros aplicando minimo privilegio.",
      ],
    });
  }

  return seeds;
}

// ---------------------------------------------------------------------------
// Correlacion en incidentes
// ---------------------------------------------------------------------------

const PHASE_ORDER: readonly KillChainPhase[] = [
  "Acceso inicial", "Ejecucion", "Persistencia", "Escalada de privilegios",
  "Evasion de defensas", "Acceso a credenciales", "Descubrimiento",
  "Movimiento lateral", "Recoleccion", "Mando y control", "Exfiltracion", "Impacto",
];

/**
 * Agrupa hallazgos que comparten entidades (host, cuenta o IP) usando
 * union-find. Cada componente conexa es un incidente: asi respondemos a la
 * pregunta del enunciado sobre si hubo uno o varios incidentes.
 */
function correlate(findings: readonly Finding[]): Incident[] {
  const parent = findings.map((_, i) => i);
  const find = (i: number): number => {
    let root = i;
    while (parent[root] !== root) root = parent[root];
    let cur = i;
    while (parent[cur] !== cur) {
      const next = parent[cur];
      parent[cur] = root;
      cur = next;
    }
    return root;
  };
  const union = (a: number, b: number): void => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent[rb] = ra;
  };

  // Indice entidad -> primer hallazgo que la contiene.
  const owner = new Map<string, number>();
  findings.forEach((f, i) => {
    const keys = [
      ...f.entities.hosts.map((h) => `h:${h.toLowerCase()}`),
      ...f.entities.users.filter((u) => !isMachineAccount(u)).map((u) => `u:${normalizeUser(u)}`),
      ...f.entities.ips.filter(Boolean).map((ip) => `i:${ip}`),
    ];
    for (const key of keys) {
      const prev = owner.get(key);
      if (prev === undefined) owner.set(key, i);
      else union(prev, i);
    }
  });

  const clusters = new Map<number, number[]>();
  findings.forEach((_, i) => {
    const root = find(i);
    const bucket = clusters.get(root) ?? [];
    bucket.push(i);
    clusters.set(root, bucket);
  });

  const incidents: Incident[] = [];
  let seq = 1;

  const ordered = [...clusters.values()].sort((a, b) => b.length - a.length);
  for (const idxs of ordered) {
    const members = idxs.map((i) => findings[i]);
    const severity = maxSeverity(members.map((m) => m.severity));
    const phases = PHASE_ORDER.filter((p) => members.some((m) => m.killChainPhase === p));
    const hosts = uniq(members.flatMap((m) => m.entities.hosts));
    const users = uniq(members.flatMap((m) => m.entities.users));
    const ips = uniq(members.flatMap((m) => m.entities.ips));
    const stamps = members.flatMap((m) => [m.firstSeen, m.lastSeen]).filter((s): s is string => Boolean(s));
    const firstSeen = stamps.length ? stamps.reduce((a, b) => (a < b ? a : b)) : null;
    const lastSeen = stamps.length ? stamps.reduce((a, b) => (a > b ? a : b)) : null;

    const externalIps = ips.filter(isPublicIp);
    const title =
      phases.length >= 4
        ? `Intrusion multifase con ${phases.length} etapas de la cadena de ataque`
        : members.length > 1
          ? `Actividad correlacionada sobre ${hosts.slice(0, 3).join(", ") || "sistemas del cliente"}`
          : members[0].title;

    const narrative =
      `Este incidente agrupa ${members.length} hallazgo${members.length === 1 ? "" : "s"} que comparten entidades ` +
      `(${hosts.length} host(s), ${users.length} cuenta(s), ${ips.length} direccion(es) IP) y que por tanto ` +
      `pertenecen a la misma linea de actividad. ` +
      (phases.length >= 3
        ? `La secuencia observada recorre ${phases.length} fases de la cadena de ataque: ${phases.join(" -> ")}. ` +
          `Esta progresion ordenada es propia de un actor con objetivo definido y no de incidentes aislados o de ` +
          `malware oportunista. `
        : `La actividad se concentra en ${phases.join(" y ") || "una unica fase"}. `) +
      (externalIps.length
        ? `Las direcciones externas implicadas son ${externalIps.join(", ")}. `
        : "") +
      `La severidad del incidente se fija en ${severity} por el hallazgo de mayor criticidad que contiene.`;

    incidents.push({
      id: `INC-${String(seq).padStart(2, "0")}`,
      title,
      severity,
      riskScore: Math.max(...members.map((m) => m.riskScore)),
      findingIds: members.map((m) => m.id),
      phases,
      entities: { hosts: hosts.slice(0, 40), users: users.slice(0, 40), ips: ips.slice(0, 40) },
      firstSeen,
      lastSeen,
      narrative,
    });
    seq += 1;
  }

  return incidents;
}

// ---------------------------------------------------------------------------
// Estadisticas
// ---------------------------------------------------------------------------

function buildTimeline(events: readonly LogEvent[], findings: readonly Finding[]): TimelineBucket[] {
  const stamped = events.filter((e) => e.epoch !== null);
  if (stamped.length === 0) return [];

  // Severidad maxima asociada a cada fila marcada por alguna regla.
  const rowSeverity = new Map<number, Severity>();
  const evidenceIndex = new Map<string, Severity>();
  for (const f of findings) {
    for (const ev of f.evidence) {
      const prev = evidenceIndex.get(ev.logId);
      if (!prev || SEVERITY_RANK[f.severity] > SEVERITY_RANK[prev]) {
        evidenceIndex.set(ev.logId, f.severity);
      }
    }
  }
  for (const e of events) {
    const sev = evidenceIndex.get(e.logId);
    if (sev) rowSeverity.set(e.rowIndex, sev);
  }

  const epochs = stamped.map((e) => e.epoch as number);
  const min = Math.min(...epochs);
  const max = Math.max(...epochs);
  const span = Math.max(max - min, 1);
  const BUCKETS = 24;
  const size = Math.ceil(span / BUCKETS);

  const buckets: TimelineBucket[] = Array.from({ length: BUCKETS }, (_, i) => {
    const start = min + i * size;
    return {
      label: new Date(start).toISOString().slice(5, 16).replace("T", " "),
      iso: new Date(start).toISOString(),
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };
  });

  for (const e of stamped) {
    const i = Math.min(BUCKETS - 1, Math.floor(((e.epoch as number) - min) / size));
    const bucket = buckets[i];
    bucket.total += 1;
    const sev = rowSeverity.get(e.rowIndex);
    if (sev === "CRITICAL") bucket.critical += 1;
    else if (sev === "HIGH") bucket.high += 1;
    else if (sev === "MEDIUM") bucket.medium += 1;
    else if (sev === "LOW") bucket.low += 1;
  }

  return buckets;
}

function buildStats(
  events: readonly LogEvent[],
  findings: readonly Finding[],
  incidents: readonly Incident[],
  flagged: ReadonlySet<number>,
): AnalysisStats {
  const bySeverity: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const byCategory: Record<DetectionCategory, number> = {
    BRUTE_FORCE: 0,
    SUSPICIOUS_LOGON: 0,
    PRIVILEGE_ESCALATION: 0,
    COMMAND_EXECUTION: 0,
    LATERAL_MOVEMENT: 0,
    ANOMALY: 0,
  };
  for (const f of findings) {
    bySeverity[f.severity] += 1;
    byCategory[f.category] += 1;
  }

  // Riesgo global: el hallazgo mas grave manda, con incremento por acumulacion.
  const peak = findings.length ? Math.max(...findings.map((f) => f.riskScore)) : 0;
  const breadth = Math.min(12, (bySeverity.CRITICAL * 3) + (bySeverity.HIGH * 1.5));
  const globalRiskScore = findings.length ? Math.min(100, Math.round(peak + breadth)) : 0;

  return {
    totalEvents: events.length,
    flaggedEvents: flagged.size,
    totalFindings: findings.length,
    totalIncidents: incidents.length,
    bySeverity,
    byCategory,
    timeline: buildTimeline(events, findings),
    topHosts: topCounts(events.map((e) => e.host), 8),
    topSourceIps: topCounts(events.map((e) => e.sourceIp), 8),
    topUsers: topCounts(events.filter((e) => !isMachineAccount(e.user)).map((e) => e.user), 8),
    topEventIds: topCounts(events.map((e) => e.eventId), 8),
    globalRiskScore,
    globalSeverity: findings.length ? severityFromScore(globalRiskScore) : "LOW",
  };
}

// ---------------------------------------------------------------------------
// Orquestacion
// ---------------------------------------------------------------------------

/** Ejecuta el pipeline completo de deteccion y correlacion sobre un dataset. */
export function analyzeDataset(dataset: ParsedDataset): AnalysisResult {
  const ctx: Ctx = {
    events: dataset.events,
    texts: dataset.events.map(eventText),
    compromisedUsers: new Set<string>(),
  };

  // El orden importa: fuerza bruta e inicios sospechosos alimentan
  // `compromisedUsers`, que modula la severidad de la escalada de privilegios.
  const seeds: Seed[] = [
    ...ruleBruteForce(ctx),
    ...ruleSuspiciousLogon(ctx),
    ...rulePrivilegeEscalation(ctx),
    ...ruleSignatures(ctx),
    ...ruleLateralMovement(ctx),
    ...ruleDataMovement(ctx),
  ];

  const flagged = new Set<number>();
  const findings = seeds
    .sort(
      (a, b) =>
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        b.matches.length - a.matches.length,
    )
    .map((seed, i) => buildFinding(seed, i + 1, flagged));

  const incidents = correlate(findings);
  const stats = buildStats(dataset.events, findings, incidents, flagged);

  return {
    generatedAt: new Date().toISOString(),
    dataset: dataset.summary,
    findings,
    incidents,
    stats,
  };
}

/** Etiquetas en castellano de las 6 familias de deteccion. */
export const CATEGORY_LABEL: Record<DetectionCategory, string> = {
  BRUTE_FORCE: "Fuerza bruta",
  SUSPICIOUS_LOGON: "Inicios sospechosos",
  PRIVILEGE_ESCALATION: "Escalamiento de privilegios",
  COMMAND_EXECUTION: "Comandos y procesos",
  LATERAL_MOVEMENT: "Movimiento lateral",
  ANOMALY: "Otras anomalias",
};

export const CATEGORY_DESCRIPTION: Record<DetectionCategory, string> = {
  BRUTE_FORCE: "Intentos de acceso no autorizados por repeticion o pulverizacion de contrasenas.",
  SUSPICIOUS_LOGON: "Sesiones anomalas por origen, horario o patron de uso.",
  PRIVILEGE_ESCALATION: "Obtencion de permisos superiores a los asignados a la cuenta.",
  COMMAND_EXECUTION: "Ejecucion de comandos y procesos sospechosos en los equipos.",
  LATERAL_MOVEMENT: "Saltos entre sistemas de la red reutilizando credenciales validas.",
  ANOMALY: "Persistencia, evasion, exfiltracion, impacto y cualquier otro comportamiento fuera de lo normal.",
};
