/**
 * Modelo de dominio del SOC N2 AI Investigator.
 *
 * Todo el pipeline (parser -> detector -> correlador -> informe -> PDF) trabaja
 * sobre estos tipos. No se usan `any` en ninguna ruta de datos de telemetria.
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type Confidence = "ALTA" | "MEDIA" | "BAJA";

/** Las 6 familias de deteccion exigidas por el enunciado del reto. */
export type DetectionCategory =
  | "BRUTE_FORCE"
  | "SUSPICIOUS_LOGON"
  | "PRIVILEGE_ESCALATION"
  | "COMMAND_EXECUTION"
  | "LATERAL_MOVEMENT"
  | "ANOMALY";

/** Fases de la cadena de ataque (tacticas MITRE ATT&CK, en orden operativo). */
export type KillChainPhase =
  | "Acceso inicial"
  | "Ejecucion"
  | "Persistencia"
  | "Escalada de privilegios"
  | "Evasion de defensas"
  | "Acceso a credenciales"
  | "Descubrimiento"
  | "Movimiento lateral"
  | "Recoleccion"
  | "Mando y control"
  | "Exfiltracion"
  | "Impacto";

/**
 * Un registro normalizado del SIEM. `raw` conserva la fila original completa
 * para que el analista pueda auditar cualquier columna que no mapeemos.
 */
export interface LogEvent {
  /** Indice 0-based dentro del dataset, estable para referencias internas. */
  rowIndex: number;
  /** Identificador del log tal y como viene en el fichero (Log_ID). */
  logId: string;
  /** Marca temporal normalizada a ISO 8601, o null si no se pudo interpretar. */
  timestamp: string | null;
  /** Milisegundos epoch derivados de `timestamp`, o null. */
  epoch: number | null;
  /** Valor textual original de la marca temporal. */
  rawTimestamp: string;
  eventId: string;
  host: string;
  user: string;
  sourceIp: string;
  destIp: string;
  logonType: string;
  process: string;
  parentProcess: string;
  commandLine: string;
  status: string;
  action: string;
  protocol: string;
  port: string;
  bytes: number | null;
  /** Objeto afectado: ruta de fichero, recurso compartido, servicio, URL... */
  target: string;
  message: string;
  /** Fila original (cabecera -> valor) ya saneada para render seguro. */
  raw: Record<string, string>;
}

export interface MitreRef {
  tactic: string;
  techniqueId: string;
  technique: string;
}

/** Una linea de evidencia citable en el informe. */
export interface Evidence {
  logId: string;
  timestamp: string;
  eventId: string;
  host: string;
  user: string;
  ip: string;
  /** Comando, recurso o descripcion concreta que motiva la deteccion. */
  detail: string;
}

export interface Finding {
  id: string;
  /** Clave estable de la regla que lo genero (util para trazabilidad). */
  rule: string;
  category: DetectionCategory;
  title: string;
  severity: Severity;
  /** Puntuacion de riesgo 0-100 derivada de severidad, volumen y correlacion. */
  riskScore: number;
  confidence: Confidence;
  killChainPhase: KillChainPhase;
  /** Resumen de una linea. */
  summary: string;
  /** Seccion 3 del informe: explicacion tecnica en profundidad. */
  technicalExplanation: string;
  /** Seccion 5 del informe: por que esta criticidad y no otra. */
  justification: string;
  /** Seccion 6 del informe: impacto concreto para la organizacion. */
  impact: string;
  mitre: MitreRef[];
  /** Evidencias citadas (muestra acotada de `evidenceCount`). */
  evidence: Evidence[];
  /** Numero total de eventos que dispararon la regla. */
  evidenceCount: number;
  entities: {
    hosts: string[];
    users: string[];
    ips: string[];
  };
  firstSeen: string | null;
  lastSeen: string | null;
  /** Seccion 7 del informe. */
  investigation: string[];
  containment: string[];
  remediation: string[];
}

/** Agrupacion de hallazgos que comparten entidades: un incidente real. */
export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  riskScore: number;
  findingIds: string[];
  phases: KillChainPhase[];
  entities: {
    hosts: string[];
    users: string[];
    ips: string[];
  };
  firstSeen: string | null;
  lastSeen: string | null;
  narrative: string;
}

export interface CountBucket {
  key: string;
  count: number;
}

export interface TimelineBucket {
  /** Etiqueta legible del intervalo. */
  label: string;
  /** Inicio del intervalo en ISO. */
  iso: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface AnalysisStats {
  totalEvents: number;
  flaggedEvents: number;
  totalFindings: number;
  totalIncidents: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<DetectionCategory, number>;
  timeline: TimelineBucket[];
  topHosts: CountBucket[];
  topSourceIps: CountBucket[];
  topUsers: CountBucket[];
  topEventIds: CountBucket[];
  /** Puntuacion global de riesgo del dataset (0-100). */
  globalRiskScore: number;
  /** Severidad global derivada de `globalRiskScore` y los hallazgos. */
  globalSeverity: Severity;
}

export interface DatasetSummary {
  fileName: string;
  fileSizeBytes: number;
  sheetName: string;
  rowCount: number;
  columns: string[];
  /** Columnas reconocidas: campo canonico -> cabecera original. */
  mappedColumns: Record<string, string>;
  /** Cabeceras que no se pudieron mapear (se conservan en `raw`). */
  unmappedColumns: string[];
  firstEventAt: string | null;
  lastEventAt: string | null;
  /** Avisos no bloqueantes del parser (fechas invalidas, filas vacias...). */
  warnings: string[];
}

export interface ParsedDataset {
  summary: DatasetSummary;
  events: LogEvent[];
}

export interface AnalysisResult {
  generatedAt: string;
  dataset: DatasetSummary;
  findings: Finding[];
  incidents: Incident[];
  stats: AnalysisStats;
}

/** Narrativa opcional generada por IA (o por el motor offline determinista). */
export interface AiNarrative {
  source: "ai" | "offline";
  model: string | null;
  executiveSummary: string;
  attackStory: string;
  priorityActions: string[];
  /** Mensaje de aviso si la IA fallo y se uso el modo offline. */
  notice: string | null;
}
