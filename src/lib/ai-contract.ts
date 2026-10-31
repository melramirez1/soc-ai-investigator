/**
 * Contrato entre el cliente y `/api/analyze`.
 *
 * Al servidor solo viaja un *resumen* de hallazgos ya generado por el motor
 * determinista: nunca el dataset completo. Esto reduce el volumen enviado, evita
 * exponer telemetria del cliente a un tercero y limita la superficie de
 * inyeccion de prompt a campos acotados y validados.
 */

import { sanitizeForPrompt } from "./sanitize";
import { SEVERITY_LABEL_ES } from "./utils";
import type { AnalysisResult, Severity } from "./types";

export interface DigestFinding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  phase: string;
  mitre: string[];
  evidenceCount: number;
  summary: string;
  hosts: string[];
  users: string[];
  ips: string[];
  firstSeen: string | null;
  lastSeen: string | null;
}

export interface DigestIncident {
  id: string;
  title: string;
  severity: Severity;
  phases: string[];
  findingIds: string[];
}

export interface AnalysisDigest {
  dataset: {
    fileName: string;
    rowCount: number;
    firstEventAt: string | null;
    lastEventAt: string | null;
  };
  stats: {
    totalEvents: number;
    flaggedEvents: number;
    totalFindings: number;
    totalIncidents: number;
    bySeverity: Record<Severity, number>;
    globalRiskScore: number;
    globalSeverity: Severity;
  };
  findings: DigestFinding[];
  incidents: DigestIncident[];
}

/** Limites duros: acotan el payload y el coste del prompt. */
export const DIGEST_LIMITS = {
  maxFindings: 40,
  maxIncidents: 12,
  maxEntities: 8,
  maxBodyBytes: 256 * 1024,
} as const;

const SEVERITIES: readonly Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/** Construye el resumen a enviar, saneando cada campo de texto. */
export function buildDigest(result: AnalysisResult): AnalysisDigest {
  return {
    dataset: {
      fileName: sanitizeForPrompt(result.dataset.fileName, 120),
      rowCount: result.dataset.rowCount,
      firstEventAt: result.dataset.firstEventAt,
      lastEventAt: result.dataset.lastEventAt,
    },
    stats: {
      totalEvents: result.stats.totalEvents,
      flaggedEvents: result.stats.flaggedEvents,
      totalFindings: result.stats.totalFindings,
      totalIncidents: result.stats.totalIncidents,
      bySeverity: result.stats.bySeverity,
      globalRiskScore: result.stats.globalRiskScore,
      globalSeverity: result.stats.globalSeverity,
    },
    findings: result.findings.slice(0, DIGEST_LIMITS.maxFindings).map((f) => ({
      id: f.id,
      title: sanitizeForPrompt(f.title, 160),
      severity: f.severity,
      category: f.category,
      phase: f.killChainPhase,
      mitre: f.mitre.map((m) => m.techniqueId),
      evidenceCount: f.evidenceCount,
      summary: sanitizeForPrompt(f.summary, 320),
      hosts: f.entities.hosts.slice(0, DIGEST_LIMITS.maxEntities).map((h) => sanitizeForPrompt(h, 60)),
      users: f.entities.users.slice(0, DIGEST_LIMITS.maxEntities).map((u) => sanitizeForPrompt(u, 60)),
      ips: f.entities.ips.filter(Boolean).slice(0, DIGEST_LIMITS.maxEntities).map((i) => sanitizeForPrompt(i, 60)),
      firstSeen: f.firstSeen,
      lastSeen: f.lastSeen,
    })),
    incidents: result.incidents.slice(0, DIGEST_LIMITS.maxIncidents).map((i) => ({
      id: i.id,
      title: sanitizeForPrompt(i.title, 160),
      severity: i.severity,
      phases: i.phases.map((p) => sanitizeForPrompt(p, 40)),
      findingIds: i.findingIds,
    })),
  };
}

// ---------------------------------------------------------------------------
// Validacion en servidor (no se confia en el cliente)
// ---------------------------------------------------------------------------

function str(value: unknown, max: number): string {
  return typeof value === "string" ? sanitizeForPrompt(value, max) : "";
}

function num(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.trunc(value) : 0;
}

function severity(value: unknown): Severity {
  return SEVERITIES.includes(value as Severity) ? (value as Severity) : "LOW";
}

function strList(value: unknown, max: number, maxLen: number): string[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, max).map((v) => str(v, maxLen)).filter(Boolean);
}

function isoOrNull(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * Normaliza un cuerpo de peticion arbitrario al contrato esperado.
 * Devuelve `null` si la forma basica no es reconocible.
 */
export function parseDigest(body: unknown): AnalysisDigest | null {
  if (typeof body !== "object" || body === null) return null;
  const raw = body as Record<string, unknown>;
  const dataset = (raw.dataset ?? {}) as Record<string, unknown>;
  const stats = (raw.stats ?? {}) as Record<string, unknown>;
  const bySeverityRaw = (stats.bySeverity ?? {}) as Record<string, unknown>;

  if (!Array.isArray(raw.findings)) return null;

  const bySeverity: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const s of SEVERITIES) bySeverity[s] = num(bySeverityRaw[s]);

  const findings: DigestFinding[] = raw.findings
    .slice(0, DIGEST_LIMITS.maxFindings)
    .map((item) => {
      const f = (item ?? {}) as Record<string, unknown>;
      return {
        id: str(f.id, 16) || "F-???",
        title: str(f.title, 160),
        severity: severity(f.severity),
        category: str(f.category, 40),
        phase: str(f.phase, 40),
        mitre: strList(f.mitre, 10, 16),
        evidenceCount: num(f.evidenceCount),
        summary: str(f.summary, 320),
        hosts: strList(f.hosts, DIGEST_LIMITS.maxEntities, 60),
        users: strList(f.users, DIGEST_LIMITS.maxEntities, 60),
        ips: strList(f.ips, DIGEST_LIMITS.maxEntities, 60),
        firstSeen: isoOrNull(f.firstSeen),
        lastSeen: isoOrNull(f.lastSeen),
      };
    })
    .filter((f) => Boolean(f.title));

  const incidentsRaw = Array.isArray(raw.incidents) ? raw.incidents : [];
  const incidents: DigestIncident[] = incidentsRaw.slice(0, DIGEST_LIMITS.maxIncidents).map((item) => {
    const i = (item ?? {}) as Record<string, unknown>;
    return {
      id: str(i.id, 16) || "INC-??",
      title: str(i.title, 160),
      severity: severity(i.severity),
      phases: strList(i.phases, 12, 40),
      findingIds: strList(i.findingIds, 40, 16),
    };
  });

  return {
    dataset: {
      fileName: str(dataset.fileName, 120) || "dataset",
      rowCount: num(dataset.rowCount),
      firstEventAt: isoOrNull(dataset.firstEventAt),
      lastEventAt: isoOrNull(dataset.lastEventAt),
    },
    stats: {
      totalEvents: num(stats.totalEvents),
      flaggedEvents: num(stats.flaggedEvents),
      totalFindings: num(stats.totalFindings) || findings.length,
      totalIncidents: num(stats.totalIncidents) || incidents.length,
      bySeverity,
      globalRiskScore: num(stats.globalRiskScore),
      globalSeverity: severity(stats.globalSeverity),
    },
    findings,
    incidents,
  };
}

/** Representacion textual compacta del digest, para incrustar en el prompt. */
export function digestToText(digest: AnalysisDigest): string {
  const lines: string[] = [];
  lines.push(
    `DATASET: ${digest.dataset.fileName} | ${digest.dataset.rowCount} registros | ` +
      `periodo ${digest.dataset.firstEventAt ?? "n/d"} a ${digest.dataset.lastEventAt ?? "n/d"}`,
  );
  lines.push(
    `METRICAS: ${digest.stats.flaggedEvents} eventos relevantes de ${digest.stats.totalEvents} | ` +
      `${digest.stats.totalFindings} hallazgos | ${digest.stats.totalIncidents} incidentes | ` +
      `riesgo global ${digest.stats.globalRiskScore}/100 (${SEVERITY_LABEL_ES[digest.stats.globalSeverity]})`,
  );
  lines.push("");

  for (const inc of digest.incidents) {
    lines.push(
      `INCIDENTE ${inc.id} [${SEVERITY_LABEL_ES[inc.severity]}] ${inc.title} | ` +
        `fases: ${inc.phases.join(" > ") || "n/d"} | hallazgos: ${inc.findingIds.join(", ")}`,
    );
  }
  lines.push("");

  for (const f of digest.findings) {
    lines.push(
      `HALLAZGO ${f.id} [${SEVERITY_LABEL_ES[f.severity]}] ${f.title}\n` +
        `  fase: ${f.phase} | categoria: ${f.category} | MITRE: ${f.mitre.join(", ") || "n/d"} | ` +
        `${f.evidenceCount} evento(s)\n` +
        `  resumen: ${f.summary}\n` +
        `  hosts: ${f.hosts.join(", ") || "n/d"} | cuentas: ${f.users.join(", ") || "n/d"} | ` +
        `ips: ${f.ips.join(", ") || "n/d"}\n` +
        `  ventana: ${f.firstSeen ?? "n/d"} a ${f.lastSeen ?? "n/d"}`,
    );
  }

  return lines.join("\n");
}
