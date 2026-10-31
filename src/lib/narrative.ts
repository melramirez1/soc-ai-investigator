/**
 * Motor narrativo deterministico (modo offline).
 *
 * Se usa cuando no hay `GROQ_API_KEY` configurada o cuando la llamada al LLM
 * falla. Garantiza que la aplicacion nunca se rompe por depender de un servicio
 * externo (SKILL 5, punto 4) y que el informe siempre incluye una sintesis.
 *
 * No inventa nada: todo el texto se construye a partir de los hallazgos reales
 * contenidos en el digest.
 */

import { SEVERITY_LABEL_ES } from "./utils";
import type { AnalysisDigest } from "./ai-contract";
import type { AiNarrative } from "./types";

/** Orden canonico de fases para ordenar la narracion. */
const PHASE_ORDER = [
  "Acceso inicial",
  "Ejecucion",
  "Persistencia",
  "Escalada de privilegios",
  "Evasion de defensas",
  "Acceso a credenciales",
  "Descubrimiento",
  "Movimiento lateral",
  "Recoleccion",
  "Mando y control",
  "Exfiltracion",
  "Impacto",
];

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

export function buildOfflineNarrative(digest: AnalysisDigest, notice: string | null): AiNarrative {
  const { stats, findings, incidents, dataset } = digest;

  if (findings.length === 0) {
    return {
      source: "offline",
      model: null,
      executiveSummary:
        `El analisis de ${stats.totalEvents.toLocaleString("es-ES")} registros de "${dataset.fileName}" no ha ` +
        `identificado indicadores de compromiso. Este resultado se limita a la telemetria aportada y no acredita ` +
        `la ausencia de compromiso en el resto de la infraestructura.`,
      attackStory:
        "No se ha podido reconstruir ninguna cadena de ataque porque no se han detectado hallazgos en los registros analizados.",
      priorityActions: [
        "Ampliar la ventana de exportacion del SIEM y repetir el analisis.",
        "Verificar que las fuentes criticas (controlador de dominio, servidores expuestos, proxy) estan reenviando eventos.",
      ],
      notice,
    };
  }

  const critical = findings.filter((f) => f.severity === "CRITICAL");
  const hosts = uniqueStrings(findings.flatMap((f) => f.hosts));
  const users = uniqueStrings(findings.flatMap((f) => f.users));
  const ips = uniqueStrings(findings.flatMap((f) => f.ips));
  const main = incidents[0];

  const executiveSummary =
    `Sobre ${stats.totalEvents.toLocaleString("es-ES")} registros del fichero "${dataset.fileName}" se han marcado ` +
    `${stats.flaggedEvents.toLocaleString("es-ES")} eventos como relevantes, que el motor de correlacion agrupa en ` +
    `${stats.totalFindings} hallazgos (${critical.length} criticos) y ${stats.totalIncidents} ` +
    `incidente${stats.totalIncidents === 1 ? "" : "s"}. La puntuacion de riesgo global es ${stats.globalRiskScore}/100, ` +
    `nivel ${SEVERITY_LABEL_ES[stats.globalSeverity].toUpperCase()}. ` +
    `Estan implicados ${hosts.length} sistema(s), ${users.length} cuenta(s) y ${ips.length} direccion(es) IP. ` +
    (critical.length > 0
      ? `Los hallazgos criticos exigen contencion inmediata: ${critical.slice(0, 3).map((f) => f.title).join("; ")}.`
      : `No hay hallazgos criticos, pero los de severidad alta requieren investigacion priorizada en 24 horas.`);

  // Reconstruccion cronologica por fase de la cadena de ataque.
  const byPhase = new Map<string, typeof findings>();
  for (const f of findings) {
    const bucket = byPhase.get(f.phase) ?? [];
    bucket.push(f);
    byPhase.set(f.phase, bucket);
  }
  const orderedPhases = PHASE_ORDER.filter((p) => byPhase.has(p));

  const storyParts: string[] = [];
  storyParts.push(
    main && main.phases.length >= 3
      ? `La evidencia describe una intrusion estructurada que recorre ${main.phases.length} fases de la cadena de ` +
        `ataque. No se trata de eventos aislados: los hallazgos comparten sistemas, cuentas y direcciones IP, lo que ` +
        `los vincula a una misma linea de actividad.`
      : `La evidencia describe actividad concentrada en ${orderedPhases.length} fase(s) de la cadena de ataque.`,
  );

  for (const phase of orderedPhases) {
    const group = byPhase.get(phase) ?? [];
    const worst = group.reduce((a, b) =>
      ["LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(b.severity) >
      ["LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(a.severity)
        ? b
        : a,
    );
    const phaseHosts = uniqueStrings(group.flatMap((f) => f.hosts)).slice(0, 4);
    storyParts.push(
      `${phase.toUpperCase()}: ${group.length} hallazgo(s), el mas grave "${worst.title}" ` +
        `[${SEVERITY_LABEL_ES[worst.severity]}], con ${group.reduce((s, f) => s + f.evidenceCount, 0)} evento(s) de ` +
        `respaldo sobre ${phaseHosts.join(", ") || "sistemas no identificados"}. ` +
        `Tecnicas: ${uniqueStrings(group.flatMap((f) => f.mitre)).join(", ") || "n/d"}.`,
    );
  }

  const firstSeen = findings.map((f) => f.firstSeen).filter((s): s is string => Boolean(s)).sort()[0];
  const lastSeen = findings.map((f) => f.lastSeen).filter((s): s is string => Boolean(s)).sort().reverse()[0];
  if (firstSeen && lastSeen) {
    storyParts.push(
      `La actividad comprobada va de ${firstSeen} a ${lastSeen} (UTC). Todo lo anterior o posterior a esa ventana ` +
        `queda fuera del alcance de los registros aportados.`,
    );
  }

  const priorityActions = [
    ...critical.slice(0, 5).map(
      (f) =>
        `[${f.id}] Contener "${f.title}" en ${f.hosts.slice(0, 3).join(", ") || "los sistemas implicados"} ` +
        `(${f.evidenceCount} evento(s) de respaldo).`,
    ),
    ips.length > 0 ? `Bloquear en el perimetro las direcciones externas implicadas: ${ips.slice(0, 6).join(", ")}.` : "",
    users.length > 0
      ? `Restablecer credenciales y revocar sesiones de las cuentas implicadas: ${users.slice(0, 6).join(", ")}.`
      : "",
    "Preservar la evidencia (discos, memoria y logs) con cadena de custodia antes de cualquier reinstalacion.",
  ].filter(Boolean);

  return {
    source: "offline",
    model: null,
    executiveSummary,
    attackStory: storyParts.join("\n\n"),
    priorityActions,
    notice,
  };
}
