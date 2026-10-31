/**
 * Construccion del informe tecnico (SKILL 4 / seccion 4 del enunciado).
 *
 * Genera un modelo estructurado con las 8 secciones obligatorias a partir del
 * resultado del analisis. Este mismo modelo alimenta la vista previa en la UI y
 * el PDF, de modo que lo que el analista ve en pantalla es exactamente lo que
 * se exporta: no hay dos fuentes de verdad.
 */

import { CATEGORY_LABEL } from "./detector";
import {
  formatSpan,
  formatTimestamp,
  SEVERITY_LABEL_ES,
  SEVERITY_ORDER,
  SEVERITY_RANK,
  uniq,
} from "./utils";
import type {
  AiNarrative,
  AnalysisResult,
  Evidence,
  Finding,
  Incident,
  Severity,
} from "./types";

export interface ReportKpi {
  label: string;
  value: string;
  hint?: string;
}

export interface ImpactRow {
  dimension: string;
  description: string;
  severity: Severity;
}

export interface ActionStep {
  priority: "P1" | "P2" | "P3";
  window: string;
  action: string;
  owner: string;
}

export interface RecommendationBlock {
  area: string;
  items: string[];
}

export interface TechnicalReport {
  meta: {
    title: string;
    client: string;
    author: string;
    generatedAt: string;
    datasetName: string;
    period: string;
    eventCount: number;
    classification: string;
  };
  /** 1. Resumen ejecutivo. */
  executiveSummary: {
    verdict: string;
    paragraphs: string[];
    kpis: ReportKpi[];
  };
  /** 2. Hallazgos identificados. */
  findings: Finding[];
  incidents: Incident[];
  /** 4. Evidencias (aplanadas y ordenadas cronologicamente). */
  evidenceLog: (Evidence & { findingId: string; severity: Severity })[];
  /** 6. Posible impacto en la organizacion. */
  impact: ImpactRow[];
  /** 7. Plan de accion. */
  actionPlan: {
    investigate: ActionStep[];
    contain: ActionStep[];
    remediate: ActionStep[];
  };
  /** 8. Recomendaciones generales. */
  recommendations: RecommendationBlock[];
  /** Narrativa opcional de apoyo generada por IA. */
  ai: AiNarrative | null;
}

const CLASSIFICATION = "CONFIDENCIAL - Uso interno del cliente y del equipo de respuesta";

function pct(part: number, total: number): string {
  if (total <= 0) return "0 %";
  return `${((part / total) * 100).toFixed(1)} %`;
}

/** Texto de veredicto global, calibrado al peor hallazgo real del dataset. */
function buildVerdict(result: AnalysisResult): string {
  const { stats, incidents } = result;
  if (stats.totalFindings === 0) {
    return (
      "No se han identificado indicadores de compromiso en la telemetria aportada. " +
      "Este resultado se limita estrictamente al conjunto de registros analizado y no constituye " +
      "una declaracion de ausencia de compromiso en la infraestructura del cliente."
    );
  }

  const critical = stats.bySeverity.CRITICAL;
  const multiPhase = incidents.filter((i) => i.phases.length >= 4).length;

  if (critical > 0 && multiPhase > 0) {
    return (
      `INCIDENTE DE SEGURIDAD CONFIRMADO DE SEVERIDAD CRITICA. El analisis de ${stats.totalEvents.toLocaleString("es-ES")} ` +
      `registros identifica ${stats.totalFindings} hallazgos, de los cuales ${critical} son criticos, correlacionados en ` +
      `${stats.totalIncidents} incidente${stats.totalIncidents === 1 ? "" : "s"}. La actividad no corresponde a eventos ` +
      `aislados: recorre de forma ordenada las fases de una intrusion dirigida, desde el acceso inicial hasta el impacto. ` +
      `Se requiere activacion inmediata del plan de respuesta a incidentes.`
    );
  }
  if (critical > 0) {
    return (
      `INCIDENTE DE SEGURIDAD CONFIRMADO. Se identifican ${critical} hallazgo(s) de severidad critica sobre ` +
      `${stats.totalEvents.toLocaleString("es-ES")} registros analizados. Requiere contencion inmediata.`
    );
  }
  if (stats.bySeverity.HIGH > 0) {
    return (
      `ACTIVIDAD SOSPECHOSA DE SEVERIDAD ALTA. Se identifican ${stats.bySeverity.HIGH} hallazgo(s) de severidad alta que ` +
      `requieren investigacion priorizada, sin evidencia concluyente de compromiso consumado en los registros aportados.`
    );
  }
  return (
    `ANOMALIAS DE SEVERIDAD MODERADA. Se identifican ${stats.totalFindings} hallazgo(s) que se desvian de la linea base ` +
    `esperada y que conviene verificar con el equipo de TI del cliente.`
  );
}

function buildExecutiveParagraphs(result: AnalysisResult): string[] {
  const { stats, dataset, findings, incidents } = result;
  const out: string[] = [];

  out.push(
    `Se ha analizado el fichero "${dataset.fileName}" (hoja "${dataset.sheetName}"), que contiene ` +
      `${stats.totalEvents.toLocaleString("es-ES")} registros exportados del SIEM del cliente` +
      `${dataset.firstEventAt && dataset.lastEventAt
        ? `, abarcando desde ${formatTimestamp(dataset.firstEventAt)} hasta ${formatTimestamp(dataset.lastEventAt)} UTC ` +
          `(${formatSpan(dataset.firstEventAt, dataset.lastEventAt)} de actividad)`
        : ""}. ` +
      `El motor de correlacion ha marcado ${stats.flaggedEvents.toLocaleString("es-ES")} eventos como relevantes ` +
      `(${pct(stats.flaggedEvents, stats.totalEvents)} del total), agrupados en ${stats.totalFindings} hallazgos.`,
  );

  if (findings.length > 0) {
    const severityParts = SEVERITY_ORDER.filter((s) => stats.bySeverity[s] > 0).map(
      (s) => `${stats.bySeverity[s]} ${SEVERITY_LABEL_ES[s].toLowerCase()}${stats.bySeverity[s] === 1 ? "" : "s"}`,
    );
    out.push(
      `Distribucion por criticidad: ${severityParts.join(", ")}. La puntuacion de riesgo global del conjunto es ` +
        `${stats.globalRiskScore}/100, lo que situa el incidente en nivel ${SEVERITY_LABEL_ES[stats.globalSeverity].toUpperCase()}. ` +
        `Las familias de deteccion activadas son: ` +
        `${(Object.keys(stats.byCategory) as (keyof typeof stats.byCategory)[])
          .filter((c) => stats.byCategory[c] > 0)
          .map((c) => `${CATEGORY_LABEL[c]} (${stats.byCategory[c]})`)
          .join(", ")}.`,
    );
  }

  const main = incidents[0];
  if (main && main.phases.length >= 2) {
    out.push(
      `El incidente principal (${main.id}) encadena ${main.phases.length} fases de la cadena de ataque: ` +
        `${main.phases.join(" -> ")}. Afecta a ${main.entities.hosts.length} sistema(s) ` +
        `(${main.entities.hosts.slice(0, 6).join(", ")}${main.entities.hosts.length > 6 ? ", entre otros" : ""}) y a ` +
        `${main.entities.users.length} cuenta(s) de usuario. ` +
        (main.firstSeen && main.lastSeen
          ? `La ventana de actividad comprobada va de ${formatTimestamp(main.firstSeen)} a ${formatTimestamp(main.lastSeen)} UTC ` +
            `(${formatSpan(main.firstSeen, main.lastSeen)}).`
          : ""),
    );
  }

  const top = findings.slice(0, 3);
  if (top.length > 0) {
    out.push(
      `Los hallazgos de mayor prioridad son: ` +
        top.map((f, i) => `(${i + 1}) ${f.title} [${SEVERITY_LABEL_ES[f.severity]}]`).join("; ") +
        `. El detalle tecnico, la evidencia que los sustenta y las acciones correspondientes se desarrollan en las ` +
        `secciones 2 a 7 de este documento.`,
    );
  }

  out.push(
    `Alcance y limitaciones: las conclusiones se apoyan exclusivamente en los registros contenidos en el fichero ` +
      `aportado. No se ha realizado analisis forense sobre los endpoints, captura de trafico ni revision de la ` +
      `configuracion de los sistemas. Cualquier actividad no registrada en el SIEM, o eliminada antes de la ` +
      `exportacion, queda fuera de este analisis.`,
  );

  return out;
}

function buildKpis(result: AnalysisResult): ReportKpi[] {
  const { stats, dataset } = result;
  return [
    { label: "Eventos analizados", value: stats.totalEvents.toLocaleString("es-ES"), hint: dataset.fileName },
    { label: "Eventos relevantes", value: stats.flaggedEvents.toLocaleString("es-ES"), hint: pct(stats.flaggedEvents, stats.totalEvents) },
    { label: "Hallazgos", value: String(stats.totalFindings), hint: `${stats.bySeverity.CRITICAL} criticos` },
    { label: "Incidentes correlacionados", value: String(stats.totalIncidents) },
    { label: "Riesgo global", value: `${stats.globalRiskScore}/100`, hint: SEVERITY_LABEL_ES[stats.globalSeverity] },
    {
      label: "Ventana de actividad",
      value: formatSpan(dataset.firstEventAt, dataset.lastEventAt),
      hint: dataset.firstEventAt ? `desde ${formatTimestamp(dataset.firstEventAt)} UTC` : undefined,
    },
  ];
}

/** Seccion 6: impacto derivado unicamente de las tecnicas realmente detectadas. */
function buildImpact(result: AnalysisResult): ImpactRow[] {
  const rules = new Set(result.findings.map((f) => f.rule));
  const has = (prefix: string) => [...rules].some((r) => r.startsWith(prefix));
  const rows: ImpactRow[] = [];

  const exfiltration = has("anomaly.data-exfiltration");
  const massAccess = has("anomaly.mass-file-access") || has("anomaly.sensitive-data-access");
  const shadowDeletion = result.findings.some((f) => f.rule === "signature.shadow-copy-deletion");
  const persistence = result.findings.some((f) => f.rule.startsWith("signature.persistence") || f.rule === "signature.webshell-execution");
  const credentials = result.findings.some((f) => f.rule === "signature.credential-dumping" || f.category === "PRIVILEGE_ESCALATION");
  const logClearing = result.findings.some((f) => f.rule === "signature.log-clearing");

  rows.push({
    dimension: "Operativo",
    severity: shadowDeletion ? "CRITICAL" : result.stats.globalSeverity,
    description: shadowDeletion
      ? "La destruccion de instantaneas de volumen elimina la via rapida de recuperacion local. Ante un cifrado " +
        "posterior, la restauracion dependeria por completo de las copias externas y el tiempo de recuperacion " +
        "pasaria de horas a dias, con parada total de los servicios afectados."
      : "Degradacion de la confianza en los sistemas implicados. Hasta completar la verificacion de integridad, los " +
        "activos afectados deben considerarse no fiables, lo que obliga a reducir su uso operativo.",
  });

  if (exfiltration || massAccess) {
    rows.push({
      dimension: "Legal y regulatorio",
      severity: exfiltration ? "CRITICAL" : "HIGH",
      description: exfiltration
        ? "Se ha confirmado transferencia de informacion hacia un destino externo. Si entre los datos figuran datos " +
          "personales, se activa el articulo 33 del RGPD: notificacion a la autoridad de control (AEPD en Espana, " +
          "IMY en Suecia) en un plazo maximo de 72 horas desde el conocimiento del hecho, y notificacion a los " +
          "interesados si el riesgo para sus derechos es alto. Procede ademas valorar la denuncia ante las " +
          "autoridades competentes y la notificacion contractual a clientes afectados."
        : "El acceso masivo a repositorios de informacion obliga a determinar si se accedio a datos personales. " +
          "Aun sin exfiltracion confirmada, el acceso no autorizado a datos personales puede constituir una " +
          "violacion de seguridad notificable segun el RGPD.",
    });
  }

  if (exfiltration) {
    rows.push({
      dimension: "Financiero",
      severity: "CRITICAL",
      description:
        "Costes directos de respuesta (analisis forense, horas de equipo, consultoria externa), posible sancion " +
        "administrativa por incumplimiento del deber de proteccion, exposicion a extorsion por publicacion de los " +
        "datos sustraidos y perdida de ventaja competitiva si la informacion incluye datos estrategicos o de clientes.",
    });
  } else {
    rows.push({
      dimension: "Financiero",
      severity: result.stats.globalSeverity,
      description:
        "Costes de respuesta, contencion y reconstruccion de los sistemas afectados, mas el coste de oportunidad " +
        "de los recursos tecnicos desviados a la gestion del incidente.",
    });
  }

  rows.push({
    dimension: "Reputacional",
    severity: exfiltration ? "CRITICAL" : "HIGH",
    description: exfiltration
      ? "La publicacion o venta de la informacion sustraida tendria impacto directo en la confianza de clientes y " +
        "socios. La gestion de la comunicacion debe planificarse antes de que el hecho trascienda por otras vias."
      : "La divulgacion del incidente puede afectar a la percepcion de madurez en seguridad de la organizacion " +
        "frente a clientes y auditores.",
  });

  if (credentials) {
    rows.push({
      dimension: "Identidad y acceso",
      severity: "CRITICAL",
      description:
        "Hay indicios de compromiso de credenciales y de elevacion de privilegios. Debe asumirse que cualquier " +
        "credencial presente en los sistemas afectados esta comprometida, lo que obliga a una rotacion masiva " +
        "coordinada y, si el directorio esta implicado, a un doble restablecimiento de la cuenta krbtgt.",
    });
  }

  if (persistence) {
    rows.push({
      dimension: "Persistencia del atacante",
      severity: "CRITICAL",
      description:
        "Se han identificado mecanismos de persistencia. Una remediacion que se limite a restablecer contrasenas " +
        "dejaria al atacante con acceso: la erradicacion debe eliminar todos los mecanismos detectados y verificarse " +
        "antes de devolver los sistemas a produccion.",
    });
  }

  if (logClearing) {
    rows.push({
      dimension: "Trazabilidad",
      severity: "HIGH",
      description:
        "El borrado de registros implica que el alcance real del incidente puede superar al documentado. Debe " +
        "asumirse el peor escenario en las decisiones de contencion.",
    });
  }

  return rows;
}

/** Seccion 7: plan de accion, derivado de los hallazgos reales y priorizado. */
function buildActionPlan(result: AnalysisResult): TechnicalReport["actionPlan"] {
  const ordered = [...result.findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

  const priorityOf = (s: Severity): ActionStep["priority"] =>
    s === "CRITICAL" ? "P1" : s === "HIGH" ? "P2" : "P3";
  const windowOf = (s: Severity): string =>
    s === "CRITICAL" ? "Inmediato (0-4 h)" : s === "HIGH" ? "24 h" : "72 h";

  const collect = (
    pick: (f: Finding) => string[],
    owner: string,
  ): ActionStep[] => {
    const seen = new Set<string>();
    const steps: ActionStep[] = [];
    for (const f of ordered) {
      for (const action of pick(f)) {
        const key = action.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        steps.push({
          priority: priorityOf(f.severity),
          window: windowOf(f.severity),
          action,
          owner,
        });
      }
    }
    return steps;
  };

  const contain = collect((f) => f.containment, "SOC N2 / Operaciones TI");
  // La contencion siempre arranca con la declaracion formal del incidente.
  if (result.findings.length > 0) {
    contain.unshift({
      priority: "P1",
      window: "Inmediato (0-1 h)",
      action:
        "Declarar formalmente el incidente, activar el comite de crisis y abrir el registro de cadena de custodia " +
        "de la evidencia.",
      owner: "Responsable de Seguridad (CISO)",
    });
  }

  return {
    investigate: collect((f) => f.investigation, "SOC N2 / Forense"),
    contain,
    remediate: collect((f) => f.remediation, "Arquitectura y Sistemas"),
  };
}

/** Seccion 8: recomendaciones estrategicas, con enfasis en lo que este caso evidencia. */
function buildRecommendations(result: AnalysisResult): RecommendationBlock[] {
  const cats = result.stats.byCategory;
  const blocks: RecommendationBlock[] = [];

  const identity: string[] = [
    "Implantar autenticacion multifactor obligatoria en todos los accesos remotos y en las cuentas privilegiadas, sin excepciones.",
    "Adoptar el modelo de niveles (tiering) de Active Directory para impedir que credenciales de dominio se expongan en estaciones de usuario.",
    "Desplegar LAPS para que la contrasena de administrador local sea unica y rotatoria en cada equipo.",
    "Revisar trimestralmente la pertenencia a grupos privilegiados y aplicar administracion Just-In-Time con caducidad automatica.",
  ];
  if (cats.BRUTE_FORCE > 0) {
    identity.unshift(
      "Configurar politicas de bloqueo inteligente y listas de contrasenas prohibidas en el proveedor de identidad, " +
        "evaluando los fallos de forma agregada por IP de origen y no solo por cuenta (un ataque de spraying no " +
        "dispara los umbrales por cuenta).",
    );
  }
  blocks.push({ area: "Gestion de identidades y accesos", items: identity });

  const perimeter: string[] = [
    "Eliminar toda exposicion directa de servicios de administracion (RDP, SSH, WinRM) a Internet; publicarlos unicamente tras VPN con MFA.",
    "Segmentar la red separando estaciones de usuario, servidores y controladores de dominio, con filtrado explicito de SMB y WinRM entre segmentos.",
    "Aplicar filtrado de salida con lista blanca en los servidores: un servidor de ficheros no necesita navegar por Internet.",
  ];
  if (cats.SUSPICIOUS_LOGON > 0) {
    perimeter.push("Implantar acceso condicional basado en ubicacion, horario y estado de cumplimiento del dispositivo.");
  }
  blocks.push({ area: "Arquitectura de red y perimetro", items: perimeter });

  blocks.push({
    area: "Proteccion del endpoint",
    items: [
      "Desplegar EDR con respuesta automatizada en el 100 % de la flota, incluidos los servidores.",
      "Activar las reglas de reduccion de superficie de ataque (ASR) que bloquean vssadmin, wbadmin, bcdedit y la ejecucion de LOLBins.",
      "Habilitar Credential Guard y proteccion LSA (RunAsPPL) para impedir el volcado de credenciales desde memoria.",
      "Aplicar control de aplicaciones (WDAC o AppLocker) con lista blanca en servidores y en estaciones de perfil cerrado.",
      "Activar la proteccion contra manipulaciones del antivirus y gestionar las exclusiones solo desde la consola central.",
    ],
  });

  const monitoring: string[] = [
    "Habilitar la auditoria de creacion de procesos con linea de comandos (EventID 4688) y el registro de bloques de script de PowerShell (EventID 4104) en toda la flota.",
    "Reenviar los registros en tiempo real a un almacen centralizado e inmutable, fuera del alcance de las cuentas administrativas locales.",
    "Definir casos de uso de correlacion en el SIEM para cada una de las tecnicas identificadas en este informe, con sus identificadores MITRE ATT&CK.",
    "Establecer lineas base de comportamiento por usuario (horario, sistemas habituales, volumen de acceso a ficheros) y alertar sobre desviaciones.",
  ];
  blocks.push({ area: "Monitorizacion y deteccion", items: monitoring });

  blocks.push({
    area: "Resiliencia y continuidad",
    items: [
      "Implantar la regla 3-2-1-1-0 de copias de seguridad, con al menos una copia inmutable y desconectada de la red.",
      "Verificar mediante pruebas de restauracion periodicas y documentadas que las copias son utilizables.",
      "Mantener y ensayar un plan de respuesta a incidentes con roles, arbol de llamadas y criterios de escalado definidos.",
      "Realizar un ejercicio de mesa (tabletop) anual sobre un escenario de ransomware con exfiltracion previa.",
    ],
  });

  blocks.push({
    area: "Gobierno y cumplimiento",
    items: [
      "Clasificar y etiquetar la informacion, aplicando controles DLP proporcionales a cada nivel.",
      "Documentar el procedimiento de notificacion de violaciones de seguridad conforme al RGPD y asignar responsables nominales.",
      "Revisar las clausulas de seguridad y los acuerdos de nivel de servicio con proveedores con acceso a la red.",
      "Programar auditorias tecnicas periodicas (test de intrusion y revision de configuracion) sobre los activos expuestos.",
    ],
  });

  return blocks;
}

export interface ReportOptions {
  client?: string;
  author?: string;
  ai?: AiNarrative | null;
}

/** Ensambla el informe tecnico completo a partir del resultado del analisis. */
export function buildReport(result: AnalysisResult, options: ReportOptions = {}): TechnicalReport {
  const evidenceLog = result.findings
    .flatMap((f) => f.evidence.map((e) => ({ ...e, findingId: f.id, severity: f.severity })))
    .sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));

  return {
    meta: {
      title: "Informe tecnico de investigacion de incidente de seguridad",
      client: options.client?.trim() || "Cliente",
      author: options.author?.trim() || "Analista SOC Nivel 2",
      generatedAt: result.generatedAt,
      datasetName: result.dataset.fileName,
      period:
        result.dataset.firstEventAt && result.dataset.lastEventAt
          ? `${formatTimestamp(result.dataset.firstEventAt)} - ${formatTimestamp(result.dataset.lastEventAt)} UTC`
          : "Periodo no determinable a partir de los registros",
      eventCount: result.stats.totalEvents,
      classification: CLASSIFICATION,
    },
    executiveSummary: {
      verdict: buildVerdict(result),
      paragraphs: buildExecutiveParagraphs(result),
      kpis: buildKpis(result),
    },
    findings: result.findings,
    incidents: result.incidents,
    evidenceLog,
    impact: buildImpact(result),
    actionPlan: buildActionPlan(result),
    recommendations: buildRecommendations(result),
    ai: options.ai ?? null,
  };
}

/** Lista unica de tecnicas MITRE observadas, para la portada y el resumen. */
export function mitreCoverage(findings: readonly Finding[]): { id: string; name: string; tactic: string }[] {
  const seen = new Map<string, { id: string; name: string; tactic: string }>();
  for (const f of findings) {
    for (const m of f.mitre) {
      if (!seen.has(m.techniqueId)) {
        seen.set(m.techniqueId, { id: m.techniqueId, name: m.technique, tactic: m.tactic });
      }
    }
  }
  return [...seen.values()].sort((a, b) => a.id.localeCompare(b.id));
}

/** Hosts, cuentas e IPs implicadas en todo el analisis (seccion de evidencias). */
export function affectedEntities(findings: readonly Finding[]): {
  hosts: string[];
  users: string[];
  ips: string[];
} {
  return {
    hosts: uniq(findings.flatMap((f) => f.entities.hosts)),
    users: uniq(findings.flatMap((f) => f.entities.users)),
    ips: uniq(findings.flatMap((f) => f.entities.ips)),
  };
}
