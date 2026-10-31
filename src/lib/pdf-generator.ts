/**
 * Generador del informe tecnico en PDF (SKILL 4).
 *
 * Produce un documento multipagina con las 8 secciones obligatorias del
 * enunciado. Se genera integramente en el navegador con jsPDF: el informe nunca
 * sale del equipo del analista.
 *
 * Nota de color: la portada usa la paleta de marca sobre fondo oscuro; las
 * paginas de contenido usan variantes oscurecidas de esos mismos tonos porque
 * el neon de pantalla (p. ej. #00FFA3) es ilegible impreso sobre blanco.
 */

import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

import { CATEGORY_LABEL } from "./detector";
import { affectedEntities, mitreCoverage, type TechnicalReport } from "./report";
import { formatTimestamp, SEVERITY_LABEL_ES } from "./utils";
import type { Severity } from "./types";

type Rgb = [number, number, number];

/** jsPDF expone `lastAutoTable` cuando se usa la API funcional del plugin. */
type DocWithTable = jsPDF & { lastAutoTable?: { finalY: number } };

const PAGE_W = 210;
const PAGE_H = 297;
const MARGIN = 16;
const CONTENT_W = PAGE_W - MARGIN * 2;

const INK: Rgb = [17, 24, 39];
const MUTED: Rgb = [100, 116, 139];
const RULE: Rgb = [214, 222, 232];
const DARK_CANVAS: Rgb = [8, 11, 16];
const DARK_PANEL: Rgb = [14, 19, 31];
const BRAND_CYAN: Rgb = [0, 229, 255];

/** Paleta de marca (portada oscura). */
const SEVERITY_NEON: Record<Severity, Rgb> = {
  CRITICAL: [255, 0, 85],
  HIGH: [255, 145, 0],
  MEDIUM: [0, 229, 255],
  LOW: [0, 255, 163],
};

/** Variantes legibles sobre papel blanco (texto blanco encima). */
const SEVERITY_PRINT: Record<Severity, Rgb> = {
  CRITICAL: [171, 0, 57],
  HIGH: [163, 85, 0],
  MEDIUM: [0, 104, 122],
  LOW: [0, 106, 71],
};

class ReportDoc {
  readonly doc: DocWithTable;
  y = MARGIN;
  private sectionNo = 0;

  constructor() {
    this.doc = new jsPDF({ unit: "mm", format: "a4", orientation: "portrait" }) as DocWithTable;
    this.doc.setProperties({
      title: "Informe tecnico de investigacion de incidente de seguridad",
      subject: "Analisis SOC N2 de telemetria SIEM",
      creator: "SOC N2 AI Investigator",
    });
  }

  /** Reserva vertical: salta de pagina si no cabe `needed` mm. */
  space(needed: number): void {
    if (this.y + needed > PAGE_H - 22) {
      this.doc.addPage();
      this.y = MARGIN + 6;
    }
  }

  gap(mm: number): void {
    this.y += mm;
  }

  /** Titulo de seccion numerada (las 8 obligatorias). */
  section(title: string): void {
    this.sectionNo += 1;
    this.space(26);
    const { doc } = this;
    doc.setFillColor(...DARK_PANEL);
    doc.rect(MARGIN, this.y, CONTENT_W, 10, "F");
    doc.setFillColor(...BRAND_CYAN);
    doc.rect(MARGIN, this.y, 1.6, 10, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.text(`${this.sectionNo}. ${title.toUpperCase()}`, MARGIN + 5, this.y + 6.8);
    this.y += 15;
    doc.setTextColor(...INK);
  }

  subsection(title: string, accent: Rgb = INK): void {
    this.space(14);
    const { doc } = this;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(10.5);
    doc.setTextColor(...accent);
    const lines = doc.splitTextToSize(title, CONTENT_W) as string[];
    doc.text(lines, MARGIN, this.y);
    this.y += lines.length * 5.2 + 1.5;
    doc.setTextColor(...INK);
  }

  label(text: string): void {
    this.space(8);
    const { doc } = this;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.setTextColor(...MUTED);
    doc.text(text.toUpperCase(), MARGIN, this.y);
    this.y += 4.5;
    doc.setTextColor(...INK);
  }

  paragraph(text: string, options: { size?: number; color?: Rgb; indent?: number } = {}): void {
    if (!text) return;
    const size = options.size ?? 9.5;
    const indent = options.indent ?? 0;
    const { doc } = this;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(size);
    doc.setTextColor(...(options.color ?? INK));
    const lines = doc.splitTextToSize(text, CONTENT_W - indent) as string[];
    const lineH = size * 0.42;
    for (const line of lines) {
      this.space(lineH + 2);
      doc.text(line, MARGIN + indent, this.y);
      this.y += lineH;
    }
    this.y += 2;
    doc.setTextColor(...INK);
  }

  bullets(items: readonly string[], marker = "•"): void {
    const { doc } = this;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    for (const item of items) {
      const lines = doc.splitTextToSize(item, CONTENT_W - 6) as string[];
      this.space(lines.length * 4 + 2);
      doc.setTextColor(...MUTED);
      doc.text(marker, MARGIN + 1, this.y);
      doc.setTextColor(...INK);
      doc.text(lines, MARGIN + 5, this.y);
      this.y += lines.length * 4 + 1.5;
    }
    this.y += 1.5;
  }

  /** Bloque destacado con barra de color (veredicto, avisos). */
  callout(text: string, accent: Rgb, title?: string): void {
    const { doc } = this;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    const lines = doc.splitTextToSize(text, CONTENT_W - 12) as string[];
    const height = lines.length * 4.3 + (title ? 7 : 0) + 8;
    this.space(height + 4);
    doc.setFillColor(248, 250, 252);
    doc.rect(MARGIN, this.y, CONTENT_W, height, "F");
    doc.setFillColor(...accent);
    doc.rect(MARGIN, this.y, 2, height, "F");
    let cursor = this.y + 6;
    if (title) {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9.5);
      doc.setTextColor(...accent);
      doc.text(title.toUpperCase(), MARGIN + 6, cursor);
      cursor += 6;
    }
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    doc.setTextColor(...INK);
    doc.text(lines, MARGIN + 6, cursor);
    this.y += height + 5;
  }

  /** Etiqueta de severidad en linea, con relleno de color. */
  severityChip(severity: Severity, x: number, y: number): number {
    const { doc } = this;
    const text = SEVERITY_LABEL_ES[severity].toUpperCase();
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.5);
    const w = doc.getTextWidth(text) + 5;
    doc.setFillColor(...SEVERITY_PRINT[severity]);
    doc.roundedRect(x, y - 3.4, w, 5, 1, 1, "F");
    doc.setTextColor(255, 255, 255);
    doc.text(text, x + 2.5, y);
    doc.setTextColor(...INK);
    return w;
  }

  table(options: Parameters<typeof autoTable>[1]): void {
    autoTable(this.doc, {
      startY: this.y,
      margin: { left: MARGIN, right: MARGIN },
      theme: "grid",
      styles: {
        font: "helvetica",
        fontSize: 7.8,
        cellPadding: 1.8,
        textColor: INK,
        lineColor: RULE,
        lineWidth: 0.1,
        overflow: "linebreak",
      },
      headStyles: {
        fillColor: DARK_PANEL,
        textColor: [255, 255, 255],
        fontStyle: "bold",
        fontSize: 7.8,
      },
      alternateRowStyles: { fillColor: [247, 249, 252] },
      ...options,
    });
    this.y = (this.doc.lastAutoTable?.finalY ?? this.y) + 6;
  }
}

function drawCover(r: ReportDoc, report: TechnicalReport): void {
  const { doc } = r;
  doc.setFillColor(...DARK_CANVAS);
  doc.rect(0, 0, PAGE_W, PAGE_H, "F");

  // Banda superior con el acento de marca.
  doc.setFillColor(...BRAND_CYAN);
  doc.rect(0, 0, PAGE_W, 1.6, "F");

  doc.setFont("courier", "bold");
  doc.setFontSize(9);
  doc.setTextColor(...BRAND_CYAN);
  doc.text("SOC N2 // AI INVESTIGATOR", MARGIN, 26);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(26);
  doc.setTextColor(255, 255, 255);
  const titleLines = doc.splitTextToSize("Informe tecnico de investigacion de incidente de seguridad", CONTENT_W) as string[];
  doc.text(titleLines, MARGIN, 58);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.setTextColor(148, 163, 184);
  doc.text("De los logs del SIEM al analisis correlacionado y el plan de respuesta", MARGIN, 58 + titleLines.length * 10 + 4);

  // Panel con el veredicto.
  const verdictTop = 120;
  const sev = report.findings[0]?.severity ?? "LOW";
  doc.setFillColor(...DARK_PANEL);
  doc.rect(MARGIN, verdictTop, CONTENT_W, 46, "F");
  doc.setFillColor(...SEVERITY_NEON[sev]);
  doc.rect(MARGIN, verdictTop, 2.2, 46, "F");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8.5);
  doc.setTextColor(...SEVERITY_NEON[sev]);
  doc.text("VEREDICTO", MARGIN + 7, verdictTop + 9);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9.5);
  doc.setTextColor(226, 232, 240);
  doc.text(doc.splitTextToSize(report.executiveSummary.verdict, CONTENT_W - 14) as string[], MARGIN + 7, verdictTop + 16);

  // Metadatos en dos columnas.
  const meta: [string, string][] = [
    ["Cliente", report.meta.client],
    ["Analista", report.meta.author],
    ["Fichero analizado", report.meta.datasetName],
    ["Registros analizados", report.meta.eventCount.toLocaleString("es-ES")],
    ["Periodo cubierto", report.meta.period],
    ["Fecha del informe", `${formatTimestamp(report.meta.generatedAt)} UTC`],
  ];
  let my = 186;
  for (const [k, v] of meta) {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text(k.toUpperCase(), MARGIN, my);
    doc.setFont("courier", "normal");
    doc.setFontSize(9);
    doc.setTextColor(226, 232, 240);
    doc.text(doc.splitTextToSize(v, CONTENT_W - 52) as string[], MARGIN + 52, my);
    my += 10;
  }

  // Resumen numerico.
  const stats: [string, string, Rgb][] = [
    [String(report.findings.filter((f) => f.severity === "CRITICAL").length), "CRITICOS", SEVERITY_NEON.CRITICAL],
    [String(report.findings.filter((f) => f.severity === "HIGH").length), "ALTOS", SEVERITY_NEON.HIGH],
    [String(report.findings.filter((f) => f.severity === "MEDIUM").length), "MEDIOS", SEVERITY_NEON.MEDIUM],
    [String(report.incidents.length), "INCIDENTES", SEVERITY_NEON.LOW],
  ];
  const boxW = (CONTENT_W - 9) / 4;
  stats.forEach(([value, label, color], i) => {
    const x = MARGIN + i * (boxW + 3);
    doc.setFillColor(...DARK_PANEL);
    doc.rect(x, 252, boxW, 22, "F");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(...color);
    doc.text(value, x + 4, 264);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(label, x + 4, 270);
  });

  doc.setFont("helvetica", "normal");
  doc.setFontSize(7.5);
  doc.setTextColor(100, 116, 139);
  doc.text(report.meta.classification, MARGIN, PAGE_H - 12);
}

function drawFooters(r: ReportDoc, report: TechnicalReport): void {
  const { doc } = r;
  const total = doc.getNumberOfPages();
  for (let page = 2; page <= total; page += 1) {
    doc.setPage(page);
    doc.setDrawColor(...RULE);
    doc.setLineWidth(0.2);
    doc.line(MARGIN, PAGE_H - 14, PAGE_W - MARGIN, PAGE_H - 14);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7);
    doc.setTextColor(...MUTED);
    doc.text(`${report.meta.client} — ${report.meta.classification}`, MARGIN, PAGE_H - 9.5);
    doc.text(`Pagina ${page} de ${total}`, PAGE_W - MARGIN, PAGE_H - 9.5, { align: "right" });
  }
}

/** Trunca para que las celdas de tabla no desborden la pagina. */
function cut(text: string, max: number): string {
  const clean = text.trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

// ---------------------------------------------------------------------------
// Secciones
// ---------------------------------------------------------------------------

function sectionExecutiveSummary(r: ReportDoc, report: TechnicalReport): void {
  r.section("Resumen ejecutivo");

  const worst = report.findings[0]?.severity ?? "LOW";
  r.callout(report.executiveSummary.verdict, SEVERITY_PRINT[worst], "Veredicto del analisis");

  r.table({
    head: [["Indicador", "Valor", "Detalle"]],
    body: report.executiveSummary.kpis.map((k) => [k.label, k.value, k.hint ?? ""]),
    columnStyles: {
      0: { cellWidth: 52, fontStyle: "bold" },
      1: { cellWidth: 34, font: "courier" },
      2: { cellWidth: "auto", textColor: MUTED },
    },
  });

  for (const p of report.executiveSummary.paragraphs) r.paragraph(p);

  if (report.ai) {
    r.callout(
      report.ai.executiveSummary,
      [71, 85, 105],
      report.ai.source === "ai"
        ? `Sintesis asistida por IA (${report.ai.model ?? "modelo"})`
        : "Sintesis generada por el motor deterministico offline",
    );
  }
}

function sectionFindings(r: ReportDoc, report: TechnicalReport): void {
  r.section("Hallazgos identificados");

  if (report.findings.length === 0) {
    r.paragraph("No se ha identificado ningun hallazgo en la telemetria analizada.");
    return;
  }

  r.paragraph(
    `Se relacionan a continuacion los ${report.findings.length} hallazgos identificados, ordenados por criticidad. ` +
      `Cada uno se desarrolla tecnicamente en la seccion 3 y se sustenta con evidencia citada en la seccion 4.`,
  );

  r.table({
    head: [["ID", "Hallazgo", "Familia", "Fase", "MITRE ATT&CK", "Crit.", "Ev."]],
    body: report.findings.map((f) => [
      f.id,
      cut(f.title, 90),
      CATEGORY_LABEL[f.category],
      f.killChainPhase,
      f.mitre.map((m) => m.techniqueId).join(", "),
      SEVERITY_LABEL_ES[f.severity],
      String(f.evidenceCount),
    ]),
    columnStyles: {
      0: { cellWidth: 11, font: "courier", fontStyle: "bold" },
      1: { cellWidth: 56 },
      2: { cellWidth: 26 },
      3: { cellWidth: 26 },
      4: { cellWidth: 29, font: "courier", fontSize: 6.8 },
      5: { cellWidth: 16, halign: "center", fontStyle: "bold" },
      6: { cellWidth: 10, halign: "center", font: "courier" },
    },
    didParseCell: (data) => {
      if (data.section === "body" && data.column.index === 5) {
        const finding = report.findings[data.row.index];
        if (finding) {
          data.cell.styles.fillColor = SEVERITY_PRINT[finding.severity];
          data.cell.styles.textColor = [255, 255, 255];
        }
      }
    },
  });

  // Correlacion: ¿uno o varios incidentes?
  r.subsection("Correlacion: incidentes identificados");
  r.paragraph(
    report.incidents.length === 1
      ? "Todos los hallazgos comparten entidades (hosts, cuentas o direcciones IP) y se agrupan por tanto en un " +
        "unico incidente de seguridad, no en eventos independientes."
      : `Los hallazgos se agrupan en ${report.incidents.length} incidentes independientes, en funcion de las ` +
        `entidades que comparten entre si.`,
  );

  r.table({
    head: [["ID", "Incidente", "Hallazgos", "Fases de la cadena de ataque", "Crit."]],
    body: report.incidents.map((i) => [
      i.id,
      cut(i.title, 70),
      i.findingIds.join(", "),
      i.phases.join(" > "),
      SEVERITY_LABEL_ES[i.severity],
    ]),
    columnStyles: {
      0: { cellWidth: 16, font: "courier", fontStyle: "bold" },
      1: { cellWidth: 48 },
      2: { cellWidth: 30, font: "courier", fontSize: 6.8 },
      3: { cellWidth: "auto", fontSize: 7 },
      4: { cellWidth: 16, halign: "center", fontStyle: "bold" },
    },
  });

  for (const incident of report.incidents) {
    r.subsection(`${incident.id} — ${incident.title}`, SEVERITY_PRINT[incident.severity]);
    r.paragraph(incident.narrative);
  }

  const mitre = mitreCoverage(report.findings);
  if (mitre.length > 0) {
    r.subsection("Cobertura MITRE ATT&CK observada");
    r.table({
      head: [["Tactica", "Tecnica", "Identificador"]],
      body: mitre.map((m) => [m.tactic, m.name, m.id]),
      columnStyles: {
        0: { cellWidth: 46 },
        1: { cellWidth: "auto" },
        2: { cellWidth: 26, font: "courier" },
      },
    });
  }
}

function sectionTechnicalExplanation(r: ReportDoc, report: TechnicalReport): void {
  r.section("Explicacion tecnica de cada hallazgo");

  for (const f of report.findings) {
    r.space(38);
    const { doc } = r;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(...SEVERITY_PRINT[f.severity]);
    const titleLines = doc.splitTextToSize(`${f.id} — ${f.title}`, CONTENT_W - 30) as string[];
    doc.text(titleLines, MARGIN, r.y);
    r.severityChip(f.severity, PAGE_W - MARGIN - 24, r.y);
    r.y += titleLines.length * 5 + 2;
    doc.setTextColor(...INK);

    doc.setFont("courier", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(...MUTED);
    doc.text(
      `${CATEGORY_LABEL[f.category]}  |  Fase: ${f.killChainPhase}  |  Riesgo ${f.riskScore}/100  |  ` +
        `Confianza ${f.confidence}  |  ${f.evidenceCount} evento(s)`,
      MARGIN,
      r.y,
    );
    r.y += 6;
    doc.setTextColor(...INK);

    r.paragraph(f.technicalExplanation);

    r.label("Tecnicas MITRE ATT&CK");
    r.bullets(f.mitre.map((m) => `${m.techniqueId} — ${m.technique} (tactica: ${m.tactic})`), "›");

    r.label("Entidades implicadas");
    r.paragraph(
      `Sistemas: ${f.entities.hosts.join(", ") || "n/d"}. ` +
        `Cuentas: ${f.entities.users.join(", ") || "n/d"}. ` +
        `Direcciones IP: ${f.entities.ips.filter(Boolean).join(", ") || "n/d"}. ` +
        `Ventana: ${f.firstSeen ? formatTimestamp(f.firstSeen) : "n/d"} a ${f.lastSeen ? formatTimestamp(f.lastSeen) : "n/d"} UTC.`,
      { size: 8.5, color: MUTED },
    );
    r.gap(3);
  }
}

function sectionEvidence(r: ReportDoc, report: TechnicalReport): void {
  r.section("Evidencias encontradas en los logs");

  if (report.findings.length === 0) {
    r.paragraph("No hay evidencias que citar: el analisis no ha producido hallazgos.");
    return;
  }

  r.paragraph(
    "Toda evidencia se cita con su identificador de registro original (Log_ID), de modo que cualquier afirmacion de " +
      "este informe puede verificarse de forma independiente contra el fichero fuente. Cuando un hallazgo agrupa un " +
      "numero elevado de eventos se incluye una muestra representativa y se indica el total.",
  );

  const entities = affectedEntities(report.findings);
  r.table({
    head: [["Ambito", "Entidades implicadas"]],
    body: [
      ["Sistemas (hosts)", entities.hosts.join(", ") || "n/d"],
      ["Cuentas de usuario", entities.users.join(", ") || "n/d"],
      ["Direcciones IP", entities.ips.filter(Boolean).join(", ") || "n/d"],
    ],
    columnStyles: {
      0: { cellWidth: 42, fontStyle: "bold" },
      1: { cellWidth: "auto", font: "courier", fontSize: 7 },
    },
  });

  for (const f of report.findings) {
    r.subsection(
      `${f.id} — ${f.title}` +
        (f.evidenceCount > f.evidence.length ? ` (muestra de ${f.evidence.length} sobre ${f.evidenceCount})` : ""),
      SEVERITY_PRINT[f.severity],
    );
    r.table({
      head: [["Log_ID", "Fecha/hora (UTC)", "EventID", "Host", "Usuario", "IP", "Detalle"]],
      body: f.evidence.map((e) => [
        e.logId,
        formatTimestamp(e.timestamp),
        e.eventId || "—",
        e.host || "—",
        e.user || "—",
        e.ip || "—",
        cut(e.detail, 150),
      ]),
      styles: { font: "courier", fontSize: 6.6, cellPadding: 1.4, overflow: "linebreak", lineColor: RULE, lineWidth: 0.1 },
      headStyles: { fillColor: DARK_PANEL, textColor: [255, 255, 255], font: "helvetica", fontSize: 7, fontStyle: "bold" },
      alternateRowStyles: { fillColor: [247, 249, 252] },
      columnStyles: {
        0: { cellWidth: 17, fontStyle: "bold" },
        1: { cellWidth: 25 },
        2: { cellWidth: 12 },
        3: { cellWidth: 20 },
        4: { cellWidth: 24 },
        5: { cellWidth: 24 },
        6: { cellWidth: "auto" },
      },
    });
  }
}

function sectionCriticality(r: ReportDoc, report: TechnicalReport): void {
  r.section("Criticidad y justificacion");

  r.paragraph(
    "La criticidad de cada hallazgo se asigna combinando tres factores: la tecnica detectada y su posicion en la " +
      "cadena de ataque, el grado de confirmacion que aportan los registros (intento frente a accion consumada) y el " +
      "volumen y la concentracion temporal de la evidencia. La puntuacion de riesgo (0-100) traduce esa valoracion a " +
      "una escala comparable que permite priorizar la respuesta.",
  );

  r.table({
    head: [["Nivel", "Rango", "Criterio de asignacion", "Respuesta esperada"]],
    body: [
      ["Critico", "85-100", "Compromiso confirmado o tecnica sin uso legitimo posible en el contexto observado.", "Contencion inmediata (0-4 h)"],
      ["Alto", "65-84", "Actividad maliciosa muy probable; admite un uso administrativo marginal a descartar.", "Investigacion priorizada (24 h)"],
      ["Medio", "40-64", "Desviacion de la linea base que requiere verificacion con el cliente.", "Verificacion programada (72 h)"],
      ["Bajo", "0-39", "Anomalia menor o informativa, sin indicio de intencionalidad.", "Seguimiento rutinario"],
    ],
    columnStyles: {
      0: { cellWidth: 20, fontStyle: "bold" },
      1: { cellWidth: 17, font: "courier", halign: "center" },
      2: { cellWidth: "auto" },
      3: { cellWidth: 42 },
    },
    didParseCell: (data) => {
      if (data.section === "body" && data.column.index === 0) {
        const order: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
        const sev = order[data.row.index];
        if (sev) {
          data.cell.styles.fillColor = SEVERITY_PRINT[sev];
          data.cell.styles.textColor = [255, 255, 255];
        }
      }
    },
  });

  for (const f of report.findings) {
    r.space(22);
    const { doc } = r;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9.5);
    doc.setTextColor(...SEVERITY_PRINT[f.severity]);
    const lines = doc.splitTextToSize(`${f.id} — ${f.title}`, CONTENT_W - 34) as string[];
    doc.text(lines, MARGIN, r.y);
    doc.setFont("courier", "normal");
    doc.setFontSize(8);
    doc.setTextColor(...MUTED);
    doc.text(`${f.riskScore}/100`, PAGE_W - MARGIN, r.y, { align: "right" });
    r.y += lines.length * 4.6 + 1;
    doc.setTextColor(...INK);
    r.paragraph(f.justification, { size: 9 });
  }
}

function sectionImpact(r: ReportDoc, report: TechnicalReport): void {
  r.section("Posible impacto en la organizacion");

  r.paragraph(
    "El impacto descrito se deriva exclusivamente de las tecnicas efectivamente detectadas en los registros. No se " +
      "proyectan escenarios hipoteticos que la evidencia no respalde.",
  );

  r.table({
    head: [["Dimension", "Crit.", "Descripcion del impacto"]],
    body: report.impact.map((row) => [row.dimension, SEVERITY_LABEL_ES[row.severity], row.description]),
    columnStyles: {
      0: { cellWidth: 36, fontStyle: "bold" },
      1: { cellWidth: 17, halign: "center", fontStyle: "bold" },
      2: { cellWidth: "auto" },
    },
    didParseCell: (data) => {
      if (data.section === "body" && data.column.index === 1) {
        const row = report.impact[data.row.index];
        if (row) {
          data.cell.styles.fillColor = SEVERITY_PRINT[row.severity];
          data.cell.styles.textColor = [255, 255, 255];
        }
      }
    },
  });

  r.subsection("Impacto especifico por hallazgo");
  for (const f of report.findings) {
    r.space(16);
    const { doc } = r;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(...INK);
    const lines = doc.splitTextToSize(`${f.id} — ${f.title}`, CONTENT_W) as string[];
    doc.text(lines, MARGIN, r.y);
    r.y += lines.length * 4.4 + 0.5;
    r.paragraph(f.impact, { size: 9, indent: 3 });
  }
}

function sectionActionPlan(r: ReportDoc, report: TechnicalReport): void {
  r.section("Plan de accion: investigar, contener y remediar");

  r.paragraph(
    "El plan se organiza en tres bloques secuenciales pero solapables. La contencion se ejecuta en paralelo a la " +
      "investigacion cuando hay hallazgos criticos: no debe esperarse a cerrar el analisis para cortar el acceso del " +
      "atacante. Las ventanas temporales se cuentan desde la aceptacion de este informe.",
  );

  const blocks: [string, typeof report.actionPlan.investigate, string][] = [
    [
      "7.1 Contener",
      report.actionPlan.contain,
      "Objetivo: detener la progresion del atacante y limitar el dano, preservando la evidencia.",
    ],
    [
      "7.2 Investigar",
      report.actionPlan.investigate,
      "Objetivo: determinar el alcance real, el vector de entrada y la permanencia del atacante.",
    ],
    [
      "7.3 Remediar",
      report.actionPlan.remediate,
      "Objetivo: erradicar el acceso y cerrar las debilidades que hicieron posible el incidente.",
    ],
  ];

  for (const [title, steps, intro] of blocks) {
    r.subsection(title);
    r.paragraph(intro, { size: 9, color: MUTED });
    if (steps.length === 0) {
      r.paragraph("Sin acciones derivadas para este bloque.", { size: 9, color: MUTED });
      continue;
    }
    r.table({
      head: [["Pri.", "Ventana", "Accion", "Responsable"]],
      body: steps.map((s) => [s.priority, s.window, s.action, s.owner]),
      columnStyles: {
        0: { cellWidth: 11, halign: "center", fontStyle: "bold", font: "courier" },
        1: { cellWidth: 26, fontSize: 7 },
        2: { cellWidth: "auto" },
        3: { cellWidth: 36, fontSize: 7, textColor: MUTED },
      },
      didParseCell: (data) => {
        if (data.section === "body" && data.column.index === 0) {
          const step = steps[data.row.index];
          if (step) {
            const color: Rgb =
              step.priority === "P1" ? SEVERITY_PRINT.CRITICAL : step.priority === "P2" ? SEVERITY_PRINT.HIGH : SEVERITY_PRINT.MEDIUM;
            data.cell.styles.fillColor = color;
            data.cell.styles.textColor = [255, 255, 255];
          }
        }
      },
    });
  }
}

function sectionRecommendations(r: ReportDoc, report: TechnicalReport): void {
  r.section("Recomendaciones generales de seguridad");

  r.paragraph(
    "Las acciones de la seccion anterior resuelven este incidente concreto. Las recomendaciones que siguen buscan " +
      "elevar el nivel de madurez de forma permanente para que un ataque equivalente no vuelva a prosperar, y se " +
      "ordenan por el retorno que ofrecen frente al esfuerzo de implantacion.",
  );

  for (const block of report.recommendations) {
    r.subsection(block.area);
    r.bullets(block.items);
  }

  if (report.ai?.attackStory) {
    r.section("Anexo: reconstruccion narrativa del ataque");
    r.paragraph(
      report.ai.source === "ai"
        ? `Narrativa generada con asistencia de IA (${report.ai.model ?? "modelo"}) a partir exclusivamente de los ` +
          `hallazgos y evidencias de este informe. Se incluye como apoyo a la lectura y no sustituye al analisis tecnico.`
        : "Narrativa generada por el motor deterministico offline a partir de los hallazgos de este informe.",
      { size: 8.5, color: MUTED },
    );
    r.paragraph(report.ai.attackStory);
    if (report.ai.priorityActions.length > 0) {
      r.label("Acciones prioritarias destacadas");
      r.bullets(report.ai.priorityActions);
    }
  }

  // Alcance y limitaciones, siempre al final.
  r.subsection("Alcance, metodologia y limitaciones");
  r.paragraph(
    `Este informe se ha elaborado analizando el fichero "${report.meta.datasetName}" ` +
      `(${report.meta.eventCount.toLocaleString("es-ES")} registros, periodo ${report.meta.period}) mediante un motor ` +
      `de correlacion basado en reglas deterministas alineadas con MITRE ATT&CK. Cada hallazgo esta respaldado por ` +
      `registros concretos citados por su Log_ID.`,
  );
  r.bullets([
    "No se ha realizado analisis forense de disco ni de memoria sobre los sistemas afectados.",
    "No se ha capturado ni analizado trafico de red en vivo.",
    "No se ha revisado la configuracion de los sistemas ni de las politicas de seguridad vigentes.",
    "La actividad no registrada por el SIEM, o eliminada antes de la exportacion, queda fuera del alcance.",
    "Las conclusiones son validas para el periodo cubierto por los registros y no proyectan el estado actual de la infraestructura.",
  ]);
}

// ---------------------------------------------------------------------------
// API publica
// ---------------------------------------------------------------------------

/** Genera el PDF completo y devuelve el blob resultante. */
export function generateReportPdf(report: TechnicalReport): Blob {
  const r = new ReportDoc();

  drawCover(r, report);
  r.doc.addPage();
  r.y = MARGIN + 6;

  sectionExecutiveSummary(r, report);
  sectionFindings(r, report);
  sectionTechnicalExplanation(r, report);
  sectionEvidence(r, report);
  sectionCriticality(r, report);
  sectionImpact(r, report);
  sectionActionPlan(r, report);
  sectionRecommendations(r, report);

  drawFooters(r, report);

  return r.doc.output("blob");
}

/** Nombre de fichero estable y ordenable para la descarga. */
export function reportFileName(report: TechnicalReport): string {
  const stamp = report.meta.generatedAt.slice(0, 19).replace(/[:T]/g, "-");
  const client = report.meta.client.replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "Cliente";
  return `Informe_Incidente_${client}_${stamp}.pdf`;
}

/** Dispara la descarga en el navegador. */
export function downloadReportPdf(report: TechnicalReport): void {
  const blob = generateReportPdf(report);
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = reportFileName(report);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  // Liberamos el object URL en el siguiente tick para no cancelar la descarga.
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
