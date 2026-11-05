"use client";

/**
 * Consola principal del SOC N2 AI Investigator.
 *
 * Flujo: fichero -> `parseTelemetryFile` -> `analyzeDataset` -> `buildReport`.
 * Todo el procesamiento ocurre en el navegador; a `/api/analyze` solo viaja el
 * digest saneado de hallazgos (`buildDigest`), nunca la telemetria.
 *
 * Seguridad (SKILL 5): no se usa `dangerouslySetInnerHTML`; todo texto de logs
 * se pinta como nodo de texto y React lo escapa.
 */

import { useCallback, useMemo, useRef, useState, type DragEvent, type ReactNode } from "react";
import {
  AlertTriangle,
  Bot,
  ChevronDown,
  ChevronRight,
  Crosshair,
  Database,
  Download,
  FileSpreadsheet,
  Fingerprint,
  Gauge,
  Loader2,
  Search,
  ShieldAlert,
  Siren,
  Upload,
} from "lucide-react";

import { MotionConfig } from "framer-motion";

import { AppHeader, SideNav, StatusBar, ViewHeader, type ViewKey } from "@/components/AppShell";
import { CategoryBreakdown, EntityRanking, EventTimeline, SeverityDonut } from "@/components/charts";
import {
  Button,
  Chip,
  EmptyState,
  Mono,
  Notice,
  Panel,
  PanelHeader,
  RiskMeter,
  SectionTitle,
  SeverityBadge,
  Stagger,
  StaggerItem,
  StatTile,
} from "@/components/ui/primitives";
import { buildDigest } from "@/lib/ai-contract";
import { analyzeDataset, CATEGORY_DESCRIPTION, CATEGORY_LABEL } from "@/lib/detector";
import { buildOfflineNarrative } from "@/lib/narrative";
import { ALLOWED_EXTENSIONS, parseTelemetryFile } from "@/lib/parser";
import { buildReport, mitreCoverage, type ActionStep, type TechnicalReport } from "@/lib/report";
import { cn, formatBytes, formatTimestamp, SEVERITY_LABEL_ES, SEVERITY_ORDER, SEVERITY_RANK } from "@/lib/utils";
import type {
  AiNarrative,
  AnalysisResult,
  DetectionCategory,
  Evidence,
  Finding,
  LogEvent,
  ParsedDataset,
  Severity,
} from "@/lib/types";

const REPORT_OPTIONS = {
  client: "Consultora Estocolmo (Infraestructura)",
  author: "Analista SOC Nivel 2",
} as const;

/** Filas maximas pintadas a la vez en tablas largas (rendimiento del DOM). */
const MAX_TABLE_ROWS = 300;

// ---------------------------------------------------------------------------
// Validacion de la respuesta de /api/analyze (no se confia en la red)
// ---------------------------------------------------------------------------

function isAiNarrative(value: unknown): value is AiNarrative {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    (v.source === "ai" || v.source === "offline") &&
    typeof v.executiveSummary === "string" &&
    typeof v.attackStory === "string" &&
    Array.isArray(v.priorityActions) &&
    v.priorityActions.every((a) => typeof a === "string") &&
    (v.model === null || typeof v.model === "string") &&
    (v.notice === null || typeof v.notice === "string")
  );
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

// ===========================================================================
// Pagina
// ===========================================================================

export default function Home() {
  const [view, setView] = useState<ViewKey>("ingest");
  const [dataset, setDataset] = useState<ParsedDataset | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [report, setReport] = useState<TechnicalReport | null>(null);
  const [processing, setProcessing] = useState(false);
  const [aiBusy, setAiBusy] = useState(false);
  const [pdfBusy, setPdfBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFile = useCallback(async (file: File) => {
    setProcessing(true);
    setError(null);
    try {
      const parsed = await parseTelemetryFile(file);
      const analysis = analyzeDataset(parsed);
      setDataset(parsed);
      setResult(analysis);
      setReport(buildReport(analysis, REPORT_OPTIONS));
      setView("dashboard");
    } catch (err) {
      setError(errorMessage(err, "Error procesando el archivo de telemetria."));
    } finally {
      setProcessing(false);
    }
  }, []);

  const handleRunAi = useCallback(async () => {
    if (!result) return;
    setAiBusy(true);
    setError(null);
    const digest = buildDigest(result);
    let narrative: AiNarrative;
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(digest),
      });
      const data: unknown = await res.json().catch(() => null);
      if (!res.ok || !isAiNarrative(data)) {
        const reason =
          typeof data === "object" && data !== null && typeof (data as { error?: unknown }).error === "string"
            ? (data as { error: string }).error
            : `HTTP ${res.status}`;
        throw new Error(reason);
      }
      narrative = data;
    } catch (err) {
      // El servidor ya degrada a offline; esto cubre la caida de red o de la ruta.
      narrative = buildOfflineNarrative(
        digest,
        `No se pudo completar el analisis IA (${errorMessage(err, "error desconocido").slice(0, 120)}). ` +
          "Se muestra la sintesis deterministica generada en el navegador.",
      );
    }
    setReport(buildReport(result, { ...REPORT_OPTIONS, ai: narrative }));
    setAiBusy(false);
    setView("report");
  }, [result]);

  const handleExportPdf = useCallback(async () => {
    if (!report) return;
    setPdfBusy(true);
    try {
      // Carga diferida: jsPDF solo se descarga cuando se exporta.
      const { downloadReportPdf } = await import("@/lib/pdf-generator");
      downloadReportPdf(report);
    } catch (err) {
      setError(errorMessage(err, "No se pudo generar el PDF."));
    } finally {
      setPdfBusy(false);
    }
  }, [report]);

  const counters: Partial<Record<ViewKey, number>> = result
    ? {
        dashboard: result.stats.totalEvents,
        findings: result.stats.totalFindings,
        risk: result.stats.totalIncidents,
        evidence: result.dataset.rowCount,
        report: 8,
      }
    : {};

  return (
    // reducedMotion="user": respeta prefers-reduced-motion en todas las animaciones JS.
    <MotionConfig reducedMotion="user">
    <div className="flex min-h-screen flex-col">
      <AppHeader
        result={result}
        aiBusy={aiBusy}
        onRunAi={handleRunAi}
        onExportPdf={handleExportPdf}
        canExport={Boolean(report) && !pdfBusy}
      />

      <div className="flex flex-1 flex-col md:flex-row">
        <SideNav active={view} onSelect={setView} enabled={Boolean(result)} counters={counters} />

        <main className="min-w-0 flex-1 space-y-6 p-5 md:p-7">
          {error && view !== "ingest" ? (
            <Notice tone="CRITICAL" title="Error">
              {error}
            </Notice>
          ) : null}

          {view === "ingest" ? (
            <IngestView processing={processing} error={error} dataset={dataset} onFile={handleFile} />
          ) : null}
          {view === "dashboard" && result ? <DashboardView result={result} /> : null}
          {view === "findings" && result ? <FindingsView findings={result.findings} /> : null}
          {view === "risk" && result && report ? <RiskView result={result} report={report} /> : null}
          {view === "evidence" && dataset && result ? <TelemetryView dataset={dataset} result={result} /> : null}
          {view === "report" && report ? (
            <ReportView
              report={report}
              aiBusy={aiBusy}
              pdfBusy={pdfBusy}
              onRunAi={handleRunAi}
              onExportPdf={handleExportPdf}
            />
          ) : null}
        </main>
      </div>

      <StatusBar result={result} />
    </div>
    </MotionConfig>
  );
}

// ===========================================================================
// 01 · Ingesta
// ===========================================================================

function IngestView({
  processing,
  error,
  dataset,
  onFile,
}: {
  processing: boolean;
  error: string | null;
  dataset: ParsedDataset | null;
  onFile: (file: File) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && !processing) onFile(file);
  };

  const summary = dataset?.summary;

  return (
    <div className="rise mx-auto max-w-5xl space-y-6">
      <ViewHeader
        step="01 · Ingesta"
        title="Carga de telemetria SIEM"
        description="Importe los registros exportados del SIEM (Excel, CSV, JSON o JSON Lines de Splunk / Elastic / Wazuh). El fichero se procesa integramente en su navegador."
      />

      <div
        role="button"
        tabIndex={0}
        aria-label="Seleccionar fichero de telemetria"
        onClick={() => !processing && inputRef.current?.click()}
        onKeyDown={(e) => {
          if ((e.key === "Enter" || e.key === " ") && !processing) {
            e.preventDefault();
            inputRef.current?.click();
          }
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={cn(
          "glass relative cursor-pointer overflow-hidden rounded-2xl border-2 border-dashed px-6 py-14 text-center transition-all duration-200",
          dragging ? "border-med/60 bg-med/5" : "hover:border-med/40",
          processing && "cursor-wait",
        )}
      >
        <input
          ref={inputRef}
          type="file"
          accept={ALLOWED_EXTENSIONS.join(",")}
          className="hidden"
          disabled={processing}
          onChange={(e) => {
            const file = e.target.files?.[0];
            // Reiniciamos el valor para poder recargar el mismo fichero.
            e.target.value = "";
            if (file) onFile(file);
          }}
        />
        {processing ? (
          <span className="scan-sweep pointer-events-none absolute inset-y-0 left-0 w-1/4 bg-gradient-to-r from-transparent via-med/10 to-transparent" />
        ) : null}
        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full border border-med/30 bg-med/10 text-med">
          {processing ? <Loader2 size={26} className="animate-spin" /> : <Upload size={26} />}
        </div>
        <p className="text-base font-semibold text-ink">
          {processing ? "Normalizando y correlacionando eventos…" : "Arrastre aqui el fichero de logs o haga clic para seleccionarlo"}
        </p>
        <p className="mt-2 text-xs text-dim">
          Formatos: <Mono className="text-ink">{ALLOWED_EXTENSIONS.join("  ")}</Mono> · Maximo 15 MB
        </p>
      </div>

      {error ? (
        <Notice tone="CRITICAL" title="No se pudo procesar el fichero">
          {error}
        </Notice>
      ) : null}

      {summary ? (
        <Panel>
          <PanelHeader
            title="Dataset cargado"
            subtitle={`${summary.sheetName} · ${formatBytes(summary.fileSizeBytes)}`}
            icon={<FileSpreadsheet size={16} />}
          />
          <div className="grid gap-4 p-5 sm:grid-cols-2 lg:grid-cols-4">
            <KeyValue label="Fichero" value={summary.fileName} mono />
            <KeyValue label="Registros" value={summary.rowCount.toLocaleString("es-ES")} mono />
            <KeyValue label="Primer evento" value={`${formatTimestamp(summary.firstEventAt)} UTC`} mono />
            <KeyValue label="Ultimo evento" value={`${formatTimestamp(summary.lastEventAt)} UTC`} mono />
          </div>
          <div className="space-y-3 border-t border-hairline p-5">
            <p className="text-[11px] font-medium uppercase tracking-wider text-steel">Columnas reconocidas</p>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(summary.mappedColumns).map(([field, header]) => (
                <Chip key={field} tone="cyan" mono>
                  {field} ← {header}
                </Chip>
              ))}
            </div>
            {summary.unmappedColumns.length > 0 ? (
              <>
                <p className="pt-2 text-[11px] font-medium uppercase tracking-wider text-steel">
                  Columnas conservadas sin mapear ({summary.unmappedColumns.length})
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {summary.unmappedColumns.slice(0, 40).map((col) => (
                    <Chip key={col} mono>
                      {col}
                    </Chip>
                  ))}
                </div>
              </>
            ) : null}
          </div>
          {summary.warnings.length > 0 ? (
            <div className="space-y-2 border-t border-hairline p-5">
              {summary.warnings.map((w) => (
                <Notice key={w} tone="HIGH" title="Aviso del parser">
                  {w}
                </Notice>
              ))}
            </div>
          ) : null}
        </Panel>
      ) : null}
    </div>
  );
}

// ===========================================================================
// 02 · Dashboard
// ===========================================================================

function DashboardView({ result }: { result: AnalysisResult }) {
  const { stats, findings } = result;

  const categoryData = useMemo(() => {
    const keys = Object.keys(CATEGORY_LABEL) as DetectionCategory[];
    return keys.map((key) => {
      const inCat = findings.filter((f) => f.category === key);
      const worst = inCat.reduce<Severity | null>(
        (acc, f) => (acc === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[acc] ? f.severity : acc),
        null,
      );
      return { label: CATEGORY_LABEL[key], count: stats.byCategory[key], worst };
    });
  }, [findings, stats.byCategory]);

  return (
    <Stagger className="space-y-6">
      <StaggerItem>
        <ViewHeader
          step="02 · Dashboard"
          title="Panorama del incidente"
          description="Volumen analizado, distribucion por criticidad, cronologia de la actividad y entidades con mayor exposicion."
        />
      </StaggerItem>

      <Stagger nested className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <StaggerItem>
          <StatTile
            className="h-full"
            label="Eventos analizados"
            value={stats.totalEvents.toLocaleString("es-ES")}
            hint={`${stats.flaggedEvents.toLocaleString("es-ES")} marcados como relevantes`}
            icon={<Database size={16} />}
          />
        </StaggerItem>
        <StaggerItem>
          <StatTile
            className="h-full"
            label="Criticos"
            value={stats.bySeverity.CRITICAL}
            hint="Requieren contencion inmediata"
            tone="CRITICAL"
            icon={<Siren size={16} />}
          />
        </StaggerItem>
        <StaggerItem>
          <StatTile className="h-full" label="Altos" value={stats.bySeverity.HIGH} hint="Investigacion priorizada" tone="HIGH" icon={<AlertTriangle size={16} />} />
        </StaggerItem>
        <StaggerItem>
          <StatTile
            className="h-full"
            label="Incidentes"
            value={stats.totalIncidents}
            hint={`${stats.totalFindings} hallazgos correlacionados`}
            tone="MEDIUM"
            icon={<Crosshair size={16} />}
          />
        </StaggerItem>
        <StaggerItem>
          <Panel interactive className={cn("h-full p-4", stats.globalSeverity === "CRITICAL" && "glow-crit")}>
            <p className="mb-3 text-[11px] font-medium uppercase tracking-wider text-steel">Riesgo global</p>
            <RiskMeter score={stats.globalRiskScore} severity={stats.globalSeverity} />
          </Panel>
        </StaggerItem>
      </Stagger>

      <Stagger nested className="grid gap-6 lg:grid-cols-3">
        <StaggerItem>
          <SeverityDonut bySeverity={stats.bySeverity} />
        </StaggerItem>
        <StaggerItem className="lg:col-span-2">
          <EventTimeline buckets={stats.timeline} />
        </StaggerItem>
      </Stagger>

      <StaggerItem>
        <CategoryBreakdown data={categoryData} />
      </StaggerItem>

      <Stagger nested className="grid gap-6 lg:grid-cols-2">
        <StaggerItem>
          <EntityRanking title="Equipos con mas actividad" subtitle="Hosts por volumen de eventos" buckets={stats.topHosts} />
        </StaggerItem>
        <StaggerItem>
          <EntityRanking
            title="IPs de origen"
            subtitle="Direcciones con mayor numero de conexiones"
            buckets={stats.topSourceIps}
            unitLabel="conexiones"
          />
        </StaggerItem>
        <StaggerItem>
          <EntityRanking title="Cuentas de usuario" subtitle="Cuentas con mas eventos asociados" buckets={stats.topUsers} />
        </StaggerItem>
        <StaggerItem>
          <EntityRanking title="Event IDs" subtitle="Identificadores de evento mas frecuentes" buckets={stats.topEventIds} />
        </StaggerItem>
      </Stagger>
    </Stagger>
  );
}

// ===========================================================================
// 03 · Detecciones
// ===========================================================================

function FindingsView({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState<Severity | "ALL">("ALL");
  const [open, setOpen] = useState<Set<string>>(() => new Set(findings.slice(0, 1).map((f) => f.id)));

  const visible = filter === "ALL" ? findings : findings.filter((f) => f.severity === filter);

  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <div className="rise space-y-6">
      <ViewHeader
        step="03 · Detecciones"
        title="Hallazgos correlacionados"
        description="Cada hallazgo cita los registros que lo sustentan y su mapeo a MITRE ATT&CK. Despliegue una tarjeta para ver la explicacion tecnica y la evidencia."
        action={
          <div className="flex flex-wrap gap-1.5">
            {(["ALL", ...SEVERITY_ORDER] as const).map((s) => (
              <Button key={s} variant={filter === s ? "primary" : "ghost"} onClick={() => setFilter(s)}>
                {s === "ALL"
                  ? `Todos (${findings.length})`
                  : `${SEVERITY_LABEL_ES[s]} (${findings.filter((f) => f.severity === s).length})`}
              </Button>
            ))}
          </div>
        }
      />

      {visible.length === 0 ? (
        <Panel>
          <EmptyState
            icon={<ShieldAlert size={28} />}
            title="Sin hallazgos para este filtro"
            description="El motor de correlacion no ha generado hallazgos con esta criticidad en el dataset cargado."
          />
        </Panel>
      ) : (
        <div className="space-y-4">
          {visible.map((f) => (
            <FindingCard key={f.id} finding={f} expanded={open.has(f.id)} onToggle={() => toggle(f.id)} />
          ))}
        </div>
      )}
    </div>
  );
}

function FindingCard({ finding, expanded, onToggle }: { finding: Finding; expanded: boolean; onToggle: () => void }) {
  return (
    <Panel className={cn("overflow-hidden", finding.severity === "CRITICAL" && "border-crit/30")}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        className="flex w-full items-start gap-4 px-5 py-4 text-left transition-colors hover:bg-white/[0.02]"
      >
        <span className="mt-1 text-steel">{expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Mono className="text-steel">{finding.id}</Mono>
            <SeverityBadge severity={finding.severity} size="sm" />
            <Chip>{CATEGORY_LABEL[finding.category]}</Chip>
            <Chip>{finding.killChainPhase}</Chip>
          </div>
          <h3 className="mt-2 text-sm font-semibold text-ink">{finding.title}</h3>
          <p className="mt-1 text-xs leading-relaxed text-dim">{finding.summary}</p>
        </div>
        <div className="hidden shrink-0 text-right sm:block">
          <p className="text-[10px] uppercase tracking-wider text-steel">Riesgo</p>
          <Mono className="text-base font-bold text-ink">{finding.riskScore}</Mono>
          <p className="mt-1 text-[10px] text-steel">Confianza {finding.confidence}</p>
        </div>
      </button>

      {expanded ? (
        <div className="space-y-5 border-t border-hairline px-5 py-5">
          <div className="grid gap-4 sm:grid-cols-4">
            <KeyValue label="Eventos" value={finding.evidenceCount.toLocaleString("es-ES")} mono />
            <KeyValue label="Primera vez" value={formatTimestamp(finding.firstSeen)} mono />
            <KeyValue label="Ultima vez" value={formatTimestamp(finding.lastSeen)} mono />
            <KeyValue label="Regla" value={finding.rule} mono />
          </div>

          <div>
            <Label>Explicacion tecnica</Label>
            <Paragraphs text={finding.technicalExplanation} />
          </div>

          <div className="flex flex-wrap gap-1.5">
            {finding.mitre.map((m) => (
              <Chip key={`${m.techniqueId}-${m.tactic}`} tone="cyan" mono>
                {m.techniqueId} · {m.technique}
              </Chip>
            ))}
          </div>

          <EntityChips entities={finding.entities} />

          <div>
            <Label>
              Evidencias en los logs ({finding.evidence.length} de {finding.evidenceCount})
            </Label>
            <EvidenceTable rows={finding.evidence} />
          </div>
        </div>
      ) : null}
    </Panel>
  );
}

function EntityChips({ entities }: { entities: Finding["entities"] }) {
  const groups: { label: string; values: string[] }[] = [
    { label: "Hosts", values: entities.hosts },
    { label: "Cuentas", values: entities.users },
    { label: "IPs", values: entities.ips.filter(Boolean) },
  ];
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      {groups.map((g) => (
        <div key={g.label}>
          <Label>{g.label}</Label>
          <div className="flex flex-wrap gap-1.5">
            {g.values.length ? g.values.slice(0, 12).map((v) => <Chip key={v} mono>{v}</Chip>) : <span className="text-xs text-steel">—</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

function EvidenceTable<T extends Evidence>({ rows, extra }: { rows: T[]; extra?: (row: T) => ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-hairline bg-canvas/60">
      <table className="w-full text-left text-[12px]">
        <thead className="border-b border-hairline text-[10px] uppercase tracking-wider text-steel">
          <tr>
            {extra ? <th className="px-3 py-2 font-medium">Hallazgo</th> : null}
            <th className="px-3 py-2 font-medium">Log_ID</th>
            <th className="px-3 py-2 font-medium">Timestamp</th>
            <th className="px-3 py-2 font-medium">EventID</th>
            <th className="px-3 py-2 font-medium">Host</th>
            <th className="px-3 py-2 font-medium">Usuario</th>
            <th className="px-3 py-2 font-medium">IP</th>
            <th className="px-3 py-2 font-medium">Detalle</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-hairline font-mono">
          {rows.map((e, i) => (
            <tr key={`${e.logId}-${i}`} className="align-top hover:bg-white/[0.02]">
              {extra ? <td className="px-3 py-2">{extra(e)}</td> : null}
              <td className="whitespace-nowrap px-3 py-2 font-semibold text-high">{e.logId}</td>
              <td className="whitespace-nowrap px-3 py-2 text-dim">{formatTimestamp(e.timestamp)}</td>
              <td className="px-3 py-2 text-ink">{e.eventId || "—"}</td>
              <td className="whitespace-nowrap px-3 py-2 text-low">{e.host || "—"}</td>
              <td className="whitespace-nowrap px-3 py-2 text-med">{e.user || "—"}</td>
              <td className="whitespace-nowrap px-3 py-2 text-dim">{e.ip || "—"}</td>
              <td className="min-w-[18rem] max-w-xl break-all px-3 py-2 text-ink">{e.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ===========================================================================
// 04 · Riesgos
// ===========================================================================

function RiskView({ result, report }: { result: AnalysisResult; report: TechnicalReport }) {
  const byRisk = useMemo(() => [...result.findings].sort((a, b) => b.riskScore - a.riskScore), [result.findings]);

  return (
    <div className="rise space-y-6">
      <ViewHeader
        step="04 · Riesgos"
        title="Clasificacion de riesgos"
        description="Criticidad de cada hallazgo (Critico, Alto, Medio o Bajo) con su justificacion, incidentes correlacionados e impacto potencial en la organizacion."
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <Panel className="p-5">
          <p className="mb-3 text-[11px] font-medium uppercase tracking-wider text-steel">Riesgo global del dataset</p>
          <RiskMeter score={result.stats.globalRiskScore} severity={result.stats.globalSeverity} />
          <p className="mt-4 text-xs leading-relaxed text-dim">{report.executiveSummary.verdict}</p>
        </Panel>

        <div className="space-y-4 lg:col-span-2">
          {result.incidents.length === 0 ? (
            <Panel>
              <EmptyState title="Sin incidentes correlacionados" description="Los hallazgos no comparten entidades suficientes para agruparse en un incidente." />
            </Panel>
          ) : (
            result.incidents.map((inc) => (
              <Panel key={inc.id} className={cn("p-5", inc.severity === "CRITICAL" && "glow-crit border-crit/30")}>
                <div className="flex flex-wrap items-center gap-2">
                  <Mono className="text-steel">{inc.id}</Mono>
                  <SeverityBadge severity={inc.severity} size="sm" />
                  <Mono className="text-dim">riesgo {inc.riskScore}/100</Mono>
                </div>
                <h3 className="mt-2 text-sm font-semibold text-ink">{inc.title}</h3>
                <p className="mt-2 text-xs leading-relaxed text-dim">{inc.narrative}</p>
                <div className="mt-3 flex flex-wrap items-center gap-1.5">
                  {inc.phases.map((p, i) => (
                    <span key={p} className="inline-flex items-center gap-1.5">
                      {i > 0 ? <ChevronRight size={12} className="text-steel" /> : null}
                      <Chip tone="cyan">{p}</Chip>
                    </span>
                  ))}
                </div>
                <p className="mt-3 text-[11px] text-steel">
                  Hallazgos: <Mono className="text-dim">{inc.findingIds.join(", ")}</Mono> · Ventana:{" "}
                  <Mono className="text-dim">
                    {formatTimestamp(inc.firstSeen)} → {formatTimestamp(inc.lastSeen)}
                  </Mono>
                </p>
              </Panel>
            ))
          )}
        </div>
      </div>

      <Panel>
        <PanelHeader title="Criticidad y justificacion por hallazgo" subtitle="Ordenado por puntuacion de riesgo" icon={<Gauge size={16} />} />
        <div className="divide-y divide-hairline">
          {byRisk.map((f) => (
            <div key={f.id} className="grid gap-3 px-5 py-4 md:grid-cols-[14rem_1fr]">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <Mono className="text-steel">{f.id}</Mono>
                  <SeverityBadge severity={f.severity} size="sm" />
                </div>
                <p className="text-xs font-semibold text-ink">{f.title}</p>
                <Mono className="text-dim">
                  riesgo {f.riskScore}/100 · confianza {f.confidence}
                </Mono>
              </div>
              <div className="space-y-2 text-xs leading-relaxed text-dim">
                <p>
                  <span className="font-semibold text-ink">Justificacion: </span>
                  {f.justification}
                </p>
                <p>
                  <span className="font-semibold text-ink">Impacto: </span>
                  {f.impact}
                </p>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <ImpactGrid report={report} />
    </div>
  );
}

function ImpactGrid({ report }: { report: TechnicalReport }) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {report.impact.map((row) => (
        <Panel key={row.dimension} interactive className="p-5">
          <div className="flex items-center justify-between gap-2">
            <h4 className="text-sm font-semibold text-ink">{row.dimension}</h4>
            <SeverityBadge severity={row.severity} size="sm" />
          </div>
          <p className="mt-2 text-xs leading-relaxed text-dim">{row.description}</p>
        </Panel>
      ))}
    </div>
  );
}

// ===========================================================================
// 05 · Telemetria
// ===========================================================================

function TelemetryView({ dataset, result }: { dataset: ParsedDataset; result: AnalysisResult }) {
  const [query, setQuery] = useState("");
  const [onlyFlagged, setOnlyFlagged] = useState(true);

  /** Log_ID -> hallazgos que lo citan, para resaltar la evidencia. */
  const citedBy = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of result.findings) {
      for (const e of f.evidence) {
        const list = map.get(e.logId) ?? [];
        if (!list.includes(f)) list.push(f);
        map.set(e.logId, list);
      }
    }
    return map;
  }, [result.findings]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return dataset.events.filter((e) => {
      if (onlyFlagged && !citedBy.has(e.logId)) return false;
      if (!q) return true;
      return [e.logId, e.eventId, e.host, e.user, e.sourceIp, e.destIp, e.process, e.commandLine, e.target, e.message]
        .some((field) => field.toLowerCase().includes(q));
    });
  }, [dataset.events, citedBy, onlyFlagged, query]);

  const shown = filtered.slice(0, MAX_TABLE_ROWS);

  return (
    <div className="rise space-y-6">
      <ViewHeader
        step="05 · Telemetria"
        title="Explorador de registros"
        description="Registros normalizados del dataset. Por defecto se muestran solo los citados como evidencia por algun hallazgo."
      />

      <div className="flex flex-wrap items-center gap-3">
        <label className="glass flex min-w-[16rem] flex-1 items-center gap-2 rounded-lg px-3 py-2">
          <Search size={14} className="text-steel" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Buscar Log_ID, host, usuario, IP, comando…"
            className="w-full bg-transparent font-mono text-xs text-ink placeholder:text-steel focus:outline-none"
          />
        </label>
        <Button variant={onlyFlagged ? "primary" : "ghost"} onClick={() => setOnlyFlagged((v) => !v)}>
          <Fingerprint size={14} />
          {onlyFlagged ? "Solo evidencia" : "Todos los registros"}
        </Button>
        <Mono className="text-steel">
          {filtered.length.toLocaleString("es-ES")} / {dataset.events.length.toLocaleString("es-ES")} registros
        </Mono>
      </div>

      <Panel className="overflow-hidden">
        {shown.length === 0 ? (
          <EmptyState icon={<Search size={26} />} title="Sin coincidencias" description="Ningun registro coincide con el filtro actual." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead className="border-b border-hairline text-[10px] uppercase tracking-wider text-steel">
                <tr>
                  <th className="px-3 py-2.5 font-medium">Log_ID</th>
                  <th className="px-3 py-2.5 font-medium">Timestamp</th>
                  <th className="px-3 py-2.5 font-medium">EventID</th>
                  <th className="px-3 py-2.5 font-medium">Host</th>
                  <th className="px-3 py-2.5 font-medium">Usuario</th>
                  <th className="px-3 py-2.5 font-medium">IP origen</th>
                  <th className="px-3 py-2.5 font-medium">Comando / detalle</th>
                  <th className="px-3 py-2.5 font-medium">Hallazgos</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline font-mono">
                {shown.map((e) => (
                  <TelemetryRow key={e.rowIndex} event={e} findings={citedBy.get(e.logId)} />
                ))}
              </tbody>
            </table>
          </div>
        )}
        {filtered.length > shown.length ? (
          <p className="border-t border-hairline px-4 py-2.5 text-[11px] text-steel">
            Mostrando los primeros {MAX_TABLE_ROWS} registros. Refine la busqueda para acotar el resultado.
          </p>
        ) : null}
      </Panel>
    </div>
  );
}

function TelemetryRow({ event: e, findings }: { event: LogEvent; findings: Finding[] | undefined }) {
  const worst = findings?.reduce<Severity | null>(
    (acc, f) => (acc === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[acc] ? f.severity : acc),
    null,
  );
  const detail = e.commandLine || e.target || e.process || e.message || e.action;
  return (
    <tr className={cn("align-top hover:bg-white/[0.02]", worst === "CRITICAL" && "bg-crit/[0.04]")}>
      <td className="whitespace-nowrap px-3 py-2 font-semibold text-high">{e.logId}</td>
      <td className="whitespace-nowrap px-3 py-2 text-dim">{e.timestamp ? formatTimestamp(e.timestamp) : e.rawTimestamp || "—"}</td>
      <td className="px-3 py-2 text-ink">{e.eventId || "—"}</td>
      <td className="whitespace-nowrap px-3 py-2 text-low">{e.host || "—"}</td>
      <td className="whitespace-nowrap px-3 py-2 text-med">{e.user || "—"}</td>
      <td className="whitespace-nowrap px-3 py-2 text-dim">{e.sourceIp || "—"}</td>
      <td className="min-w-[18rem] max-w-xl break-all px-3 py-2 text-ink">{detail || "—"}</td>
      <td className="whitespace-nowrap px-3 py-2">
        {findings?.length ? (
          <span className="flex flex-wrap gap-1">
            {findings.map((f) => (
              <span key={f.id} title={f.title}>
                <SeverityBadge severity={f.severity} size="sm" />
              </span>
            ))}
          </span>
        ) : (
          <span className="text-steel">—</span>
        )}
      </td>
    </tr>
  );
}

// ===========================================================================
// 06 · Informe (8 secciones)
// ===========================================================================

function ReportView({
  report,
  aiBusy,
  pdfBusy,
  onRunAi,
  onExportPdf,
}: {
  report: TechnicalReport;
  aiBusy: boolean;
  pdfBusy: boolean;
  onRunAi: () => void;
  onExportPdf: () => void;
}) {
  const { meta, executiveSummary, findings, evidenceLog, actionPlan, recommendations, ai } = report;
  const mitre = useMemo(() => mitreCoverage(findings), [findings]);
  const evidenceShown = evidenceLog.slice(0, MAX_TABLE_ROWS);

  return (
    <div className="rise space-y-6">
      <ViewHeader
        step="06 · Informe"
        title="Informe tecnico de incidente"
        description="Vista previa del documento que se exporta a PDF: mismo modelo de datos, 8 secciones obligatorias."
        action={
          <div className="flex gap-2">
            <Button onClick={onRunAi} disabled={aiBusy}>
              {aiBusy ? <Loader2 size={14} className="animate-spin" /> : <Bot size={14} />}
              {ai ? "Regenerar sintesis IA" : "Sintesis IA"}
            </Button>
            <Button variant="primary" onClick={onExportPdf} disabled={pdfBusy}>
              {pdfBusy ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
              Descargar PDF
            </Button>
          </div>
        }
      />

      <Panel className="p-6">
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-crit">{meta.classification}</p>
        <h2 className="mt-2 text-lg font-bold text-ink">{meta.title}</h2>
        <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <KeyValue label="Cliente" value={meta.client} />
          <KeyValue label="Autor" value={meta.author} />
          <KeyValue label="Dataset" value={`${meta.datasetName} (${meta.eventCount.toLocaleString("es-ES")} registros)`} mono />
          <KeyValue label="Periodo" value={meta.period} mono />
        </div>
      </Panel>

      {/* 1. Resumen ejecutivo */}
      <ReportSection number={1} title="Resumen ejecutivo">
        <div className="rounded-lg border border-crit/30 bg-crit/[0.06] p-4">
          <p className="text-sm font-semibold leading-relaxed text-ink">{executiveSummary.verdict}</p>
        </div>
        <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
          {executiveSummary.kpis.map((k) => (
            <div key={k.label} className="rounded-lg border border-hairline bg-canvas/60 p-3">
              <p className="text-[10px] uppercase tracking-wider text-steel">{k.label}</p>
              <Mono className="mt-1 block text-base font-bold text-ink">{k.value}</Mono>
              {k.hint ? <p className="mt-0.5 truncate text-[11px] text-dim" title={k.hint}>{k.hint}</p> : null}
            </div>
          ))}
        </div>
        {executiveSummary.paragraphs.map((p, i) => (
          <p key={i} className="text-sm leading-relaxed text-dim">
            {p}
          </p>
        ))}
        {ai ? <AiNarrativeBlock ai={ai} /> : null}
      </ReportSection>

      {/* 2. Hallazgos identificados */}
      <ReportSection number={2} title="Hallazgos identificados" description="Con su mapeo a tacticas y tecnicas MITRE ATT&CK.">
        <div className="overflow-x-auto rounded-lg border border-hairline">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-hairline text-[10px] uppercase tracking-wider text-steel">
              <tr>
                <th className="px-3 py-2 font-medium">ID</th>
                <th className="px-3 py-2 font-medium">Hallazgo</th>
                <th className="px-3 py-2 font-medium">Criticidad</th>
                <th className="px-3 py-2 font-medium">Fase</th>
                <th className="px-3 py-2 font-medium">MITRE ATT&CK</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline">
              {findings.map((f) => (
                <tr key={f.id} className="align-top">
                  <td className="px-3 py-2"><Mono className="text-steel">{f.id}</Mono></td>
                  <td className="px-3 py-2 text-ink">{f.title}</td>
                  <td className="px-3 py-2"><SeverityBadge severity={f.severity} size="sm" /></td>
                  <td className="px-3 py-2 text-dim">{f.killChainPhase}</td>
                  <td className="px-3 py-2"><Mono className="text-med">{f.mitre.map((m) => m.techniqueId).join(", ")}</Mono></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {mitre.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {mitre.map((m) => (
              <Chip key={m.id} tone="cyan" mono>
                {m.id} · {m.name} ({m.tactic})
              </Chip>
            ))}
          </div>
        ) : null}
      </ReportSection>

      {/* 3. Explicacion tecnica */}
      <ReportSection number={3} title="Explicacion tecnica de cada hallazgo">
        {findings.map((f) => (
          <div key={f.id} className="space-y-2 rounded-lg border border-hairline bg-canvas/40 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <Mono className="text-steel">{f.id}</Mono>
              <SeverityBadge severity={f.severity} size="sm" />
              <h4 className="text-sm font-semibold text-ink">{f.title}</h4>
            </div>
            <p className="text-[11px] text-steel">
              {CATEGORY_LABEL[f.category]} — {CATEGORY_DESCRIPTION[f.category]}
            </p>
            <Paragraphs text={f.technicalExplanation} />
          </div>
        ))}
      </ReportSection>

      {/* 4. Evidencias */}
      <ReportSection
        number={4}
        title="Evidencias encontradas en los logs"
        description={`${evidenceLog.length} registros citados, ordenados cronologicamente.`}
      >
        <EvidenceTable
          rows={evidenceShown}
          extra={(row) => (
            <span className="flex items-center gap-1.5 whitespace-nowrap">
              <Mono className="text-steel">{row.findingId}</Mono>
              <SeverityBadge severity={row.severity} size="sm" />
            </span>
          )}
        />
        {evidenceLog.length > evidenceShown.length ? (
          <p className="text-[11px] text-steel">
            Vista previa limitada a {MAX_TABLE_ROWS} filas; el PDF incluye la tabla completa.
          </p>
        ) : null}
      </ReportSection>

      {/* 5. Criticidad y justificacion */}
      <ReportSection number={5} title="Criticidad y justificacion">
        {findings.map((f) => (
          <div key={f.id} className="flex flex-col gap-2 border-b border-hairline pb-3 last:border-0 last:pb-0 md:flex-row md:gap-4">
            <div className="flex shrink-0 items-start gap-2 md:w-56">
              <Mono className="text-steel">{f.id}</Mono>
              <SeverityBadge severity={f.severity} size="sm" />
              <Mono className="text-dim">{f.riskScore}/100</Mono>
            </div>
            <p className="text-xs leading-relaxed text-dim">{f.justification}</p>
          </div>
        ))}
      </ReportSection>

      {/* 6. Impacto */}
      <ReportSection number={6} title="Posible impacto en la organizacion">
        <ImpactGrid report={report} />
      </ReportSection>

      {/* 7. Plan de accion */}
      <ReportSection number={7} title="Plan de accion" description="Investigar, contener y remediar, priorizado por criticidad.">
        <div className="grid gap-4 xl:grid-cols-3">
          <ActionColumn title="Investigar" steps={actionPlan.investigate} />
          <ActionColumn title="Contener" steps={actionPlan.contain} />
          <ActionColumn title="Remediar" steps={actionPlan.remediate} />
        </div>
      </ReportSection>

      {/* 8. Recomendaciones */}
      <ReportSection number={8} title="Recomendaciones generales de seguridad">
        <div className="grid gap-4 md:grid-cols-2">
          {recommendations.map((block) => (
            <div key={block.area} className="rounded-lg border border-hairline bg-canvas/40 p-4">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-med">{block.area}</h4>
              <ul className="mt-2 list-disc space-y-1.5 pl-4 text-xs leading-relaxed text-dim marker:text-steel">
                {block.items.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </ReportSection>

      <div className="flex justify-center pb-4">
        <Button variant="primary" onClick={onExportPdf} disabled={pdfBusy} className="px-6 py-3 text-sm">
          {pdfBusy ? <Loader2 size={16} className="animate-spin" /> : <Download size={16} />}
          Descargar informe tecnico en PDF (8 secciones)
        </Button>
      </div>
    </div>
  );
}

function AiNarrativeBlock({ ai }: { ai: AiNarrative }) {
  const story = ai.attackStory.split(/\n{2,}/).map((p) => p.trim()).filter(Boolean);
  return (
    <div className="space-y-3 rounded-lg border border-med/30 bg-med/[0.05] p-4">
      <div className="flex flex-wrap items-center gap-2">
        <Bot size={15} className="text-med" />
        <p className="text-xs font-semibold uppercase tracking-wider text-med">
          Sintesis {ai.source === "ai" ? "asistida por IA" : "deterministica (offline)"}
        </p>
        {ai.model ? <Chip mono>{ai.model}</Chip> : null}
      </div>
      {ai.notice ? (
        <Notice tone="HIGH" title="Modo de respaldo">
          {ai.notice}
        </Notice>
      ) : null}
      <p className="text-sm leading-relaxed text-ink">{ai.executiveSummary}</p>
      {story.length > 0 ? (
        <div className="space-y-2">
          <Label>Reconstruccion del ataque</Label>
          {story.map((p, i) => (
            <p key={i} className="text-xs leading-relaxed text-dim">
              {p}
            </p>
          ))}
        </div>
      ) : null}
      {ai.priorityActions.length > 0 ? (
        <div>
          <Label>Acciones prioritarias</Label>
          <ol className="list-decimal space-y-1 pl-5 text-xs leading-relaxed text-dim marker:font-mono marker:text-med">
            {ai.priorityActions.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ol>
        </div>
      ) : null}
    </div>
  );
}

const PRIORITY_TONE: Record<ActionStep["priority"], Severity> = { P1: "CRITICAL", P2: "HIGH", P3: "MEDIUM" };

function ActionColumn({ title, steps }: { title: string; steps: ActionStep[] }) {
  return (
    <div className="rounded-lg border border-hairline bg-canvas/40 p-4">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-ink">
        {title} <span className="font-mono text-steel">({steps.length})</span>
      </h4>
      <ol className="mt-3 space-y-3">
        {steps.map((s) => (
          <li key={s.action} className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <Mono className={cn("font-bold", PRIORITY_TONE[s.priority] === "CRITICAL" ? "text-crit" : PRIORITY_TONE[s.priority] === "HIGH" ? "text-high" : "text-med")}>
                {s.priority}
              </Mono>
              <Mono className="text-steel">{s.window}</Mono>
              <span className="text-[10px] text-steel">· {s.owner}</span>
            </div>
            <p className="text-xs leading-relaxed text-dim">{s.action}</p>
          </li>
        ))}
      </ol>
    </div>
  );
}

function ReportSection({
  number,
  title,
  description,
  children,
}: {
  number: number;
  title: string;
  description?: string;
  children: ReactNode;
}) {
  return (
    <Panel className="space-y-4 p-6">
      <SectionTitle number={number} title={title} description={description} />
      {children}
    </Panel>
  );
}

// ===========================================================================
// Utilidades de presentacion
// ===========================================================================

function Label({ children }: { children: ReactNode }) {
  return <p className="mb-2 text-[11px] font-medium uppercase tracking-wider text-steel">{children}</p>;
}

function KeyValue({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="text-[10px] uppercase tracking-wider text-steel">{label}</p>
      {mono ? (
        <Mono className="mt-1 block truncate text-ink" title={value}>
          {value}
        </Mono>
      ) : (
        <p className="mt-1 truncate text-sm text-ink" title={value}>
          {value}
        </p>
      )}
    </div>
  );
}

/** Texto multiparrafo de los hallazgos, siempre como nodos de texto. */
function Paragraphs({ text }: { text: string }) {
  const parts = text.split(/\n{2,}/).map((p) => p.trim()).filter(Boolean);
  return (
    <div className="space-y-2">
      {parts.map((p, i) => (
        <p key={i} className="whitespace-pre-line text-xs leading-relaxed text-dim">
          {p}
        </p>
      ))}
    </div>
  );
}
