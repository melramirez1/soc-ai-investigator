"use client";

import {
  Activity,
  Download,
  FileText,
  LayoutDashboard,
  Loader2,
  Radar,
  ScrollText,
  ShieldAlert,
  Siren,
  Sparkles,
  Upload,
} from "lucide-react";
import { motion } from "framer-motion";
import type { ReactNode } from "react";

import { cn, formatTimestamp, SEVERITY_LABEL_ES } from "@/lib/utils";
import type { AnalysisResult } from "@/lib/types";
import { SPRING_SNAPPY, SPRING_TAB, TAP_SCALE } from "@/components/ui/motion";
import { Button, Mono, SEVERITY_TEXT } from "@/components/ui/primitives";

export type ViewKey = "ingest" | "dashboard" | "findings" | "risk" | "evidence" | "report";

export const VIEWS: { key: ViewKey; label: string; icon: typeof Upload; hint: string }[] = [
  { key: "ingest", label: "Ingesta", icon: Upload, hint: "Carga y validacion del Excel/CSV" },
  { key: "dashboard", label: "Dashboard", icon: LayoutDashboard, hint: "Estadisticas y graficos" },
  { key: "findings", label: "Detecciones", icon: Siren, hint: "Hallazgos correlacionados" },
  { key: "risk", label: "Riesgos", icon: Radar, hint: "Clasificacion y justificacion" },
  { key: "evidence", label: "Telemetria", icon: ScrollText, hint: "Explorador de registros" },
  { key: "report", label: "Informe", icon: FileText, hint: "Informe tecnico y PDF" },
];

/** Baliza roja pulsante del encabezado (SKILL 2). */
function LiveBeacon({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-crit/30 bg-crit/10 px-2.5 py-1">
      <span className="beacon h-1.5 w-1.5 rounded-full bg-crit" aria-hidden />
      <span className="text-[10px] font-bold uppercase tracking-[0.12em] text-crit">{label}</span>
    </span>
  );
}

export function AppHeader({
  result,
  aiBusy,
  onRunAi,
  onExportPdf,
  canExport,
}: {
  result: AnalysisResult | null;
  aiBusy: boolean;
  onRunAi: () => void;
  onExportPdf: () => void;
  canExport: boolean;
}) {
  return (
    <header className="sticky top-0 z-30 border-b border-hairline bg-canvas/85 backdrop-blur-xl">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-3">
        <div className="flex items-center gap-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-med/30 bg-med/10 text-med">
            <ShieldAlert size={18} strokeWidth={2} />
          </span>
          <div className="leading-tight">
            <p className="text-sm font-bold tracking-tight text-ink">
              SOC N2 <span className="text-steel">·</span> AI Investigator
            </p>
            <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-steel">
              Incident Response Console
            </p>
          </div>
        </div>

        <LiveBeacon label={result ? "Analisis activo" : "En espera"} />

        {result ? (
          <div className="hidden items-center gap-4 border-l border-hairline pl-4 lg:flex">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-steel">Dataset</p>
              <Mono className="text-ink">{result.dataset.fileName}</Mono>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-steel">Registros</p>
              <Mono className="text-ink">{result.stats.totalEvents.toLocaleString("es-ES")}</Mono>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-steel">Riesgo global</p>
              <Mono className={cn("font-bold", SEVERITY_TEXT[result.stats.globalSeverity])}>
                {result.stats.globalRiskScore}/100 · {SEVERITY_LABEL_ES[result.stats.globalSeverity]}
              </Mono>
            </div>
          </div>
        ) : null}

        <div className="ml-auto flex items-center gap-2">
          <Button onClick={onRunAi} disabled={!result || aiBusy} variant="ghost" title="Generar la sintesis asistida por IA">
            {aiBusy ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
            {aiBusy ? "Analizando…" : "Analisis IA"}
          </Button>
          <Button onClick={onExportPdf} disabled={!canExport} variant="primary" title="Descargar el informe tecnico en PDF">
            <Download size={14} />
            Exportar PDF
          </Button>
        </div>
      </div>
    </header>
  );
}

export function SideNav({
  active,
  onSelect,
  enabled,
  counters,
}: {
  active: ViewKey;
  onSelect: (view: ViewKey) => void;
  enabled: boolean;
  counters: Partial<Record<ViewKey, number>>;
}) {
  return (
    <nav aria-label="Navegacion principal" className="flex gap-1 overflow-x-auto p-3 md:w-52 md:shrink-0 md:flex-col md:overflow-visible md:border-r md:border-hairline">
      {VIEWS.map((view) => {
        const Icon = view.icon;
        const disabled = !enabled && view.key !== "ingest";
        const count = counters[view.key];
        const isActive = active === view.key;
        return (
          <motion.button
            key={view.key}
            type="button"
            disabled={disabled}
            onClick={() => onSelect(view.key)}
            aria-current={isActive ? "page" : undefined}
            title={view.hint}
            whileTap={disabled ? undefined : { scale: TAP_SCALE }}
            transition={SPRING_SNAPPY}
            className={cn(
              "group relative flex shrink-0 items-center gap-2.5 rounded-lg px-3 py-2 text-left text-xs font-semibold",
              "transition-colors duration-200",
              isActive ? "text-med" : "text-dim hover:bg-white/[0.03] hover:text-ink",
              disabled && "cursor-not-allowed opacity-35 hover:bg-transparent hover:text-dim",
            )}
          >
            {/* Pastilla compartida: se desliza entre opciones via layoutId. */}
            {isActive ? (
              <motion.span
                layoutId="activeTabIndicator"
                transition={SPRING_TAB}
                aria-hidden
                className="absolute inset-0 rounded-lg border border-med/35 bg-med/10 shadow-[0_0_18px_-6px_rgba(0,229,255,0.35),inset_0_1px_0_0_rgba(255,255,255,0.05)]"
              />
            ) : null}
            <Icon size={15} strokeWidth={2} className="relative shrink-0" />
            <span className="relative whitespace-nowrap">{view.label}</span>
            {count !== undefined && count > 0 ? (
              <span
                className={cn(
                  "relative ml-auto hidden rounded px-1.5 py-0.5 font-mono text-[10px] tabular-nums transition-colors duration-200 md:inline",
                  isActive ? "bg-med/15 text-med" : "bg-white/[0.07] text-dim",
                )}
              >
                {count}
              </span>
            ) : null}
          </motion.button>
        );
      })}
    </nav>
  );
}

export function ViewHeader({
  step,
  title,
  description,
  action,
}: {
  step: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 border-b border-hairline pb-5">
      <div>
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-med">{step}</p>
        <h1 className="mt-1.5 text-xl font-bold tracking-tight text-ink">{title}</h1>
        <p className="mt-1.5 max-w-3xl text-xs leading-relaxed text-dim">{description}</p>
      </div>
      {action}
    </div>
  );
}

export function StatusBar({ result }: { result: AnalysisResult | null }) {
  return (
    <footer className="border-t border-hairline px-5 py-2.5">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1 font-mono text-[10px] text-steel">
        <span className="inline-flex items-center gap-1.5">
          <Activity size={11} className="text-low" />
          Motor de correlacion operativo
        </span>
        {result ? (
          <>
            <span>
              Analisis: <span className="text-dim">{formatTimestamp(result.generatedAt)} UTC</span>
            </span>
            <span>
              Hallazgos: <span className="text-dim">{result.stats.totalFindings}</span>
            </span>
            <span>
              Incidentes: <span className="text-dim">{result.stats.totalIncidents}</span>
            </span>
          </>
        ) : (
          <span>Esperando dataset…</span>
        )}
        <span className="ml-auto">Procesamiento local en el navegador · los logs no se suben a ningun servidor</span>
      </div>
    </footer>
  );
}
