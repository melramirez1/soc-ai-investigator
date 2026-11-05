"use client";

/**
 * Primitivas de UI del design system (SKILL 2).
 *
 * Reglas que aplican a todo el proyecto:
 *  - Nunca se usa `dangerouslySetInnerHTML`: todo el texto procedente de logs se
 *    renderiza como nodo de texto y React lo escapa.
 *  - El color de severidad nunca va solo: siempre acompana a una etiqueta
 *    textual, para que la identidad no dependa de la vision del color.
 */

import { motion } from "framer-motion";
import type { ReactNode } from "react";

import { SPRING_SNAPPY, staggerContainer, staggerItem, TAP_SCALE } from "@/components/ui/motion";
import { cn, SEVERITY_LABEL_ES } from "@/lib/utils";
import type { Severity } from "@/lib/types";

// ---------------------------------------------------------------------------
// Tablas de clases por severidad (estaticas, para que Tailwind las detecte)
// ---------------------------------------------------------------------------

export const SEVERITY_TEXT: Record<Severity, string> = {
  CRITICAL: "text-crit",
  HIGH: "text-high",
  MEDIUM: "text-med",
  LOW: "text-low",
};

export const SEVERITY_BORDER: Record<Severity, string> = {
  CRITICAL: "border-crit/40",
  HIGH: "border-high/40",
  MEDIUM: "border-med/40",
  LOW: "border-low/40",
};

export const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: "bg-crit/10",
  HIGH: "bg-high/10",
  MEDIUM: "bg-med/10",
  LOW: "bg-low/10",
};

export const SEVERITY_SOLID: Record<Severity, string> = {
  CRITICAL: "bg-crit",
  HIGH: "bg-high",
  MEDIUM: "bg-med",
  LOW: "bg-low",
};

export const SEVERITY_GLOW: Record<Severity, string> = {
  CRITICAL: "glow-crit",
  HIGH: "glow-high",
  MEDIUM: "glow-med",
  LOW: "glow-low",
};

// ---------------------------------------------------------------------------
// Panel
// ---------------------------------------------------------------------------

export function Panel({
  children,
  className,
  interactive = false,
}: {
  children: ReactNode;
  className?: string;
  interactive?: boolean;
}) {
  // El desplazamiento en hover lo resuelve un resorte (framer-motion); el CSS
  // de `glass-hover` solo anima borde y resplandor para no competir por transform.
  return (
    <motion.div
      className={cn("glass rounded-xl", interactive && "glass-hover", className)}
      whileHover={interactive ? { y: -2 } : undefined}
      transition={SPRING_SNAPPY}
    >
      {children}
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Entrada escalonada
// ---------------------------------------------------------------------------

/**
 * Contenedor que orquesta la entrada escalonada de sus `StaggerItem`.
 * Con `nested` no dispara su propia animacion: hereda el estado de un `Stagger`
 * padre y escalona sus hijos cuando el padre le da el turno.
 */
export function Stagger({
  children,
  className,
  nested = false,
}: {
  children: ReactNode;
  className?: string;
  nested?: boolean;
}) {
  return (
    <motion.div
      className={className}
      variants={staggerContainer}
      initial={nested ? undefined : "hidden"}
      animate={nested ? undefined : "show"}
    >
      {children}
    </motion.div>
  );
}

/** Hijo de `Stagger`: hereda la orquestacion del contenedor por contexto. */
export function StaggerItem({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <motion.div className={className} variants={staggerItem}>
      {children}
    </motion.div>
  );
}

export function PanelHeader({
  title,
  subtitle,
  icon,
  action,
}: {
  title: string;
  subtitle?: string;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-hairline px-5 py-4">
      <div className="flex min-w-0 items-start gap-3">
        {icon ? <span className="mt-0.5 shrink-0 text-med">{icon}</span> : null}
        <div className="min-w-0">
          <h2 className="truncate text-sm font-semibold tracking-tight text-ink">{title}</h2>
          {subtitle ? <p className="mt-0.5 text-xs text-dim">{subtitle}</p> : null}
        </div>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Severidad
// ---------------------------------------------------------------------------

/** Etiqueta de severidad: color + texto siempre juntos (nunca color solo). */
export function SeverityBadge({
  severity,
  size = "md",
}: {
  severity: Severity;
  size?: "sm" | "md";
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border font-semibold uppercase tracking-wider",
        SEVERITY_TEXT[severity],
        SEVERITY_BORDER[severity],
        SEVERITY_BG[severity],
        size === "sm" ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-1 text-[11px]",
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", SEVERITY_SOLID[severity])} aria-hidden />
      {SEVERITY_LABEL_ES[severity]}
    </span>
  );
}

export function Chip({
  children,
  tone = "neutral",
  mono = false,
}: {
  children: ReactNode;
  tone?: "neutral" | "cyan";
  mono?: boolean;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-[11px]",
        mono && "font-mono",
        tone === "cyan"
          ? "border-med/30 bg-med/10 text-med"
          : "border-hairline bg-white/[0.03] text-dim",
      )}
    >
      {children}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Texto monoespaciado para telemetria
// ---------------------------------------------------------------------------

/** Log_IDs, IPs, timestamps, comandos: siempre monoespaciado (SKILL 2). */
export function Mono({
  children,
  className,
  title,
}: {
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span className={cn("font-mono text-[12px] tabular-nums", className)} title={title}>
      {children}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Tiles de cifras (hero numbers)
// ---------------------------------------------------------------------------

export function StatTile({
  label,
  value,
  hint,
  tone = "neutral",
  icon,
  className,
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: Severity | "neutral";
  icon?: ReactNode;
  className?: string;
}) {
  const accent = tone === "neutral" ? "text-ink" : SEVERITY_TEXT[tone];
  return (
    <Panel interactive className={cn("p-4", className)}>
      <div className="flex items-start justify-between gap-2">
        <p className="text-[11px] font-medium uppercase tracking-wider text-steel">{label}</p>
        {icon ? <span className={cn("shrink-0", tone === "neutral" ? "text-steel" : accent)}>{icon}</span> : null}
      </div>
      <p className={cn("mt-2 font-mono text-3xl font-bold leading-none tabular-nums", accent)}>{value}</p>
      {hint ? <p className="mt-2 text-xs text-dim">{hint}</p> : null}
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Medidor de riesgo
// ---------------------------------------------------------------------------

export function RiskMeter({ score, severity }: { score: number; severity: Severity }) {
  const clamped = Math.max(0, Math.min(100, score));
  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between">
        <span className={cn("font-mono text-2xl font-bold tabular-nums", SEVERITY_TEXT[severity])}>
          {clamped}
          <span className="text-sm text-steel">/100</span>
        </span>
        <SeverityBadge severity={severity} size="sm" />
      </div>
      <div
        className="h-2 w-full overflow-hidden rounded-full bg-white/[0.06]"
        role="meter"
        aria-valuenow={clamped}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Puntuacion de riesgo ${clamped} de 100, nivel ${SEVERITY_LABEL_ES[severity]}`}
      >
        <div
          className={cn("h-full rounded-full transition-[width] duration-700", SEVERITY_SOLID[severity])}
          style={{ width: `${clamped}%` }}
        />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Botones
// ---------------------------------------------------------------------------

export function Button({
  children,
  onClick,
  variant = "ghost",
  disabled = false,
  type = "button",
  className,
  title,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "ghost" | "danger";
  disabled?: boolean;
  type?: "button" | "submit";
  className?: string;
  title?: string;
}) {
  return (
    <motion.button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      whileTap={disabled ? undefined : { scale: TAP_SCALE }}
      transition={SPRING_SNAPPY}
      className={cn(
        // transform queda fuera de la transicion CSS: lo gobierna el resorte.
        "inline-flex items-center justify-center gap-2 rounded-lg border px-3.5 py-2 text-xs font-semibold",
        "transition-[color,background-color,border-color,box-shadow] duration-200",
        "disabled:cursor-not-allowed disabled:opacity-45",
        variant === "primary" &&
          "border-med/50 bg-med/15 text-med hover:bg-med/25 hover:shadow-[0_0_18px_rgba(0,229,255,0.22)]",
        variant === "danger" &&
          "border-crit/50 bg-crit/15 text-crit hover:bg-crit/25 hover:shadow-[0_0_18px_rgba(255,0,85,0.25)]",
        variant === "ghost" && "border-hairline bg-white/[0.02] text-dim hover:border-med/35 hover:text-ink",
        className,
      )}
    >
      {children}
    </motion.button>
  );
}

// ---------------------------------------------------------------------------
// Estados vacios y avisos
// ---------------------------------------------------------------------------

export function EmptyState({
  title,
  description,
  icon,
}: {
  title: string;
  description: string;
  icon?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      {icon ? <span className="text-steel">{icon}</span> : null}
      <p className="text-sm font-semibold text-ink">{title}</p>
      <p className="max-w-md text-xs leading-relaxed text-dim">{description}</p>
    </div>
  );
}

export function Notice({
  tone,
  title,
  children,
}: {
  tone: Severity | "info";
  title: string;
  children: ReactNode;
}) {
  const sev: Severity = tone === "info" ? "MEDIUM" : tone;
  return (
    <div className={cn("rounded-lg border px-4 py-3", SEVERITY_BORDER[sev], SEVERITY_BG[sev])}>
      <p className={cn("text-xs font-semibold uppercase tracking-wider", SEVERITY_TEXT[sev])}>{title}</p>
      <div className="mt-1.5 text-xs leading-relaxed text-dim">{children}</div>
    </div>
  );
}

/** Titulo de seccion dentro de una vista. */
export function SectionTitle({
  number,
  title,
  description,
}: {
  number?: number;
  title: string;
  description?: string;
}) {
  return (
    <div className="flex items-start gap-3">
      {number !== undefined ? (
        <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded border border-med/30 bg-med/10 font-mono text-[11px] font-bold text-med">
          {number}
        </span>
      ) : null}
      <div>
        <h3 className="text-sm font-semibold tracking-tight text-ink">{title}</h3>
        {description ? <p className="mt-1 text-xs leading-relaxed text-dim">{description}</p> : null}
      </div>
    </div>
  );
}
