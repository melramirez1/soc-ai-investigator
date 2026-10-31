"use client";

/**
 * Graficos del dashboard.
 *
 * Decisiones de visualizacion:
 *  - La severidad es una *paleta de estado*, no categorica: se usa unicamente
 *    para codificar criticidad y siempre acompanada de su etiqueta textual.
 *  - Las magnitudes puras (eventos por host, por IP, por categoria) usan una
 *    rampa secuencial de un solo tono, nunca colores categoricos arbitrarios.
 *  - Ningun grafico tiene doble eje Y.
 *  - Todos llevan tooltip al pasar el raton y una vista de tabla equivalente,
 *    para que la informacion no dependa de la percepcion del color.
 */

import { useId, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { cn, SEQUENTIAL_CYAN, SEVERITY_HEX, SEVERITY_LABEL_ES } from "@/lib/utils";
import type { CountBucket, Severity, TimelineBucket } from "@/lib/types";
import { Panel, PanelHeader } from "@/components/ui/primitives";

const GRID = "#1E293B";
const AXIS = "#64748B";

interface TooltipRow {
  name?: string | number;
  value?: number | string;
  color?: string;
  dataKey?: string | number;
}

/** Tooltip oscuro consistente en todos los graficos. */
function ChartTooltip({
  active,
  payload,
  label,
  unit = "eventos",
}: {
  active?: boolean;
  payload?: TooltipRow[];
  label?: string | number;
  unit?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-hairline bg-[#0E131F]/95 px-3 py-2 shadow-xl backdrop-blur">
      {label !== undefined && label !== "" ? (
        <p className="mb-1.5 font-mono text-[11px] text-dim">{String(label)}</p>
      ) : null}
      <ul className="space-y-1">
        {payload.map((row, i) => (
          <li key={`${row.dataKey ?? i}`} className="flex items-center gap-2 text-xs">
            <span
              className="h-2 w-2 shrink-0 rounded-sm"
              style={{ background: row.color ?? AXIS }}
              aria-hidden
            />
            <span className="text-dim">{row.name ?? row.dataKey}</span>
            <span className="ml-auto font-mono font-semibold tabular-nums text-ink">
              {typeof row.value === "number" ? row.value.toLocaleString("es-ES") : row.value}
            </span>
          </li>
        ))}
      </ul>
      <p className="mt-1.5 text-[10px] uppercase tracking-wider text-steel">{unit}</p>
    </div>
  );
}

/** Leyenda textual: la identidad nunca depende solo del color. */
function Legend({ items }: { items: { label: string; color: string; value?: number }[] }) {
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
      {items.map((item) => (
        <li key={item.label} className="flex items-center gap-1.5 text-[11px]">
          <span className="h-2 w-2 rounded-sm" style={{ background: item.color }} aria-hidden />
          <span className="text-dim">{item.label}</span>
          {item.value !== undefined ? (
            <span className="font-mono font-semibold tabular-nums text-ink">{item.value}</span>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

/**
 * Marco comun: titulo, leyenda, lienzo y conmutador de vista de tabla.
 * La tabla cumple el requisito de accesibilidad (alternativa no visual).
 */
function ChartFrame({
  title,
  subtitle,
  legend,
  table,
  children,
  height = 240,
}: {
  title: string;
  subtitle?: string;
  legend?: { label: string; color: string; value?: number }[];
  table: { head: string[]; rows: (string | number)[][] };
  children: React.ReactNode;
  height?: number;
}) {
  const [showTable, setShowTable] = useState(false);
  const tableId = useId();

  return (
    <Panel interactive className="overflow-hidden">
      <PanelHeader
        title={title}
        subtitle={subtitle}
        action={
          <button
            type="button"
            onClick={() => setShowTable((v) => !v)}
            aria-expanded={showTable}
            aria-controls={tableId}
            className="rounded border border-hairline px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-steel transition-colors hover:border-med/40 hover:text-med"
          >
            {showTable ? "Ver grafico" : "Ver datos"}
          </button>
        }
      />
      <div className="px-5 py-4">
        {legend && legend.length > 1 ? (
          <div className="mb-3">
            <Legend items={legend} />
          </div>
        ) : null}

        {showTable ? (
          <div id={tableId} className="max-h-60 overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-panel">
                <tr className="border-b border-hairline">
                  {table.head.map((h) => (
                    <th key={h} className="px-2 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-steel">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {table.rows.map((row, i) => (
                  <tr key={i} className="border-b border-white/[0.04]">
                    {row.map((cell, j) => (
                      <td
                        key={j}
                        className={cn("px-2 py-1.5", j === 0 ? "text-dim" : "font-mono tabular-nums text-ink")}
                      >
                        {cell}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ height }} aria-hidden>
            {children}
          </div>
        )}
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// 1. Distribucion de hallazgos por criticidad (paleta de estado)
// ---------------------------------------------------------------------------

export function SeverityDonut({ bySeverity }: { bySeverity: Record<Severity, number> }) {
  const order: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const data = order
    .map((s) => ({ key: s, name: SEVERITY_LABEL_ES[s], value: bySeverity[s], color: SEVERITY_HEX[s] }))
    .filter((d) => d.value > 0);
  const total = data.reduce((sum, d) => sum + d.value, 0);

  return (
    <ChartFrame
      title="Hallazgos por criticidad"
      subtitle={`${total} hallazgo${total === 1 ? "" : "s"} clasificado${total === 1 ? "" : "s"}`}
      legend={data.map((d) => ({ label: d.name, color: d.color, value: d.value }))}
      table={{
        head: ["Criticidad", "Hallazgos", "Porcentaje"],
        rows: data.map((d) => [d.name, d.value, `${((d.value / Math.max(total, 1)) * 100).toFixed(1)} %`]),
      }}
    >
      {total === 0 ? (
        <p className="pt-16 text-center text-xs text-steel">Sin hallazgos que representar.</p>
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius="58%"
              outerRadius="86%"
              paddingAngle={3}
              stroke="#0E131F"
              strokeWidth={2}
              isAnimationActive={false}
            >
              {data.map((d) => (
                <Cell key={d.key} fill={d.color} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip unit="hallazgos" />} cursor={false} />
          </PieChart>
        </ResponsiveContainer>
      )}
    </ChartFrame>
  );
}

// ---------------------------------------------------------------------------
// 2. Linea temporal de eventos, apilada por criticidad
// ---------------------------------------------------------------------------

export function EventTimeline({ buckets }: { buckets: TimelineBucket[] }) {
  const series: { key: keyof TimelineBucket; label: string; color: string }[] = [
    { key: "critical", label: "Critico", color: SEVERITY_HEX.CRITICAL },
    { key: "high", label: "Alto", color: SEVERITY_HEX.HIGH },
    { key: "medium", label: "Medio", color: SEVERITY_HEX.MEDIUM },
    { key: "low", label: "Bajo", color: SEVERITY_HEX.LOW },
  ];
  const active = series.filter((s) => buckets.some((b) => Number(b[s.key]) > 0));
  const legend = [
    ...active.map((s) => ({ label: s.label, color: s.color })),
    { label: "Volumen total", color: SEQUENTIAL_CYAN[3] },
  ];

  return (
    <ChartFrame
      title="Actividad en el tiempo"
      subtitle="Volumen de eventos por intervalo; en color, los marcados por el motor de correlacion"
      legend={legend}
      height={260}
      table={{
        head: ["Intervalo (UTC)", "Total", "Critico", "Alto", "Medio", "Bajo"],
        rows: buckets.map((b) => [b.label, b.total, b.critical, b.high, b.medium, b.low]),
      }}
    >
      {buckets.length === 0 ? (
        <p className="pt-20 text-center text-xs text-steel">
          No hay marcas temporales interpretables en el dataset.
        </p>
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={buckets} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
            <defs>
              <linearGradient id="grad-total" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={SEQUENTIAL_CYAN[3]} stopOpacity={0.35} />
                <stop offset="100%" stopColor={SEQUENTIAL_CYAN[3]} stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="label"
              tick={{ fill: AXIS, fontSize: 10 }}
              tickLine={false}
              axisLine={{ stroke: GRID }}
              minTickGap={24}
            />
            <YAxis
              tick={{ fill: AXIS, fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              width={44}
              allowDecimals={false}
            />
            <Tooltip content={<ChartTooltip />} cursor={{ stroke: SEQUENTIAL_CYAN[2], strokeWidth: 1 }} />
            <Area
              type="monotone"
              dataKey="total"
              name="Total"
              stroke={SEQUENTIAL_CYAN[2]}
              strokeWidth={2}
              fill="url(#grad-total)"
              isAnimationActive={false}
            />
            {active.map((s) => (
              <Area
                key={String(s.key)}
                type="monotone"
                dataKey={s.key as string}
                name={s.label}
                stackId="flagged"
                stroke={s.color}
                strokeWidth={2}
                fill={s.color}
                fillOpacity={0.22}
                isAnimationActive={false}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      )}
    </ChartFrame>
  );
}

// ---------------------------------------------------------------------------
// 3. Ranking de entidades (magnitud -> rampa secuencial de un solo tono)
// ---------------------------------------------------------------------------

export function EntityRanking({
  title,
  subtitle,
  buckets,
  unitLabel = "eventos",
}: {
  title: string;
  subtitle?: string;
  buckets: CountBucket[];
  unitLabel?: string;
}) {
  const data = buckets.slice(0, 8);
  const max = Math.max(1, ...data.map((d) => d.count));
  // El tono se asigna por magnitud relativa, no por identidad de la serie.
  const shade = (count: number): string => {
    const ratio = count / max;
    if (ratio > 0.75) return SEQUENTIAL_CYAN[0];
    if (ratio > 0.5) return SEQUENTIAL_CYAN[1];
    if (ratio > 0.25) return SEQUENTIAL_CYAN[2];
    return SEQUENTIAL_CYAN[3];
  };

  return (
    <ChartFrame
      title={title}
      subtitle={subtitle}
      height={Math.max(180, data.length * 28)}
      table={{
        head: ["Entidad", unitLabel.charAt(0).toUpperCase() + unitLabel.slice(1)],
        rows: data.map((d) => [d.key, d.count]),
      }}
    >
      {data.length === 0 ? (
        <p className="pt-12 text-center text-xs text-steel">Sin datos para este eje.</p>
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 0, right: 28, left: 0, bottom: 0 }} barCategoryGap={6}>
            <CartesianGrid stroke={GRID} strokeDasharray="3 3" horizontal={false} />
            <XAxis type="number" hide allowDecimals={false} />
            <YAxis
              type="category"
              dataKey="key"
              tick={{ fill: AXIS, fontSize: 10, fontFamily: "var(--font-jetbrains)" }}
              tickLine={false}
              axisLine={false}
              width={128}
            />
            <Tooltip content={<ChartTooltip unit={unitLabel} />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
            <Bar dataKey="count" name={unitLabel} radius={[0, 4, 4, 0]} isAnimationActive={false}>
              {data.map((d) => (
                <Cell key={d.key} fill={shade(d.count)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </ChartFrame>
  );
}

// ---------------------------------------------------------------------------
// 4. Hallazgos por familia de deteccion
// ---------------------------------------------------------------------------

export function CategoryBreakdown({
  data,
}: {
  data: { label: string; count: number; worst: Severity | null }[];
}) {
  const present = data.filter((d) => d.count > 0);

  return (
    <ChartFrame
      title="Hallazgos por familia de deteccion"
      subtitle="Las 6 familias del alcance; el color indica la criticidad maxima alcanzada en cada una"
      legend={(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[])
        .filter((s) => present.some((d) => d.worst === s))
        .map((s) => ({ label: SEVERITY_LABEL_ES[s], color: SEVERITY_HEX[s] }))}
      height={Math.max(180, present.length * 30)}
      table={{
        head: ["Familia", "Hallazgos", "Criticidad maxima"],
        rows: data.map((d) => [d.label, d.count, d.worst ? SEVERITY_LABEL_ES[d.worst] : "—"]),
      }}
    >
      {present.length === 0 ? (
        <p className="pt-12 text-center text-xs text-steel">Ninguna familia de deteccion se ha activado.</p>
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={present} layout="vertical" margin={{ top: 0, right: 28, left: 0, bottom: 0 }} barCategoryGap={6}>
            <CartesianGrid stroke={GRID} strokeDasharray="3 3" horizontal={false} />
            <XAxis type="number" hide allowDecimals={false} />
            <YAxis
              type="category"
              dataKey="label"
              tick={{ fill: AXIS, fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              width={150}
            />
            <Tooltip content={<ChartTooltip unit="hallazgos" />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
            <Bar dataKey="count" name="Hallazgos" radius={[0, 4, 4, 0]} isAnimationActive={false}>
              {present.map((d) => (
                <Cell key={d.label} fill={d.worst ? SEVERITY_HEX[d.worst] : SEQUENTIAL_CYAN[3]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </ChartFrame>
  );
}
