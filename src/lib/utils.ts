import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

import type { Severity } from "./types";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** Orden operativo de severidades, de mayor a menor. */
export const SEVERITY_ORDER: readonly Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
] as const;

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

export const SEVERITY_LABEL_ES: Record<Severity, string> = {
  CRITICAL: "Critico",
  HIGH: "Alto",
  MEDIUM: "Medio",
  LOW: "Bajo",
};

/** Paleta de estado del design system (SKILL 2). Nunca para series categoricas. */
export const SEVERITY_HEX: Record<Severity, string> = {
  CRITICAL: "#FF0055",
  HIGH: "#FF9100",
  MEDIUM: "#00E5FF",
  LOW: "#00FFA3",
};

/** Rampa secuencial de un solo tono (magnitud). Pasos >= 3:1 sobre el panel. */
export const SEQUENTIAL_CYAN: readonly string[] = [
  "#7BE4F7",
  "#2ECBE8",
  "#0FA3C4",
  "#0D7F99",
] as const;

export function maxSeverity(severities: readonly Severity[]): Severity {
  return severities.reduce<Severity>(
    (acc, s) => (SEVERITY_RANK[s] > SEVERITY_RANK[acc] ? s : acc),
    "LOW",
  );
}

export function severityFromScore(score: number): Severity {
  if (score >= 85) return "CRITICAL";
  if (score >= 65) return "HIGH";
  if (score >= 40) return "MEDIUM";
  return "LOW";
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/** Formato corto y estable (UTC) para timestamps en tablas y PDF. */
export function formatTimestamp(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
    `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`
  );
}

export function formatDateOnly(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`;
}

/** Duracion legible entre dos ISO. */
export function formatSpan(fromIso: string | null, toIso: string | null): string {
  if (!fromIso || !toIso) return "—";
  const ms = new Date(toIso).getTime() - new Date(fromIso).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const mins = Math.round(ms / 60000);
  if (mins < 60) return `${mins} min`;
  const hours = Math.floor(mins / 60);
  const rest = mins % 60;
  if (hours < 24) return rest ? `${hours} h ${rest} min` : `${hours} h`;
  const days = Math.floor(hours / 24);
  return `${days} d ${hours % 24} h`;
}

/** Deduplica preservando orden y descartando vacios. */
export function uniq(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    if (!v || seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

export function topCounts(
  values: readonly string[],
  limit: number,
): { key: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const v of values) {
    if (!v) continue;
    counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
    .slice(0, limit);
}

/** Rangos RFC1918 / loopback / link-local. Todo lo demas se considera externo. */
export function isPrivateIp(ip: string): boolean {
  const value = ip.trim();
  if (!value) return true; // Sin IP no podemos afirmar que sea externa.
  if (value === "::1" || value === "localhost" || value === "-") return true;
  if (value.toLowerCase().startsWith("fe80:") || value.toLowerCase().startsWith("fc")) {
    return true;
  }
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (!m) return true; // Nombres de host u otros formatos: no afirmamos nada.
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

export function isPublicIp(ip: string): boolean {
  return Boolean(ip.trim()) && !isPrivateIp(ip);
}

/** `CORP\mgarcia` -> `mgarcia` (para agrupar el mismo principal). */
export function normalizeUser(user: string): string {
  const value = user.trim();
  if (!value) return "";
  const slash = value.lastIndexOf("\\");
  const base = slash >= 0 ? value.slice(slash + 1) : value;
  return base.split("@")[0].toLowerCase();
}

/** Cuentas de servicio/equipo que generan ruido y no son principales humanos. */
export function isMachineAccount(user: string): boolean {
  const u = normalizeUser(user);
  if (!u) return true;
  if (u.endsWith("$")) return true;
  return ["system", "local service", "network service", "anonymous logon", "-"].includes(u);
}
