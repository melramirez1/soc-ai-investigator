/**
 * Saneamiento defensivo (SKILL 5).
 *
 * Dos superficies distintas:
 *  1. Render en UI/PDF  -> `sanitizeCell`: elimina caracteres de control que
 *     pueden romper el layout o inyectar secuencias ANSI. El escapado de HTML
 *     lo garantiza React al renderizar siempre como nodo de texto (nunca se usa
 *     `dangerouslySetInnerHTML` en este proyecto).
 *  2. Prompt del LLM    -> `sanitizeForPrompt`: neutraliza los delimitadores del
 *     bloque de datos y acota la longitud para que el contenido de un log no
 *     pueda cerrar el bloque y hacerse pasar por instruccion del sistema.
 */

/** Claves que nunca deben escribirse en un objeto plano (prototype pollution). */
const FORBIDDEN_KEYS = new Set(["__proto__", "prototype", "constructor"]);

export function isForbiddenKey(key: string): boolean {
  return FORBIDDEN_KEYS.has(key);
}

/** Crea un objeto de registro seguro, descartando claves peligrosas. */
export function safeRecord(
  entries: readonly (readonly [string, string])[],
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of entries) {
    if (!key || isForbiddenKey(key)) continue;
    Object.defineProperty(out, key, {
      value,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

/**
 * Construye una clase de caracteres a partir de rangos de code point.
 * Se expresa con numeros para que el fichero fuente no contenga bytes de
 * control literales (ilegibles y fragiles ante reformateos).
 */
function charClass(ranges: readonly (readonly [number, number])[]): RegExp {
  const body = ranges
    .map(([lo, hi]) =>
      lo === hi
        ? String.fromCodePoint(lo)
        : `${String.fromCodePoint(lo)}-${String.fromCodePoint(hi)}`,
    )
    .join("");
  return new RegExp(`[${body}]`, "gu");
}

/** C0 (salvo tab/LF/CR), DEL y C1. */
const CONTROL_CHARS = charClass([
  [0x00, 0x08],
  [0x0b, 0x0c],
  [0x0e, 0x1f],
  [0x7f, 0x9f],
]);

/** Marcas de direccionalidad usadas para spoofing visual de rutas y comandos. */
const BIDI_CHARS = charClass([
  [0x200e, 0x200f],
  [0x202a, 0x202e],
  [0x2066, 0x2069],
]);

/** Normaliza un valor de celda para mostrarlo o imprimirlo con seguridad. */
export function sanitizeCell(value: unknown, maxLength = 600): string {
  if (value === null || value === undefined) return "";
  const text = typeof value === "string" ? value : String(value);
  const cleaned = text
    .replace(CONTROL_CHARS, " ")
    .replace(BIDI_CHARS, "")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}...` : cleaned;
}

/**
 * Neutraliza una celda destinada a exportacion a hoja de calculo.
 * Disponible para cualquier exportacion tabular: evita CSV/formula injection
 * al abrir el fichero resultante en Excel o LibreOffice.
 */
export function neutralizeFormula(value: string): string {
  return /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
}

/**
 * Prepara texto procedente de logs (no confiable) para incrustarlo en un prompt.
 * Rompe los delimitadores del bloque de datos y las etiquetas de rol.
 */
export function sanitizeForPrompt(value: unknown, maxLength = 400): string {
  return sanitizeCell(value, maxLength)
    // El bloque de datos se delimita con """ : lo neutralizamos.
    .replace(/"{3,}/g, "'''")
    .replace(/`{3,}/g, "'''")
    // Etiquetas de rol tipo chat-ML que podrian simular un turno del sistema.
    .replace(/<\|[^|>]*\|>/g, "[tag]")
    .replace(/\b(system|assistant|developer)\s*:/gi, "$1-:");
}

/** Recorta un array y anota cuantos elementos se omitieron. */
export function capList<T>(
  items: readonly T[],
  max: number,
): { items: T[]; omitted: number } {
  if (items.length <= max) return { items: [...items], omitted: 0 };
  return { items: items.slice(0, max), omitted: items.length - max };
}
