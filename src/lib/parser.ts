/**
 * Ingesta segura de telemetria (SKILL 1 + SKILL 5).
 *
 * El parseo ocurre integramente en el navegador: los logs del cliente nunca se
 * suben a ningun servidor. Al motor de IA solo viaja un resumen de hallazgos ya
 * generado y saneado (ver `src/app/api/analyze/route.ts`).
 */

import * as XLSX from "xlsx";

import { isForbiddenKey, safeRecord, sanitizeCell } from "./sanitize";
import type { DatasetSummary, LogEvent, ParsedDataset } from "./types";

/** Limite duro para evitar agotamiento de memoria (DoS). */
export const MAX_FILE_BYTES = 15 * 1024 * 1024;
/**
 * Hojas de calculo exportadas del SIEM y JSON / JSON Lines (exportaciones de
 * Splunk, Elastic o Wazuh).
 */
export const ALLOWED_EXTENSIONS = [".xlsx", ".csv", ".json", ".ndjson", ".jsonl"] as const;

const JSON_EXTENSIONS: readonly string[] = [".json", ".ndjson", ".jsonl"];

export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ParseError";
  }
}

/** Campos canonicos del modelo `LogEvent` que intentamos mapear. */
type CanonicalField =
  | "logId"
  | "timestamp"
  | "eventId"
  | "host"
  | "user"
  | "sourceIp"
  | "destIp"
  | "logonType"
  | "process"
  | "parentProcess"
  | "commandLine"
  | "status"
  | "action"
  | "protocol"
  | "port"
  | "bytes"
  | "target"
  | "message";

/**
 * Alias de cabecera por campo canonico (ES/EN, con y sin separadores).
 * Se comparan contra la cabecera normalizada: minusculas, sin acentos y sin
 * caracteres no alfanumericos.
 */
const COLUMN_ALIASES: Record<CanonicalField, readonly string[]> = {
  logId: ["logid", "id", "idlog", "eventrecordid", "recordid", "idregistro", "nolog", "num", "idevento"],
  timestamp: [
    "timestamp", "fechahora", "fecha", "datetime", "date", "time", "hora",
    "timegenerated", "timecreated", "eventtime", "utctime", "createdat",
  ],
  eventId: ["eventid", "idevent", "evento", "eventcode", "codigoevento", "winevent", "eventidwindows"],
  host: [
    "host", "hostname", "equipo", "computer", "computername", "machine",
    "device", "dispositivo", "asset", "servidor", "origenhost", "srchost",
    // Wazuh: agent.name
    "agentname",
  ],
  user: [
    "user", "usuario", "username", "account", "accountname", "cuenta",
    "targetusername", "subjectusername", "samaccountname", "principal",
  ],
  sourceIp: [
    "sourceip", "srcip", "iporigen", "ipaddress", "ipsource", "clientip",
    "origenip", "remoteip", "ipfuente", "sourceaddress", "srcaddr", "ip",
  ],
  destIp: [
    "destip", "dstip", "ipdestino", "destinationip", "destinationaddress",
    "dstaddr", "targetip", "remotehostip", "destino",
  ],
  logonType: ["logontype", "tipologon", "tipodeinicio", "tipoinicio", "logontypeid", "tipoacceso"],
  process: [
    "process", "proceso", "processname", "image", "imagen", "newprocessname",
    "nombreproceso", "binario", "executable",
  ],
  parentProcess: [
    "parentprocess", "parentprocessname", "procesopadre", "parentimage",
    "parent", "creatorprocessname", "padre",
  ],
  commandLine: [
    "commandline", "comando", "command", "lineacomando", "lineadecomandos",
    "cmdline", "processcommandline", "args", "argumentos", "script",
  ],
  status: ["status", "estado", "resultado", "result", "outcome", "statuscode", "resultcode", "exito"],
  action: ["action", "accion", "activity", "actividad", "operation", "operacion", "verb"],
  protocol: ["protocol", "protocolo", "proto", "servicio", "service"],
  port: ["port", "puerto", "destport", "dstport", "puertodestino", "destinationport", "srcport"],
  bytes: ["bytes", "bytessent", "bytesenviados", "size", "tamano", "tamanio", "volumen", "bytestotal", "datasize"],
  target: [
    "target", "objetivo", "objeto", "object", "objectname", "recurso",
    "resource", "sharename", "filepath", "ruta", "path", "file", "fichero",
    "archivo", "url", "sharepath", "targetname", "targetobject",
  ],
  message: [
    "message", "mensaje", "descripcion", "description", "details", "detalle",
    "detalles", "eventdata", "info", "texto", "raw", "summary", "resumen",
  ],
};

/** Prioridad de resolucion: campos mas especificos ganan la cabecera ambigua. */
const FIELD_PRIORITY: readonly CanonicalField[] = [
  "logId", "timestamp", "eventId", "logonType", "sourceIp", "destIp", "host",
  "user", "parentProcess", "process", "commandLine", "port", "bytes",
  "protocol", "status", "action", "target", "message",
];

function normalizeHeader(header: string): string {
  return header
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

function extension(fileName: string): string {
  const dot = fileName.lastIndexOf(".");
  return dot < 0 ? "" : fileName.slice(dot).toLowerCase();
}

export function validateFile(file: File): void {
  const ext = extension(file.name);
  if (!(ALLOWED_EXTENSIONS as readonly string[]).includes(ext)) {
    throw new ParseError(
      `Extension no permitida "${ext || "(sin extension)"}". Solo se aceptan ${ALLOWED_EXTENSIONS.join(", ")}.`,
    );
  }
  if (file.size > MAX_FILE_BYTES) {
    throw new ParseError(
      `El archivo pesa ${(file.size / 1024 / 1024).toFixed(1)} MB y supera el limite de 15 MB.`,
    );
  }
  if (file.size === 0) {
    throw new ParseError("El archivo esta vacio.");
  }
}

/**
 * Opciones de lectura endurecidas: sin evaluacion de formulas ni HTML embebido.
 * Esto corta formula injection y reduce la superficie de parseo del XML.
 */
const READ_OPTIONS: XLSX.ParsingOptions = {
  cellFormula: false,
  cellHTML: false,
  cellDates: true,
  cellStyles: false,
  cellNF: false,
  dense: false,
};

/** Localiza la fila de cabecera: la primera con >= 2 alias reconocidos. */
function findHeaderRow(grid: readonly (readonly string[])[]): number {
  const limit = Math.min(grid.length, 15);
  let best = -1;
  let bestScore = 0;
  for (let i = 0; i < limit; i += 1) {
    const row = grid[i];
    const nonEmpty = row.filter((c) => c.trim()).length;
    if (nonEmpty < 2) continue;
    let score = 0;
    for (const cell of row) {
      const norm = normalizeHeader(cell);
      if (!norm) continue;
      if (FIELD_PRIORITY.some((f) => COLUMN_ALIASES[f].includes(norm))) score += 1;
    }
    if (score > bestScore) {
      bestScore = score;
      best = i;
    }
  }
  if (best >= 0 && bestScore >= 2) return best;
  // Sin cabecera reconocible usamos la primera fila con contenido.
  return grid.findIndex((row) => row.some((c) => c.trim()));
}

/** Asigna cada campo canonico a una columna, resolviendo colisiones por prioridad. */
function mapColumns(headers: readonly string[]): {
  index: Partial<Record<CanonicalField, number>>;
  mapped: Record<string, string>;
  unmapped: string[];
} {
  const normalized = headers.map(normalizeHeader);
  const taken = new Set<number>();
  const index: Partial<Record<CanonicalField, number>> = {};
  const mapped: Record<string, string> = {};

  const assign = (field: CanonicalField, col: number) => {
    taken.add(col);
    index[field] = col;
    mapped[field] = headers[col];
  };

  // 1) Coincidencias exactas de todos los campos primero, para que una
  //    contencion no robe una cabecera exacta de otro campo (p.ej. el ECS
  //    "process.command_line" es exacto de commandLine, no de process).
  for (const field of FIELD_PRIORITY) {
    const aliases = COLUMN_ALIASES[field];
    const col = normalized.findIndex((h, i) => !taken.has(i) && h !== "" && aliases.includes(h));
    if (col >= 0) assign(field, col);
  }

  // 2) Coincidencia por contencion (p.ej. "winlogsourceipv4").
  for (const field of FIELD_PRIORITY) {
    if (index[field] !== undefined) continue;
    const aliases = COLUMN_ALIASES[field];
    const col = normalized.findIndex(
      (h, i) =>
        !taken.has(i) &&
        h.length >= 3 &&
        aliases.some((a) => a.length >= 4 && (h.includes(a) || a.includes(h))),
    );
    if (col >= 0) assign(field, col);
  }

  const unmapped = headers.filter((h, i) => h.trim() && !taken.has(i));
  return { index, mapped, unmapped };
}

/** Serial de Excel (dias desde 1899-12-30) a epoch ms, en UTC. */
function excelSerialToEpoch(serial: number): number | null {
  if (!Number.isFinite(serial) || serial <= 0 || serial > 2958466) return null;
  return Math.round((serial - 25569) * 86400 * 1000);
}

const DMY = /^(\d{1,2})[/-](\d{1,2})[/-](\d{4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?/;
const YMD = /^(\d{4})[/-](\d{1,2})[/-](\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?/;

/**
 * Interpreta una marca temporal en los formatos habituales de export de SIEM.
 * Las fechas sin zona se tratan como UTC para que el analisis sea reproducible.
 */
export function parseTimestamp(value: string): number | null {
  const text = value.trim();
  if (!text) return null;

  // Serial numerico de Excel.
  if (/^\d+(\.\d+)?$/.test(text)) {
    const n = Number(text);
    // Un entero grande tambien puede ser epoch en segundos o ms.
    if (n > 1e12) return n;
    if (n > 1e9) return n * 1000;
    return excelSerialToEpoch(n);
  }

  // ISO 8601 con o sin zona explicita.
  if (/^\d{4}-\d{2}-\d{2}T/.test(text)) {
    const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/.test(text);
    const d = new Date(hasZone ? text : `${text}Z`);
    return Number.isNaN(d.getTime()) ? null : d.getTime();
  }

  const ymd = YMD.exec(text);
  if (ymd) {
    return Date.UTC(
      Number(ymd[1]), Number(ymd[2]) - 1, Number(ymd[3]),
      Number(ymd[4] ?? 0), Number(ymd[5] ?? 0), Number(ymd[6] ?? 0),
    );
  }

  const dmy = DMY.exec(text);
  if (dmy) {
    // Formato europeo dd/MM/yyyy; si el primer grupo > 12 es inequivoco.
    let day = Number(dmy[1]);
    let month = Number(dmy[2]);
    if (day <= 12 && month > 12) [day, month] = [month, day];
    return Date.UTC(
      Number(dmy[3]), month - 1, day,
      Number(dmy[4] ?? 0), Number(dmy[5] ?? 0), Number(dmy[6] ?? 0),
    );
  }

  const fallback = new Date(text);
  return Number.isNaN(fallback.getTime()) ? null : fallback.getTime();
}

function parseBytes(value: string): number | null {
  const text = value.replace(/[\s,_]/g, "");
  if (!text) return null;
  const m = /^(\d+(?:\.\d+)?)(kb|mb|gb|b)?$/i.exec(text);
  if (!m) return null;
  const n = Number(m[1]);
  const unit = (m[2] ?? "b").toLowerCase();
  const factor = unit === "gb" ? 1024 ** 3 : unit === "mb" ? 1024 ** 2 : unit === "kb" ? 1024 : 1;
  return Math.round(n * factor);
}

/** Extrae el primer ID de evento numerico de un texto libre. */
function extractEventId(value: string): string {
  const m = /\b(\d{3,5})\b/.exec(value);
  return m ? m[1] : value.trim();
}

function readWorkbook(fileName: string, data: ArrayBuffer | string): XLSX.WorkBook {
  try {
    if (typeof data === "string") {
      return XLSX.read(data, { ...READ_OPTIONS, type: "string" });
    }
    return XLSX.read(new Uint8Array(data), { ...READ_OPTIONS, type: "array" });
  } catch (error) {
    const detail = error instanceof Error ? error.message : "formato no reconocido";
    throw new ParseError(`No se pudo leer "${fileName}": ${detail}`);
  }
}

/**
 * Tabla intermedia comun a todos los formatos de entrada: una cabecera y filas
 * de texto. A partir de aqui el mapeo de columnas y el saneado son identicos.
 */
interface RawTable {
  sheetName: string;
  headers: string[];
  rows: string[][];
  warnings: string[];
}

async function readSpreadsheetTable(file: File): Promise<RawTable> {
  const isCsv = extension(file.name) === ".csv";
  const raw = isCsv ? await file.text() : await file.arrayBuffer();
  const workbook = readWorkbook(file.name, raw);

  const sheetName = workbook.SheetNames[0];
  if (!sheetName) throw new ParseError("El libro no contiene ninguna hoja.");
  const sheet = workbook.Sheets[sheetName];
  if (!sheet) throw new ParseError(`No se pudo abrir la hoja "${sheetName}".`);

  const grid = XLSX.utils.sheet_to_json<string[]>(sheet, {
    header: 1,
    raw: false,
    defval: "",
    blankrows: false,
  });

  if (grid.length === 0) throw new ParseError("La hoja no contiene filas.");

  const headerRow = findHeaderRow(grid);
  if (headerRow < 0) throw new ParseError("No se encontro ninguna fila con datos.");

  return {
    sheetName,
    headers: (grid[headerRow] ?? []).map((h, i) => sanitizeCell(h, 80) || `Columna_${i + 1}`),
    rows: grid.slice(headerRow + 1),
    warnings: [],
  };
}

// ---------------------------------------------------------------------------
// JSON / JSON Lines (Splunk, Elastic, Wazuh)
// ---------------------------------------------------------------------------

/** Cotas del aplanado: un documento hostil no puede inflar columnas ni pila. */
const JSON_LIMITS = {
  maxDepth: 6,
  maxKeysPerRecord: 250,
  maxColumns: 400,
} as const;

/** Claves contenedoras habituales de cada exportador. */
const JSON_ARRAY_KEYS = ["events", "records", "results", "data", "logs", "items", "alerts"] as const;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Desenvuelve el envoltorio de cada exportador:
 *  - Splunk: `{"preview":false,"result":{...}}`
 *  - Elastic: `{"_index":"...","_source":{...}}`
 */
function unwrapRecord(value: Record<string, unknown>): Record<string, unknown> {
  if (isPlainObject(value._source)) return value._source;
  if (isPlainObject(value.result)) return value.result;
  return value;
}

/** Localiza el array de registros en un documento JSON completo. */
function extractJsonRecords(doc: unknown): unknown[] {
  if (Array.isArray(doc)) return doc;
  if (!isPlainObject(doc)) return [];
  // Respuesta de busqueda de Elastic: { hits: { hits: [...] } }
  if (isPlainObject(doc.hits) && Array.isArray(doc.hits.hits)) return doc.hits.hits;
  for (const key of JSON_ARRAY_KEYS) {
    const candidate = doc[key];
    if (Array.isArray(candidate)) return candidate;
  }
  // Un unico evento suelto.
  return [doc];
}

/**
 * Aplana un evento anidado a pares `ruta.con.puntos -> texto`
 * (`source.ip`, `winlog.event_id`, `data.win.system.eventID`...). Las rutas se
 * normalizan despues igual que una cabecera de Excel, por lo que los alias de
 * columna existentes siguen funcionando. Las claves peligrosas se descartan en
 * cualquier nivel para impedir prototype pollution.
 */
function flattenRecord(record: Record<string, unknown>): [string, string][] {
  const out: [string, string][] = [];

  const visit = (value: unknown, path: string, depth: number): void => {
    if (out.length >= JSON_LIMITS.maxKeysPerRecord) return;
    if (value === null || value === undefined) {
      out.push([path, ""]);
      return;
    }
    if (Array.isArray(value)) {
      const primitives = value.every((v) => v === null || typeof v !== "object");
      out.push([path, primitives ? value.map((v) => String(v ?? "")).join(", ") : JSON.stringify(value)]);
      return;
    }
    if (typeof value === "object") {
      if (depth >= JSON_LIMITS.maxDepth) {
        out.push([path, JSON.stringify(value)]);
        return;
      }
      for (const [key, child] of Object.entries(value)) {
        if (isForbiddenKey(key)) continue;
        visit(child, path ? `${path}.${key}` : key, depth + 1);
      }
      return;
    }
    out.push([path, String(value)]);
  };

  visit(record, "", 0);
  return out.filter(([path]) => path !== "");
}

function parseNdjson(text: string): { records: unknown[]; malformed: number } {
  const records: unknown[] = [];
  let malformed = 0;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      records.push(JSON.parse(trimmed));
    } catch {
      malformed += 1;
    }
  }
  return { records, malformed };
}

async function readJsonTable(file: File): Promise<RawTable> {
  const text = (await file.text()).replace(/^﻿/, "");
  const warnings: string[] = [];
  const ext = extension(file.name);

  let records: unknown[];
  let format: string;
  let wholeDoc: unknown = undefined;
  let parsedWhole = false;

  // Un `.json` puede ser un documento unico o, muy a menudo, JSON Lines.
  if (ext === ".json") {
    try {
      wholeDoc = JSON.parse(text);
      parsedWhole = true;
    } catch {
      parsedWhole = false;
    }
  }

  if (parsedWhole) {
    records = extractJsonRecords(wholeDoc);
    format = "JSON";
  } else {
    const nd = parseNdjson(text);
    records = nd.records;
    format = "JSON Lines";
    if (nd.malformed > 0) {
      warnings.push(`${nd.malformed} linea(s) del fichero JSON Lines no son JSON valido y se han descartado.`);
    }
  }

  const objects = records
    .filter(isPlainObject)
    .map(unwrapRecord);
  if (objects.length === 0) {
    throw new ParseError(`No se encontro ningun evento en "${file.name}" (se esperaba un objeto JSON por evento).`);
  }
  if (objects.length < records.length) {
    warnings.push(`${records.length - objects.length} elemento(s) no eran objetos JSON y se han descartado.`);
  }

  // Cabecera = union de rutas en orden de primera aparicion.
  const columnIndex = new Map<string, number>();
  const headers: string[] = [];
  let droppedColumns = 0;
  const flatRows = objects.map(flattenRecord);

  for (const pairs of flatRows) {
    for (const [path] of pairs) {
      if (columnIndex.has(path)) continue;
      if (headers.length >= JSON_LIMITS.maxColumns) {
        droppedColumns += 1;
        continue;
      }
      columnIndex.set(path, headers.length);
      headers.push(path);
    }
  }
  if (droppedColumns > 0) {
    warnings.push(`Se han ignorado ${droppedColumns} campo(s) por superar el limite de ${JSON_LIMITS.maxColumns} columnas.`);
  }

  const rows = flatRows.map((pairs) => {
    const row: string[] = new Array<string>(headers.length).fill("");
    for (const [path, value] of pairs) {
      const col = columnIndex.get(path);
      if (col !== undefined) row[col] = value;
    }
    return row;
  });

  return {
    sheetName: format,
    headers: headers.map((h, i) => sanitizeCell(h, 80) || `Campo_${i + 1}`),
    rows,
    warnings,
  };
}

/** Convierte el fichero cargado por el usuario en un dataset normalizado. */
export async function parseTelemetryFile(file: File): Promise<ParsedDataset> {
  validateFile(file);

  const isJson = JSON_EXTENSIONS.includes(extension(file.name));
  const table = isJson ? await readJsonTable(file) : await readSpreadsheetTable(file);
  const { sheetName, headers, rows } = table;

  const { index, mapped, unmapped } = mapColumns(headers);
  const warnings: string[] = [...table.warnings];

  if (index.timestamp === undefined) {
    warnings.push(
      "No se identifico una columna de fecha/hora: el analisis temporal y la correlacion por ventanas quedan limitados.",
    );
  }
  if (index.eventId === undefined && index.commandLine === undefined && index.message === undefined) {
    warnings.push(
      "No se identificaron columnas de EventID, comando ni mensaje: la cobertura de deteccion sera parcial.",
    );
  }

  const get = (row: readonly string[], field: CanonicalField, max = 600): string => {
    const col = index[field];
    return col === undefined ? "" : sanitizeCell(row[col], max);
  };

  const events: LogEvent[] = [];
  let unparsedDates = 0;

  for (const row of rows) {
    if (!row.some((c) => String(c ?? "").trim())) continue;

    const rowIndex = events.length;
    const rawTimestamp = get(row, "timestamp", 60);
    const epoch = rawTimestamp ? parseTimestamp(rawTimestamp) : null;
    if (rawTimestamp && epoch === null) unparsedDates += 1;

    const message = get(row, "message", 1000);
    const eventIdRaw = get(row, "eventId", 40);

    const rawEntries: (readonly [string, string])[] = headers.map((header, i) => [
      header,
      sanitizeCell(row[i], 400),
    ]);

    events.push({
      rowIndex,
      logId: get(row, "logId", 40) || `ROW-${String(rowIndex + 1).padStart(5, "0")}`,
      timestamp: epoch === null ? null : new Date(epoch).toISOString(),
      epoch,
      rawTimestamp,
      eventId: eventIdRaw ? extractEventId(eventIdRaw) : "",
      host: get(row, "host", 80),
      user: get(row, "user", 80),
      sourceIp: get(row, "sourceIp", 60),
      destIp: get(row, "destIp", 60),
      logonType: get(row, "logonType", 20),
      process: get(row, "process", 200),
      parentProcess: get(row, "parentProcess", 200),
      commandLine: get(row, "commandLine", 900),
      status: get(row, "status", 80),
      action: get(row, "action", 80),
      protocol: get(row, "protocol", 40),
      port: get(row, "port", 20),
      bytes: parseBytes(get(row, "bytes", 30)),
      target: get(row, "target", 400),
      message,
      raw: safeRecord(rawEntries),
    });
  }

  if (events.length === 0) {
    throw new ParseError("No se encontro ninguna fila de datos por debajo de la cabecera.");
  }
  if (unparsedDates > 0) {
    warnings.push(
      `${unparsedDates} de ${events.length} filas tienen una fecha que no se pudo interpretar y quedan fuera del eje temporal.`,
    );
  }

  const epochs = events.map((e) => e.epoch).filter((e): e is number => e !== null);
  const summary: DatasetSummary = {
    fileName: sanitizeCell(file.name, 120),
    fileSizeBytes: file.size,
    sheetName: sanitizeCell(sheetName, 60),
    rowCount: events.length,
    columns: headers,
    mappedColumns: mapped,
    unmappedColumns: unmapped,
    firstEventAt: epochs.length ? new Date(Math.min(...epochs)).toISOString() : null,
    lastEventAt: epochs.length ? new Date(Math.max(...epochs)).toISOString() : null,
    warnings,
  };

  return { summary, events };
}
