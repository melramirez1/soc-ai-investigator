# ENTERPRISE SOC N2 INCIDENT RESPONSE PLATFORM (NEXT.JS + DOCKER)

================================================================================
SKILL 1: NOTEBOOKLM INGESTION & TOKEN OPTIMIZATION PIPELINE
================================================================================
When receiving telemetry, Excel sheets, or notes from NotebookLM:
1. TOKEN PRESERVATION PRINCIPLE: Never ingest raw binary/XML multi-megabyte files directly into LLM context.
2. MARKDOWN DIGESTION: Use `markitdown <file>` or python scripts to convert incoming assets into clean Markdown tables before reasoning.
3. CONTEXT INTEGRATION: Treat `context/INCIDENT_BRIEF.md` as the business and telemetry ground truth.
4. RIGOROUS FIDELITY: Strictly adhere to provided facts. Never hallucinate unauthorized IPs, timestamps, or fake attack steps.

================================================================================
SKILL 2: ELITE CYBER-SOC UI/UX DESIGN SYSTEM (FALCON / LINEAR ENGINE)
================================================================================
You are an expert Frontend Security Architect. You must deliver a high-impact, SaaS-grade SOC interface inspired by CrowdStrike Falcon, Darktrace, and Linear.
- Canvas Base: `#080B10` (Ultra-deep OLED space black).
- Card Panels: `#0E131F` with frosted glassmorphism: `backdrop-filter: blur(12px); background: rgba(14, 19, 31, 0.75); border: 1px solid rgba(255, 255, 255, 0.08);`.
- Card Hover: `transition: all 0.25s ease; border-color: rgba(0, 229, 255, 0.4); transform: translateY(-2px);`.
- Threat Palettes:
  * CRITICAL: `#FF0055` (Neon Crimson + soft glow `box-shadow: 0 0 16px rgba(255, 0, 85, 0.3)`).
  * HIGH: `#FF9100` (Cyber Amber).
  * MEDIUM: `#00E5FF` (Electric Cyan).
  * LOW / SUCCESS: `#00FFA3` (Matrix Emerald).
  * MUTED TELEMETRY: `#64748B` (Steel Slate).
- Typography: Clean sans-serif for UI, strict monospace (`JetBrains Mono`, `Consolas`, `monospace`) for Log_IDs, IPs, timestamps, and commands.
- Live Indicator: CSS pulsing red beacon on the header (`@keyframes pulse`).
- Recharts Styling: Dark `#080B10` canvas, subtle grid lines `#1E293B`, no white borders, custom styled tooltips with dark slate background.

================================================================================
SKILL 3: ADVANCED SOC N2 DETECTION & CORRELATION ENGINE (`src/lib/detector.ts`)
================================================================================
Correlate the 6-phase APT Kill Chain using the actual dataset telemetry:
1. Password Spraying (Critical): Event 4625 from IP `203.0.113.74` targeting `DC-01` across multiple accounts (EVT-00057 to EVT-00111), leading to compromised logon for `CORP\mgarcia` (EVT-00123) and privilege elevation (EVT-00126).
2. External RDP Breach (Critical): Event 4624 (LogonType=10) from `198.51.100.77` to `APP-SRV01` as `CORP\admin` (EVT-00188).
3. Process Obfuscation & Discovery (High): PowerShell `-EncodedCommand` (EVT-00198), discovery `Get-LocalGroupMember` and `net view` (EVT-00207, EVT-00214).
4. Ransomware Staging & Shadow Deletion (Critical): Access to `\\FS-SRV01\Finance`, access to `Budget2027.xlsx` (EVT-00231), compression with `tar.exe` (EVT-00232), mass FY2026 file access (EVT-00284-00309), and `vssadmin.exe delete shadows /all /quiet` (EVT-00314).
5. Mass Exfiltration via Proxy (Critical): Archive creation `7z.exe a archive.7z` on `WS-018` (EVT-00428) and 22 consecutive HTTP POST uploads to `198.51.100.88:443` (EVT-00430 to EVT-00461).
6. Persistence & Web Shell RCE (Critical): Scheduled Task `UpdateCheck` (EVT-00523), Trojan service `WinUpdateHelper` (`wuhelper.exe`, EVT-00524), and Web Shell exploitation on `WEB-01` executing `cmd.exe /c whoami` under `IIS APPPOOL` (EVT-00599

cat << 'EOF' > CLAUDE.md
# ENTERPRISE SOC N2 INCIDENT RESPONSE PLATFORM (NEXT.JS + DOCKER)

================================================================================
SKILL 1: NOTEBOOKLM INGESTION & TOKEN OPTIMIZATION PIPELINE
================================================================================
When receiving telemetry, Excel sheets, or notes from NotebookLM:
1. TOKEN PRESERVATION PRINCIPLE: Never ingest raw binary/XML multi-megabyte files directly into LLM context.
2. MARKDOWN DIGESTION: Use `markitdown <file>` or python scripts to convert incoming assets into clean Markdown tables before reasoning.
3. CONTEXT INTEGRATION: Treat `context/INCIDENT_BRIEF.md` as the business and telemetry ground truth.
4. RIGOROUS FIDELITY: Strictly adhere to provided facts. Never hallucinate unauthorized IPs, timestamps, or fake attack steps.

================================================================================
SKILL 2: ELITE CYBER-SOC UI/UX DESIGN SYSTEM (FALCON / LINEAR ENGINE)
================================================================================
You are an expert Frontend Security Architect. You must deliver a high-impact, SaaS-grade SOC interface inspired by CrowdStrike Falcon, Darktrace, and Linear.
- Canvas Base: `#080B10` (Ultra-deep OLED space black).
- Card Panels: `#0E131F` with frosted glassmorphism: `backdrop-filter: blur(12px); background: rgba(14, 19, 31, 0.75); border: 1px solid rgba(255, 255, 255, 0.08);`.
- Card Hover: `transition: all 0.25s ease; border-color: rgba(0, 229, 255, 0.4); transform: translateY(-2px);`.
- Threat Palettes:
  * CRITICAL: `#FF0055` (Neon Crimson + soft glow `box-shadow: 0 0 16px rgba(255, 0, 85, 0.3)`).
  * HIGH: `#FF9100` (Cyber Amber).
  * MEDIUM: `#00E5FF` (Electric Cyan).
  * LOW / SUCCESS: `#00FFA3` (Matrix Emerald).
  * MUTED TELEMETRY: `#64748B` (Steel Slate).
- Typography: Clean sans-serif for UI, strict monospace (`JetBrains Mono`, `Consolas`, `monospace`) for Log_IDs, IPs, timestamps, and commands.
- Live Indicator: CSS pulsing red beacon on the header (`@keyframes pulse`).
- Recharts Styling: Dark `#080B10` canvas, subtle grid lines `#1E293B`, no white borders, custom styled tooltips with dark slate background.

================================================================================
SKILL 3: ADVANCED SOC N2 DETECTION & CORRELATION ENGINE (`src/lib/detector.ts`)
================================================================================
Correlate the 6-phase APT Kill Chain using the actual dataset telemetry:
1. Password Spraying (Critical): Event 4625 from IP `203.0.113.74` targeting `DC-01` across multiple accounts (EVT-00057 to EVT-00111), leading to compromised logon for `CORP\mgarcia` (EVT-00123) and privilege elevation (EVT-00126).
2. External RDP Breach (Critical): Event 4624 (LogonType=10) from `198.51.100.77` to `APP-SRV01` as `CORP\admin` (EVT-00188).
3. Process Obfuscation & Discovery (High): PowerShell `-EncodedCommand` (EVT-00198), discovery `Get-LocalGroupMember` and `net view` (EVT-00207, EVT-00214).
4. Ransomware Staging & Shadow Deletion (Critical): Access to `\\FS-SRV01\Finance`, access to `Budget2027.xlsx` (EVT-00231), compression with `tar.exe` (EVT-00232), mass FY2026 file access (EVT-00284-00309), and `vssadmin.exe delete shadows /all /quiet` (EVT-00314).
5. Mass Exfiltration via Proxy (Critical): Archive creation `7z.exe a archive.7z` on `WS-018` (EVT-00428) and 22 consecutive HTTP POST uploads to `198.51.100.88:443` (EVT-00430 to EVT-00461).
6. Persistence & Web Shell RCE (Critical): Scheduled Task `UpdateCheck` (EVT-00523), Trojan service `WinUpdateHelper` (`wuhelper.exe`, EVT-00524), and Web Shell exploitation on `WEB-01` executing `cmd.exe /c whoami` under `IIS APPPOOL` (EVT-00599).

================================================================================
SKILL 4: ENTERPRISE TECHNICAL PDF REPORT GENERATOR (`src/lib/pdf-generator.ts`)
================================================================================
Produce a downloadable, multi-page client report using `jspdf` + `jspdf-autotable` covering all 8 mandatory sections:
1. Resumen ejecutivo (Executive Summary).
2. Hallazgos identificados (Identified Findings with MITRE ATT&CK tags).
3. Explicación técnica de cada hallazgo (In-depth analysis).
4. Evidencias encontradas en los logs (Log_ID, Host, User, Command).
5. Criticidad y justificación (Severity rating & impact rationale).
6. Posible impacto en la organización (Operational, legal, and financial risk).
7. Plan de acción: investigar, contener y remediar (Containment roadmap).
8. Recomendaciones generales de seguridad (Strategic hardening).

================================================================================
SKILL 5: ZERO-VULNERABILITY APPSEC & SECURE CODING (OWASP TOP 10 HARDENED)
================================================================================
You must enforce strict defensive programming and DevSecOps best practices:
1. XSS / INJECTION DEFENSE: Never use `dangerouslySetInnerHTML`. Ensure all log text, command lines, and filenames are rendered as escaped text nodes.
2. SECURE FILE PARSING:
   - Enforce a strict 15MB file size limit to prevent memory exhaustion DoS.
   - Restrict extensions strictly to `.xlsx` and `.csv`.
   - In SheetJS (`xlsx`), explicitly disable formula parsing and evaluation: `{ cellFormula: false, cellHTML: false }` to mitigate prototype pollution and formula injection vulnerabilities.
3. PROMPT INJECTION MITIGATION:
   - Sanitize all log payloads before inserting them into LLM prompt templates.
   - Use strict system role delineation and delimiter blocks (e.g. `"""`) to prevent malicious log content from overriding AI system instructions.
4. SECURE SECRETS HANDLING:
   - Never expose API keys (Groq/OpenAI) on the client side. AI processing must occur in secure Next.js API Routes (`/api/analyze`).
   - Gracefully fallback to deterministic offline rule-based analysis if no API key is provided, never crashing the application.
5. TYPESCRIPT STRICTNESS: Enable full type-safety. No usage of loose `any` types for security-critical telemetry parsing.
