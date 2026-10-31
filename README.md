# SOC N2 · AI Investigator

### SIEM Triage & Incident Response SaaS Platform

[![Live App](https://img.shields.io/badge/Live-soc.optimalabs.cloud-00E5FF?style=for-the-badge)](https://soc.optimalabs.cloud)
[![Next.js](https://img.shields.io/badge/Next.js-16-000000?style=for-the-badge&logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Recharts](https://img.shields.io/badge/Recharts-3-FF0055?style=for-the-badge)](https://recharts.org/)
[![Docker](https://img.shields.io/badge/Docker-Standalone-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)

**🔴 Live demo: [https://soc.optimalabs.cloud](https://soc.optimalabs.cloud)**

SOC N2 · AI Investigator is a SaaS-grade incident response and SIEM triage platform. Upload a SIEM log export (`.xlsx` / `.csv`). The app parses the telemetry in the browser, correlates suspicious events into a multi-stage attack kill chain, and classifies every finding by severity with a written justification. It then produces a client-ready technical report as a PDF. An optional AI layer helps with analysis and report writing. Without it, the app falls back to a deterministic offline engine.

---

## 👤 Author

**Melvin Ramírez Ramírez**
Lead Security Engineer & Founder of **OptimaLabs Cloud Solutions**

This project is the **Final Challenge (Reto Final) of the SOC Analyst Level 2 Bootcamp** (*Bootcamp Analista SOC Nivel 2*): *"Investigating a possible security incident: from SIEM logs to a professional technical report, with an AI-assisted web application."*

---

## 🇸🇪 The Case: Stockholm

You are the new **SOC Tier 2 Analyst** at a cybersecurity consultancy in **Stockholm, Sweden**. A client reports a possible incident in its infrastructure and hands over an Excel file with logs exported from its SIEM.

**Mission:** find Indicators of Compromise (IoCs), correlate the events, and determine whether one or several incidents took place. Every conclusion must be supported by the records provided. **No invented findings.**

The investigation shows a coordinated, multi-stage intrusion. It spans the domain controller (`DC-01`), an application server (`APP-SRV01`), the finance file server (`FS-SRV01`), a workstation (`WS-018`), and the public web server (`WEB-01`).

---

## ⛓️ Correlated Kill Chain (6 Phases)

Every phase is backed by real `Log_ID` evidence from the dataset and mapped to MITRE ATT&CK techniques.

| # | Phase | Severity | Key Evidence (Log_IDs) | MITRE ATT&CK |
|---|-------|----------|------------------------|--------------|
| 1 | **Password Spraying → Account Compromise** | 🔴 Critical | Event 4625 from `203.0.113.74` against `DC-01` across multiple accounts (`EVT-00057`–`EVT-00111`); successful logon as `CORP\mgarcia` (`EVT-00123`); special privileges assigned (`EVT-00126`) | **TA0006 Credential Access / TA0001 Initial Access** · T1110.003 Password Spraying · T1078 Valid Accounts · T1078.002 Domain Accounts · T1134 Access Token Manipulation |
| 2 | **External RDP Breach** | 🔴 Critical | Event 4624 (LogonType=10) from `198.51.100.77` to `APP-SRV01` as `CORP\admin` (`EVT-00188`) | **TA0001 Initial Access / TA0008 Lateral Movement** · T1133 External Remote Services · T1021.001 Remote Desktop Protocol · T1078 Valid Accounts |
| 3 | **Process Obfuscation & Discovery** | 🟠 High | PowerShell `-EncodedCommand` (`EVT-00198`); `Get-LocalGroupMember` (`EVT-00207`); `net view` (`EVT-00214`) | **TA0002 Execution / TA0005 Defense Evasion / TA0007 Discovery** · T1059.001 PowerShell · T1027 Obfuscated Files or Information · T1087 Account Discovery · T1135 Network Share Discovery |
| 4 | **Ransomware Staging & Shadow Copy Deletion** | 🔴 Critical | Access to `\\FS-SRV01\Finance`; `Budget2027.xlsx` accessed (`EVT-00231`); `tar.exe` compression (`EVT-00232`); mass FY2026 file access (`EVT-00284`–`EVT-00309`); `vssadmin.exe delete shadows /all /quiet` (`EVT-00314`) | **TA0008 Lateral Movement / TA0009 Collection / TA0040 Impact** · T1021.002 SMB/Admin Shares · T1039 Data from Network Shared Drive · T1083 File & Directory Discovery · T1560.001 Archive via Utility · T1490 Inhibit System Recovery |
| 5 | **Mass Exfiltration via Proxy** | 🔴 Critical | `7z.exe a archive.7z` on `WS-018` (`EVT-00428`); 22 consecutive HTTP POST uploads to `198.51.100.88:443` (`EVT-00430`–`EVT-00461`) | **TA0009 Collection / TA0010 Exfiltration / TA0011 Command & Control** · T1560.001 Archive via Utility · T1041 Exfiltration Over C2 Channel · T1567.002 Exfiltration to Cloud Storage · T1071.001 Web Protocols |
| 6 | **Persistence & Web Shell RCE** | 🔴 Critical | Scheduled task `UpdateCheck` (`EVT-00523`); trojan service `WinUpdateHelper` / `wuhelper.exe` (`EVT-00524`); web shell on `WEB-01` running `cmd.exe /c whoami` as `IIS APPPOOL` (`EVT-00599`) | **TA0003 Persistence / TA0002 Execution / TA0007 Discovery** · T1053.005 Scheduled Task · T1543.003 Windows Service · T1505.003 Web Shell · T1059.003 Windows Command Shell · T1033 System Owner/User Discovery |

### Indicators of Compromise

| Type | Value | Context |
|------|-------|---------|
| IPv4 | `203.0.113.74` | Password spraying source against `DC-01` |
| IPv4 | `198.51.100.77` | External RDP logon to `APP-SRV01` |
| IPv4 | `198.51.100.88:443` | Exfiltration endpoint (HTTP POST uploads) |
| Account | `CORP\mgarcia`, `CORP\admin` | Compromised identities |
| Scheduled Task | `UpdateCheck` | Persistence |
| Service / Binary | `WinUpdateHelper` / `wuhelper.exe` | Trojan service persistence |
| Command | `vssadmin.exe delete shadows /all /quiet` | Recovery inhibition |

---

## ✨ Capabilities

| # | Feature | Description |
|---|---------|-------------|
| 01 | **File ingestion** | Imports and previews SIEM exports in `.xlsx` and `.csv`. Parsing runs in the browser. |
| 02 | **Detection & correlation engine** | Rule-based detector (`src/lib/detector.ts`) that flags suspicious events and links them across hosts, users, and time into the kill chain above. |
| 03 | **Interactive dashboard** | Recharts visualizations of severity distribution, event timelines, and affected hosts and users. |
| 04 | **Risk classification** | Every finding is rated **Critical / High / Medium / Low** with a written justification and an impact statement. |
| 05 | **Technical report** | Structured, evidence-backed incident narrative that cites real `Log_ID`s, hosts, users, and IPs. |
| 06 | **PDF export** | Multi-page client report (`jspdf` + `jspdf-autotable`) with the 8 mandatory sections. |
| 07 | **AI-assisted analysis** | Optional Groq LLM synthesis via a server-side API route (`/api/analyze`), with a deterministic offline fallback. |

### PDF report: 8 mandatory sections

1. Executive Summary
2. Identified Findings (with MITRE ATT&CK tags)
3. Technical Explanation of Each Finding
4. Log Evidence (`Log_ID`, host, user, command)
5. Severity & Justification
6. Potential Organizational Impact (operational, legal, financial)
7. Action Plan: Investigate, Contain & Remediate
8. General Security Recommendations

---

## 🛡️ Security by Design (OWASP-Hardened)

- **XSS defense:** no `dangerouslySetInnerHTML`. Log text, command lines, and filenames always render as escaped text nodes.
- **Secure file parsing:** 15 MB upload limit. Only `.xlsx` and `.csv` are accepted. SheetJS runs with `cellFormula: false` and `cellHTML: false` to block formula injection.
- **Prompt-injection mitigation:** log payloads are sanitized (`src/lib/sanitize.ts`) and wrapped in delimiter blocks with strict system/user role separation before they reach the LLM.
- **Secrets handling:** the API key stays on the server. All AI calls go through the Next.js API route `/api/analyze`, and keys never reach the client.
- **Graceful degradation:** if `GROQ_API_KEY` is missing or the model returns an invalid response, the app falls back to the deterministic offline engine instead of failing.
- **Strict TypeScript:** telemetry parsing is fully typed, with no loose `any`.

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | **Next.js 16** (App Router, Turbopack, `output: "standalone"`) |
| UI | **React 19**, **Tailwind CSS 4**, `lucide-react` |
| Language | **TypeScript** (strict) |
| Charts | **Recharts 3** |
| Parsing | SheetJS (`xlsx`) |
| Reporting | `jspdf` + `jspdf-autotable` |
| AI | `groq-sdk` (default model `llama-3.3-70b-versatile`) |
| Deployment | **Docker** (Next.js standalone bundle) |
| Package manager | pnpm |

### Design system

The dark "Falcon / Linear" SOC look: a `#080B10` OLED canvas, frosted-glass panels, a severity palette (Critical `#FF0055`, High `#FF9100`, Medium `#00E5FF`, Low `#00FFA3`), monospace type for Log_IDs, IPs, and commands, and a pulsing live beacon in the header.

---

## 📁 Project Structure

```
src/
├── app/
│   ├── api/analyze/route.ts   # Server-side AI synthesis (Groq) + offline fallback
│   ├── layout.tsx
│   ├── page.tsx               # Main SOC workspace
│   └── globals.css
├── components/
│   ├── AppShell.tsx
│   ├── charts/                # Recharts dashboards
│   └── ui/primitives.tsx
└── lib/
    ├── parser.ts              # Secure .xlsx/.csv ingestion
    ├── detector.ts            # Detection & kill-chain correlation engine
    ├── narrative.ts           # Incident narrative builder
    ├── report.ts              # Report model (8 sections)
    ├── pdf-generator.ts       # PDF export
    ├── ai-contract.ts         # LLM request/response contract
    ├── sanitize.ts            # Prompt-injection & input sanitization
    ├── types.ts
    └── utils.ts
```

---

## 🚀 Getting Started

### Prerequisites

- Node.js 20+
- pnpm 10+

### Local development

```bash
git clone <repository-url>
cd soc-ai-investigator
pnpm install
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000).

### Environment variables (optional)

Create `.env.local`:

```env
GROQ_API_KEY=your_groq_api_key
# Optional override (default: llama-3.3-70b-versatile)
GROQ_MODEL=llama-3.3-70b-versatile
```

Without `GROQ_API_KEY`, the platform still works using the deterministic offline engine.

### Production build

```bash
pnpm build
pnpm start
```

---

## 🐳 Docker

The repository ships a production-ready, multi-stage [`Dockerfile`](Dockerfile) built on the Next.js `standalone` output, plus a hardened [`docker-compose.yml`](docker-compose.yml).

**Image highlights**

- Three build stages (`deps` → `builder` → `runner`). Only the standalone server, `public/` and `.next/static` reach the final image.
- `pnpm` version pinned through Corepack (`packageManager` field), `--frozen-lockfile` installs, and a BuildKit cache mount for the pnpm store.
- Runs as a non-root user (`nextjs`, UID 1001), with a built-in `HEALTHCHECK`.
- `.dockerignore` keeps `.env*`, `.git`, `node_modules` and local build artifacts out of the build context. Secrets are never baked into the image.

**Compose hardening:** read-only root filesystem (`tmpfs` for `/tmp` and the Next.js cache), `no-new-privileges`, all Linux capabilities dropped, CPU/memory limits and log rotation.

> Requires Docker with the **Buildx / BuildKit** plugin (included in Docker Desktop and Docker Engine 23+).

```bash
# Optional: AI-assisted analysis (otherwise the offline engine is used)
echo "GROQ_API_KEY=your_groq_api_key" > .env

docker compose up -d --build
docker compose ps        # wait for "healthy"
docker compose logs -f
```

The app is available at [http://localhost:3000](http://localhost:3000). Set `PORT` in `.env` to change the host port.

Without Compose:

```bash
docker build -t soc-ai-investigator .
docker run -d -p 3000:3000 -e GROQ_API_KEY=your_key soc-ai-investigator
```

---

## 🎯 Usage Workflow

1. **Upload** the client's SIEM export (`.xlsx` / `.csv`).
2. **Review** the parsed telemetry and the dashboard.
3. **Investigate** the correlated findings, severity ratings, and MITRE ATT&CK mappings.
4. **Generate** the AI-assisted (or offline) technical narrative.
5. **Export** the 8-section PDF incident report for the client.

---

## 📜 Analytical Integrity

Every finding, IoC, and timeline entry in this platform comes from the provided SIEM telemetry and is traceable to a specific `Log_ID`. The AI layer only synthesizes and writes up evidence the detection engine has already confirmed. It cannot add findings of its own.

---

## 🏢 About

Built by **Melvin Ramírez Ramírez**, Lead Security Engineer & Founder of **OptimaLabs Cloud Solutions**, as the Final Challenge of the **SOC Analyst Level 2 Bootcamp**.

🌐 **Live:** [https://soc.optimalabs.cloud](https://soc.optimalabs.cloud)
