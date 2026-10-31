import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";

import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

/** Monoespaciada estricta para Log_IDs, IPs, timestamps y comandos (SKILL 2). */
const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "SOC N2 · AI Investigator",
  description:
    "Plataforma de investigacion de incidentes para analistas SOC Nivel 2: ingesta de telemetria SIEM, " +
    "correlacion de la cadena de ataque e informe tecnico en PDF.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: "#080B10",
  colorScheme: "dark",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="es"
      className={`${inter.variable} ${jetbrainsMono.variable} h-full antialiased`}
    >
      <body className="min-h-full bg-canvas text-ink">{children}</body>
    </html>
  );
}
