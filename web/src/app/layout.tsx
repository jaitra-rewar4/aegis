import type { Metadata } from "next";
import { Archivo, IBM_Plex_Sans, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";
import { SmoothScroll } from "@/components/smooth-scroll";
import { DecisionField } from "@/components/decision-field";
import { ScrollRail } from "@/components/scroll-rail";
import { Footer } from "@/components/footer";

const display = Archivo({
  variable: "--font-display",
  subsets: ["latin"],
  weight: ["500", "600", "700", "800"],
});

const sans = IBM_Plex_Sans({
  variable: "--font-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

const mono = IBM_Plex_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

export const metadata: Metadata = {
  title: "Aegis — deterministic action-layer policy for AI agents",
  description:
    "Guardrails check what an agent says. Aegis governs what it does — allow or deny at the tool-call boundary, deterministically, with a trajectory-aware audit trail.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${display.variable} ${sans.variable} ${mono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <DecisionField />
        <SmoothScroll>
          {children}
          <Footer />
        </SmoothScroll>
        <ScrollRail />
      </body>
    </html>
  );
}
