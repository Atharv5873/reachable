import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import { Suspense } from "react";

import { AppShell, ShellFallback } from "@/components/shell/app-shell";
import { TooltipProvider } from "@/components/ui/tooltip";
import { WorkspaceProvider } from "@/lib/workspace";

import "./globals.css";

const sans = IBM_Plex_Sans({
  variable: "--font-plex-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

const mono = IBM_Plex_Mono({
  variable: "--font-plex-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

export const metadata: Metadata = {
  title: "Reachable",
  description:
    "Triage scanner findings by what an attacker can actually reach. Attack paths, minimum fix sets and the decisions behind them, in a graph.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`dark ${sans.variable} ${mono.variable} antialiased`}>
      <body>
        <TooltipProvider delayDuration={250}>
          {/* The workspace reads the URL (useSearchParams), so it renders at
              request time inside a Suspense boundary; the shell is static. */}
          <Suspense fallback={<ShellFallback />}>
            <WorkspaceProvider>
              <AppShell>{children}</AppShell>
            </WorkspaceProvider>
          </Suspense>
        </TooltipProvider>
      </body>
    </html>
  );
}
