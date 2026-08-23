import "@hanzo/font/css"
import "./global.css"
import { RootProvider } from "fumadocs-ui/provider/next"
import type { ReactNode } from "react"

export const metadata = {
  title: {
    default: "Ledger Integration Documentation",
    template: "%s | Ledger Integration",
  },
  description: "Hardware wallet integration for Ledger devices",
}

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-svh bg-background font-sans antialiased">
        <RootProvider
          search={{
            enabled: true,
          }}
          theme={{
            enabled: true,
            defaultTheme: "dark",
          }}
        >
          <div className="relative flex min-h-svh flex-col bg-background">
            {children}
          </div>
        </RootProvider>
      </body>
    </html>
  )
}
