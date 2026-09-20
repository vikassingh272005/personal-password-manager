import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import { Sidebar } from '@/components/Sidebar';
import { BottomNav } from '@/components/SecureX';
import { VaultSyncManager } from '@/hooks/useVaultSync';
import '@/styles/globals.css';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'SecureX — Your Passwords, Safely Secured',
  description: 'Zero-knowledge password manager with a royal-charcoal glass interface',
};

export const viewport = {
  themeColor: '#1e2023',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={inter.variable}>
      <body className="dark">
        <VaultSyncManager />
        <div className="flex min-h-screen bg-background text-foreground">
          <Sidebar />
          <main className="relative flex-1 overflow-y-auto pb-28 md:pb-0">
            <div
              aria-hidden
              className="pointer-events-none fixed inset-0 z-0 bg-[radial-gradient(60%_45%_at_15%_-10%,rgba(255,255,255,0.07),transparent_70%),radial-gradient(45%_35%_at_95%_110%,rgba(255,255,255,0.04),transparent_70%)]"
            />
            <div className="relative z-10 mx-auto max-w-6xl p-4 sm:p-8">{children}</div>
          </main>
        </div>
        <BottomNav />
      </body>
    </html>
  );
}
