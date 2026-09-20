'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/crypto';
import { SecureXLogo } from '@/components/SecureX';
import {
  LayoutDashboard,
  KeyRound,
  Shield,
  Radar,
  Smartphone,
  LogOut,
  Lock,
  Sparkles,
  Activity,
  Settings,
} from 'lucide-react';
import { useAuthStore } from '@/hooks/useAuth';
import { useAutoLock } from '@/hooks/useAutoLock';
import { useVaultStore } from '@/hooks/useVault';
import { api } from '@/lib/api';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';

const baseNavigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Vault', href: '/vault', icon: KeyRound },
  { name: 'Generator', href: '/generator', icon: Sparkles },
  { name: 'Security', href: '/security', icon: Shield },
  { name: 'Dark Web Monitor', href: '/monitor', icon: Radar },
  { name: 'Devices', href: '/devices', icon: Smartphone },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { isLocked, lock } = useVaultStore();
  const { user, refresh, clear } = useAuthStore();
  const [signingOut, setSigningOut] = useState(false);

  // Mounted here (every page, via the root layout) so auto-lock applies
  // regardless of which page is showing the vault.
  useAutoLock();

  // Re-check identity whenever the route changes so the Admin entry appears
  // (or disappears) as soon as the session role is known.
  useEffect(() => {
    refresh();
  }, [pathname]);

  const navigation =
    user?.role === 'admin'
      ? [
          ...baseNavigation.slice(0, baseNavigation.length - 1),
          { name: 'Admin', href: '/admin', icon: Activity },
          baseNavigation[baseNavigation.length - 1],
        ]
      : baseNavigation;

  return (
    <aside className="hidden h-screen w-64 shrink-0 flex-col border-r border-white/10 bg-ink-soft/60 backdrop-blur-xl md:flex">
      <div className="px-5 pb-5 pt-6">
        <SecureXLogo />
      </div>

      <nav className="flex-1 space-y-1 px-3">
        {navigation.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.name}
              href={isLocked ? '/unlock' : item.href}
              className={cn(
                'group relative flex items-center gap-3 rounded-2xl px-3 py-2.5 text-sm font-medium transition-colors',
                isActive
                  ? 'border border-white/15 bg-white/[0.08] text-white shadow-card backdrop-blur-xl'
                  : 'text-white/55 hover:bg-white/[0.05] hover:text-white'
              )}
            >
              <item.icon
                className={cn(
                  'h-[18px] w-[18px] transition-colors',
                  isActive ? 'text-white' : 'text-white/45 group-hover:text-white'
                )}
              />
              {item.name}
              {isActive && (
                <span className="absolute right-2.5 h-1.5 w-1.5 rounded-full bg-white shadow-[0_0_8px_rgba(255,255,255,0.8)]" />
              )}
            </Link>
          );
        })}
      </nav>

      <div className="space-y-1 border-t border-border p-3">
        <div className="flex items-center gap-2.5 rounded-xl px-3 py-2.5">
          <span className="relative flex h-2 w-2">
            <span
              className={cn(
                'absolute inline-flex h-full w-full animate-ping rounded-full opacity-60',
                isLocked ? 'bg-red-500' : 'bg-emerald-500'
              )}
            />
            <span
              className={cn(
                'relative inline-flex h-2 w-2 rounded-full',
                isLocked ? 'bg-red-500' : 'bg-emerald-500'
              )}
            />
          </span>
          <span className="text-xs font-medium text-muted-foreground">
            {isLocked ? 'Vault locked' : 'Vault unlocked'}
          </span>
        </div>
        {!isLocked && (
          <button
            onClick={lock}
            className="flex w-full cursor-pointer items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          >
            <Lock className="h-[18px] w-[18px]" />
            Lock Vault
          </button>
        )}
        {user && (
          <button
            onClick={async () => {
              setSigningOut(true);
              try {
                await api.auth.logout();
              } catch {
                // Session may already be gone (expired / revoked); the local
                // cleanup below is what matters — never surface a rejection.
              } finally {
                clear();
                lock(); // drop the decrypted vault key too
                setSigningOut(false);
                router.push('/login');
              }
            }}
            disabled={signingOut}
            className="flex w-full cursor-pointer items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:pointer-events-none disabled:opacity-50"
          >
            <LogOut className="h-[18px] w-[18px]" />
            {signingOut ? 'Signing out…' : 'Sign out'}
          </button>
        )}
      </div>
    </aside>
  );
}