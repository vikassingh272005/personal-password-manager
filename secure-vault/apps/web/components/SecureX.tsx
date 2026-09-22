'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Home,
  Shield,
  User,
  Plus,
  ChevronRight,
  Search,
  SlidersHorizontal,
  ArrowUpRight,
  Copy,
  Check,
} from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { cn } from '@/lib/crypto';

/* ---------- Brand ---------- */

export function SecureXLogo({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) {
  const box =
    size === 'lg' ? 'h-12 w-12 rounded-2xl' : size === 'sm' ? 'h-8 w-8 rounded-lg' : 'h-9 w-9 rounded-xl';
  return (
    <span className="inline-flex items-center gap-2.5">
      <span
        className={`${box} flex items-center justify-center border border-white/20 bg-gradient-to-b from-white/25 to-white/5 shadow-glass backdrop-blur-xl`}
      >
        <svg viewBox="0 0 24 24" className="h-1/2 w-1/2 text-white" fill="none" stroke="currentColor" strokeWidth={2.4}>
          <path d="M12 2.5 21 7v6c0 5-3.8 8.3-9 9.5C6.8 21.3 3 18 3 13V7l9-4.5Z" strokeLinejoin="round" />
          <path d="M8.5 12h7" strokeLinecap="round" />
        </svg>
      </span>
      <span className="text-[15px] font-semibold tracking-tight text-white">SecureX</span>
    </span>
  );
}

/* ---------- Phone shell (desktop preview of the mobile UI) ---------- */

export function PhoneShell({ children }: { children: ReactNode }) {
  return (
    <div className="relative mx-auto w-full max-w-[400px]">
      <div className="glass overflow-hidden !rounded-[32px] p-0">
        <div className="flex items-center justify-between px-6 pb-1 pt-4 text-[11px] font-medium text-white/80">
          <span>9:41</span>
          <span className="flex items-center gap-1.5">
            <span className="flex items-end gap-[2px]">
              <span className="h-1.5 w-[3px] rounded-sm bg-white/80" />
              <span className="h-2 w-[3px] rounded-sm bg-white/80" />
              <span className="h-2.5 w-[3px] rounded-sm bg-white/80" />
            </span>
            <span className="h-3 w-6 rounded-[4px] border border-white/60 p-[1.5px]">
              <span className="block h-full w-3/4 rounded-[2px] bg-white/90" />
            </span>
          </span>
        </div>
        <div className="px-4 pb-5 pt-2">{children}</div>
        <div className="mx-auto mb-2 h-1 w-28 rounded-full bg-white/40" />
      </div>
    </div>
  );
}

/* ---------- Bottom nav (mobile pattern, also handy on desktop) ---------- */

const NAV = [
  { href: '/dashboard', icon: Home, label: 'Home' },
  { href: '/security', icon: Shield, label: 'Security' },
  { href: '/settings', icon: User, label: 'Profile' },
];

const AUTH_ROUTES = ['/login', '/register', '/unlock'];

export function BottomNav() {
  const pathname = usePathname();
  const router = useRouter();
  // Auth screens use the minimal AuthHeader — never the marketing dock.
  if (pathname && AUTH_ROUTES.some((r) => pathname === r || pathname.startsWith(r + '/')))
    return null;
  return (
    <nav className="pointer-events-none fixed bottom-5 left-0 right-0 z-40 flex justify-center px-4 md:hidden">
      <div className="pointer-events-auto flex items-center gap-1.5 rounded-full border border-white/15 bg-ink-soft/85 py-2 pl-2 pr-2 shadow-glass backdrop-blur-2xl">
        {NAV.map((item) => {
          const active = pathname === item.href || pathname?.startsWith(item.href + '/');
          return (
            <Link
              key={item.href}
              href={item.href}
              aria-label={item.label}
              className={cn(
                'flex h-11 w-11 items-center justify-center rounded-full transition-all',
                active
                  ? 'bg-silver text-ink shadow-pill'
                  : 'text-white/60 hover:bg-white/10 hover:text-white'
              )}
            >
              <item.icon className="h-5 w-5" />
            </Link>
          );
        })}
        <button
          onClick={() => router.push('/vault/new')}
          aria-label="Add account"
          className="ml-1 flex h-12 w-12 cursor-pointer items-center justify-center rounded-full bg-silver text-ink shadow-pill transition-transform hover:scale-105 active:scale-95"
        >
          <Plus className="h-6 w-6" strokeWidth={2.5} />
        </button>
      </div>
    </nav>
  );
}

/* ---------- Auth header (login / register / unlock): brand + sign-in link only ---------- */

export function AuthHeader() {
  return (
    <header className="flex items-center justify-between px-1 pb-6 pt-2">
      <Link href="/" className="inline-flex items-center gap-2.5 rounded-lg" aria-label="SecureX home">
        <SecureXLogo />
      </Link>
      <Link
        href="/login"
        className="glass-pill px-4 py-2 text-xs font-semibold text-white/85 transition-colors hover:text-white"
      >
        Sign in
      </Link>
    </header>
  );
}

/* ---------- Search ---------- */

export function SearchBar({
  value,
  onChange,
  placeholder = 'Search account, name',
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <div className="search-pill">
      <Search className="h-4 w-4 shrink-0 text-white/60" />
      <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
      <SlidersHorizontal className="h-4 w-4 shrink-0 text-white/60" />
    </div>
  );
}

/* ---------- Vault row (matches the account list mockup) ---------- */

export function VaultRow({
  icon,
  title,
  subtitle,
  url,
  secretPreview,
  strength = 10,
  onCopy,
  onOpen,
}: {
  icon?: ReactNode;
  title: string;
  subtitle?: string;
  url?: string;
  secretPreview?: string;
  strength?: number;
  onCopy?: () => void;
  onOpen?: () => void;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="glass-row cursor-pointer" onClick={onOpen}>
      <span className="icon-disc overflow-hidden text-sm font-bold text-white">
        {icon ?? title.charAt(0).toUpperCase()}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-semibold text-white">{title}</span>
        {subtitle && <span className="block truncate text-[11px] text-white/50">{subtitle}</span>}
        {url && <span className="block truncate text-[11px] text-white/35">{url}</span>}
      </span>
      {secretPreview && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onCopy?.();
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
          className="flex shrink-0 items-center gap-1.5 text-[11px] text-white/60 hover:text-white"
          aria-label="Copy password"
        >
          {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
          <span className="font-mono">{copied ? 'copied' : secretPreview}</span>
        </button>
      )}
      <span
        className={cn(
          'strength-ring',
          strength >= 8
            ? 'border-emerald-400/40 text-emerald-300'
            : strength >= 5
              ? 'border-amber-400/40 text-amber-300'
              : 'border-red-400/40 text-red-300'
        )}
      >
        {strength}
      </span>
    </div>
  );
}

/* ---------- Health row (matches the Password Health mockup) ---------- */

export function HealthRow({
  icon,
  badge,
  title,
  subtitle,
  href,
}: {
  icon: ReactNode;
  badge?: number | string;
  title: string;
  subtitle: string;
  href: string;
}) {
  return (
    <Link href={href} className="glass-row">
      <span className="relative">
        <span className="icon-disc">{icon}</span>
        {badge !== undefined && (
          <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[9px] font-bold text-white">
            {badge}
          </span>
        )}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-semibold text-white">{title}</span>
        <span className="block truncate text-[11px] text-white/50">{subtitle}</span>
      </span>
      <ChevronRight className="h-4 w-4 shrink-0 text-white/40" />
    </Link>
  );
}

/* ---------- Promo / banner card ---------- */

export function PromoBanner({
  title,
  subtitle,
  href,
}: {
  title: string;
  subtitle: string;
  href: string;
}) {
  return (
    <Link href={href} className="glass-row">
      <span className="icon-disc">
        <svg viewBox="0 0 24 24" className="h-4 w-4 text-white" fill="none" stroke="currentColor" strokeWidth={2.2}>
          <path d="M7 17 17 7M9 7h8v8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-semibold text-white">{title}</span>
        <span className="block truncate text-[11px] text-white/50">{subtitle}</span>
      </span>
      <ArrowUpRight className="h-4 w-4 shrink-0 text-white/60" />
    </Link>
  );
}

/* ---------- Section heading ---------- */

export function SectionTitle({ children }: { children: ReactNode }) {
  return <h2 className="px-1 text-[13px] font-semibold tracking-wide text-white/80">{children}</h2>;
}
