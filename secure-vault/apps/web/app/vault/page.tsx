'use client';

import { useVaultStore } from '@/hooks/useVault';
import { SyncStatus } from '@/components/SyncStatus';
import { SearchBar, SecureXLogo, VaultRow } from '@/components/SecureX';
import { getPasswordStrength } from '@/lib/crypto';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Plus, KeyRound } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';

type Tab = 'today' | 'important' | 'all';

export default function VaultPage() {
  const router = useRouter();
  const { isLocked, getFilteredItems, setSearchQuery, searchQuery, setSelectedItem } = useVaultStore();
  const [tab, setTab] = useState<Tab>('all');

  useEffect(() => {
    if (isLocked) {
      router.replace('/unlock');
    }
  }, [isLocked, router]);

  const items = useMemo(() => {
    const all = getFilteredItems();
    if (tab === 'important') return all.filter((i) => i.favorite);
    if (tab === 'today') {
      const day = 24 * 60 * 60 * 1000;
      return all.filter((i) => Date.now() - new Date(i.updated_at).getTime() < day);
    }
    return all;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, searchQuery, getFilteredItems]);

  if (isLocked) {
    return null;
  }

  const copyPassword = async (pw?: string) => {
    if (!pw) return;
    await navigator.clipboard.writeText(pw);
    setTimeout(() => navigator.clipboard.writeText(''), 30000);
  };

  return (
    <div className="mx-auto max-w-xl space-y-4 pb-10">
      <div className="flex items-center justify-between px-1 pt-2">
        <SecureXLogo />
        <Link href="/settings" className="icon-disc !h-9 !w-9 text-white/70">
          ≡
        </Link>
      </div>

      <h1 className="px-1 text-[26px] font-semibold leading-tight tracking-tight text-white">
        Keep ◉ Safe
        <br />
        Your Accounts!
      </h1>

      <SearchBar value={searchQuery} onChange={setSearchQuery} placeholder="Search account, name" />

      <div className="flex items-center justify-between gap-2">
        <div className="flex gap-2">
          {(
            [
              { id: 'today', label: 'Today' },
              { id: 'important', label: 'Important' },
              { id: 'all', label: 'All Secured' },
            ] as { id: Tab; label: string }[]
          ).map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`tab-pill border ${tab === t.id ? 'tab-pill-active border-transparent' : 'border-white/10'}`}
            >
              {t.label}
            </button>
          ))}
        </div>
        <SyncStatus />
      </div>

      <div className="space-y-2.5">
        {items.length === 0 ? (
          <div className="glass flex flex-col items-center gap-3 border-dashed p-12 text-center">
            <div className="icon-disc">
              <KeyRound className="h-5 w-5 text-white" />
            </div>
            <p className="max-w-xs text-sm text-white/55">
              {searchQuery
                ? 'No accounts match your search.'
                : tab === 'important'
                  ? 'No favorites yet. Star an account to pin it here.'
                  : tab === 'today'
                    ? 'Nothing changed in the last 24 hours.'
                    : 'No accounts yet. Add your first one to get started.'}
            </p>
            <Link href="/vault/new" className="btn-primary mt-1">
              <Plus className="h-4 w-4" />
              Add Account
            </Link>
          </div>
        ) : (
          items.map((item) => {
            const strength = item.password ? getPasswordStrength(item.password) : null;
            const score = strength ? Math.min(10, Math.max(1, Math.round(((strength.score + 1) / 4) * 10))) : 5;
            return (
              <VaultRow
                key={item.id}
                title={item.title}
                subtitle={item.username || item.urls[0]}
                url={item.urls[0]}
                secretPreview={item.password ? '••••••' : undefined}
                strength={score}
                onCopy={() => copyPassword(item.password)}
                onOpen={() => {
                  setSelectedItem(item);
                  router.push(`/vault/${item.id}`);
                }}
              />
            );
          })
        )}
      </div>
    </div>
  );
}
