'use client';

import { useEffect } from 'react';
import { useVaultStore } from '@/hooks/useVault';
import { AccountForm } from '@/components/AccountForm';
import { useRouter } from 'next/navigation';
import { ArrowLeft } from 'lucide-react';

export default function NewAccountPage() {
  const router = useRouter();
  const { isLocked, addItem } = useVaultStore();

  // Vault pages require an unlocked vault (same guard as /vault).
  useEffect(() => {
    if (isLocked) {
      router.replace('/unlock');
    }
  }, [isLocked, router]);

  if (isLocked) {
    return null;
  }

  return (
    <div className="mx-auto max-w-2xl">
      <button
        onClick={() => router.push('/vault')}
        className="mb-6 inline-flex cursor-pointer items-center gap-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Vault
      </button>

      <h1 className="text-2xl font-bold tracking-tight">Add Account</h1>
      <p className="mt-1.5 text-sm text-muted-foreground">
        Encrypted on this device and synced to your vault when you save — only
        your master password can decrypt it.
      </p>

      <AccountForm
        onCancel={() => router.push('/vault')}
        onSubmit={(values) => {
          const now = new Date().toISOString();
          addItem({
            id: crypto.randomUUID(),
            type: 'login',
            title: values.title,
            username: values.username || undefined,
            password: values.password || undefined,
            urls: values.url ? [values.url] : [],
            notes: values.notes || undefined,
            favorite: values.favorite,
            folder: values.folder || undefined,
            created_at: now,
            updated_at: now,
          });
          router.push('/vault');
        }}
      />
    </div>
  );
}
