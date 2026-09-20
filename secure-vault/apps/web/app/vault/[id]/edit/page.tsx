'use client';

import { useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { useVaultStore } from '@/hooks/useVault';
import { AccountForm } from '@/components/AccountForm';
import { ArrowLeft } from 'lucide-react';

export default function EditAccountPage() {
  const { id } = useParams();
  const router = useRouter();
  const { isLocked, items, updateItem } = useVaultStore();

  const itemId = String(id);
  const item = items.find((i) => i.id === itemId);

  // Vault pages require an unlocked vault (same guard as /vault).
  useEffect(() => {
    if (isLocked) {
      router.replace('/unlock');
    }
  }, [isLocked, router]);

  if (isLocked) {
    return null;
  }

  if (!item) {
    return (
      <div className="mx-auto mt-16 max-w-md text-center">
        <p className="text-muted-foreground">Account not found.</p>
        <button onClick={() => router.push('/vault')} className="btn-ghost mt-4">
          Back to Vault
        </button>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl">
      <button
        onClick={() => router.push(`/vault/${item.id}`)}
        className="mb-6 inline-flex cursor-pointer items-center gap-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to {item.title}
      </button>

      <h1 className="text-2xl font-bold tracking-tight">Edit Account</h1>
      <p className="mt-1.5 text-sm text-muted-foreground">
        Changes are encrypted on this device and synced to your vault when you
        save.
      </p>

      <AccountForm
        initial={{
          title: item.title,
          username: item.username ?? '',
          password: item.password ?? '',
          url: item.urls[0] ?? '',
          folder: item.folder ?? '',
          notes: item.notes ?? '',
          favorite: item.favorite,
        }}
        onCancel={() => router.push(`/vault/${item.id}`)}
        onSubmit={(values) => {
          updateItem(item.id, {
            title: values.title,
            username: values.username || undefined,
            password: values.password || undefined,
            urls: values.url ? [values.url] : [],
            notes: values.notes || undefined,
            favorite: values.favorite,
            folder: values.folder || undefined,
            updated_at: new Date().toISOString(),
          });
          router.push(`/vault/${item.id}`);
        }}
      />
    </div>
  );
}
