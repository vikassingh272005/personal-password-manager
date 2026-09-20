'use client';

import { useParams, useRouter } from 'next/navigation';
import { useVaultStore } from '@/hooks/useVault';
import { SyncStatus } from '@/components/SyncStatus';
import { getPasswordStrength, cn } from '@/lib/crypto';
import { useEffect, useState } from 'react';
import { Eye, EyeOff, Copy, ExternalLink, Trash2, Pencil, Star, ArrowLeft } from 'lucide-react';

export default function VaultItemDetailPage() {
  const { id } = useParams();
  const router = useRouter();
  const { isLocked, items, updateItem, removeItem } = useVaultStore();
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  // Vault pages require an unlocked vault (same guard as /vault).
  useEffect(() => {
    if (isLocked) {
      router.replace('/unlock');
    }
  }, [isLocked, router]);

  if (isLocked) {
    return null;
  }

  const item = items.find((i) => i.id === id);

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

  const handleCopy = async (text: string, field: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(field);
    setTimeout(() => {
      navigator.clipboard.writeText('');
      setCopied(null);
    }, 30000);
  };

  const handleToggleFavorite = () => {
    updateItem(item.id, { favorite: !item.favorite });
  };

  const handleDelete = () => {
    if (confirm(`Delete "${item.title}"? This cannot be undone.`)) {
      removeItem(item.id);
      router.push('/vault');
    }
  };

  const strength = item.password ? getPasswordStrength(item.password) : null;

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <button
        onClick={() => router.push('/vault')}
        className="inline-flex cursor-pointer items-center gap-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Vault
      </button>

      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex min-w-0 items-center gap-4">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br from-vault-500/20 to-vault-700/20 text-lg font-bold text-primary ring-1 ring-primary/20">
            {item.title.charAt(0).toUpperCase()}
          </div>
          <div className="min-w-0">
            <h1 className="truncate text-2xl font-bold tracking-tight">{item.title}</h1>
            <p className="truncate text-sm text-muted-foreground">{item.username}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleToggleFavorite}
            className={`btn-ghost !px-2.5 !py-2 ${item.favorite ? 'text-amber-400' : ''}`}
            aria-label={item.favorite ? 'Remove favorite' : 'Mark favorite'}
          >
            <Star
              className={`h-4 w-4 ${item.favorite ? 'fill-amber-400 text-amber-400' : ''}`}
            />
          </button>
          <button
            onClick={() => router.push(`/vault/${item.id}/edit`)}
            className="btn-ghost !px-2.5 !py-2"
            aria-label="Edit account"
          >
            <Pencil className="h-4 w-4" />
          </button>
          <button
            onClick={handleDelete}
            className="btn-danger !px-2.5 !py-2"
            aria-label="Delete account"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="card space-y-5 p-6">
        {item.username && (
          <div>
            <label className="label">Username</label>
            <div className="flex items-center justify-between gap-2 rounded-xl bg-secondary/60 px-3.5 py-2.5">
              <span className="truncate text-sm">{item.username}</span>
              <button
                onClick={() => handleCopy(item.username!, 'username')}
                className="cursor-pointer rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-background hover:text-foreground"
                aria-label="Copy username"
              >
                {copied === 'username' ? (
                  <span className="text-xs font-semibold text-emerald-400">Copied</span>
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </button>
            </div>
          </div>
        )}

        {item.password && (
          <div>
            <label className="label">Password</label>
            <div className="flex items-center justify-between gap-2 rounded-xl bg-secondary/60 px-3.5 py-2.5">
              <span className="truncate font-mono text-sm">
                {showPassword ? item.password : '••••••••••••'}
              </span>
              <div className="flex shrink-0 items-center gap-0.5">
                <button
                  onClick={() => setShowPassword(!showPassword)}
                  className="cursor-pointer rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-background hover:text-foreground"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
                <button
                  onClick={() => handleCopy(item.password!, 'password')}
                  className="cursor-pointer rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-background hover:text-foreground"
                  aria-label="Copy password"
                >
                  {copied === 'password' ? (
                    <span className="text-xs font-semibold text-emerald-400">Copied</span>
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>
            {strength && (
              <div className="mt-2.5 flex items-center gap-2">
                <div className="h-1 flex-1 overflow-hidden rounded-full bg-secondary">
                  <div
                    className={cn('h-full rounded-full transition-all', strength.color)}
                    style={{ width: `${(strength.score + 1) * 25}%` }}
                  />
                </div>
                <span className="text-xs text-muted-foreground">{strength.label}</span>
              </div>
            )}
          </div>
        )}

        {item.urls.length > 0 && (
          <div>
            <label className="label">Website</label>
            <div className="flex items-center justify-between gap-2 rounded-xl bg-secondary/60 px-3.5 py-2.5">
              <span className="truncate text-sm text-primary">{item.urls[0]}</span>
              <a
                href={item.urls[0]}
                target="_blank"
                rel="noopener noreferrer"
                className="cursor-pointer rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-background hover:text-foreground"
                aria-label="Open website"
              >
                <ExternalLink className="h-4 w-4" />
              </a>
            </div>
          </div>
        )}

        {item.notes && (
          <div>
            <label className="label">Notes</label>
            <p className="whitespace-pre-wrap rounded-xl bg-secondary/60 px-3.5 py-2.5 text-sm">
              {item.notes}
            </p>
          </div>
        )}

        {item.folder && (
          <div>
            <label className="label">Folder</label>
            <span className="inline-flex items-center rounded-lg bg-secondary/60 px-3 py-1.5 text-sm">
              {item.folder}
            </span>
          </div>
        )}
      </div>

      <div className="flex items-center justify-between px-1 text-xs text-muted-foreground">
        <span>Created {new Date(item.created_at).toLocaleDateString()}</span>
        <span>Last changed {new Date(item.updated_at).toLocaleDateString()}</span>
        <SyncStatus />
      </div>
    </div>
  );
}