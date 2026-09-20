'use client';

import { cn, getPasswordStrength } from '@/lib/crypto';
import { Eye, EyeOff, Copy, Star } from 'lucide-react';
import { useState } from 'react';

interface VaultItemCardProps {
  item: {
    id: string;
    title: string;
    username?: string;
    password?: string;
    urls: string[];
    folder?: string;
    favorite: boolean;
    updated_at: string;
  };
  onSelect: (item: any) => void;
}

export function VaultItemCard({ item, onSelect }: VaultItemCardProps) {
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const handleCopy = async (text: string, field: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(field);
    setTimeout(() => {
      navigator.clipboard.writeText('');
      setCopied(null);
    }, 30000);
  };

  const strength = item.password ? getPasswordStrength(item.password) : null;

  return (
    <div
      className="glass group cursor-pointer p-5 transition-all hover:-translate-y-0.5 hover:border-white/20"
      onClick={() => onSelect(item)}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <div className="icon-disc text-sm font-bold text-white">
            {item.title.charAt(0).toUpperCase()}
          </div>
          <div className="min-w-0">
            <h3 className="truncate font-semibold tracking-tight">{item.title}</h3>
            <p className="truncate text-sm text-muted-foreground">{item.username}</p>
          </div>
        </div>
        {item.favorite && (
          <Star className="h-4 w-4 shrink-0 fill-amber-400 text-amber-400" />
        )}
      </div>

      <div className="mt-4 space-y-2">
        {item.password && (
          <div className="flex items-center justify-between gap-2 rounded-2xl border border-white/10 bg-white/[0.04] px-3 py-2">
            <span className="truncate font-mono text-sm">
              {showPassword ? item.password : '••••••••••••'}
            </span>
            <div className="flex shrink-0 items-center gap-0.5">
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setShowPassword(!showPassword);
                }}
                className="cursor-pointer rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-background hover:text-foreground"
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleCopy(item.password!, 'password');
                }}
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
        )}

        {strength && (
          <div className="flex items-center gap-2">
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

      <div className="mt-4 flex items-center justify-between border-t border-border/60 pt-3 text-xs text-muted-foreground">
        <span>{item.folder || 'No folder'}</span>
        <span>{new Date(item.updated_at).toLocaleDateString()}</span>
      </div>
    </div>
  );
}