'use client';

import { useEffect, useState } from 'react';
import { generatePassword, getPasswordStrength, cn } from '@/lib/crypto';
import { RefreshCw, Copy, Check } from 'lucide-react';

export function PasswordGenerator() {
  const [length, setLength] = useState(24);
  const [uppercase, setUppercase] = useState(true);
  const [lowercase, setLowercase] = useState(true);
  const [numbers, setNumbers] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [password, setPassword] = useState('');
  const [copied, setCopied] = useState(false);

  // Generate client-side only: crypto.getRandomValues must not run during SSR,
  // otherwise the server and client render different passwords and hydration fails.
  useEffect(() => {
    setPassword(generatePassword(24, true, true, true, true));
  }, []);

  const regenerate = () => {
    setPassword(generatePassword(length, uppercase, lowercase, numbers, symbols));
    setCopied(false);
  };

  const handleCopy = async () => {
    await navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => {
      navigator.clipboard.writeText('');
      setCopied(false);
    }, 30000);
  };

  const strength = password ? getPasswordStrength(password) : null;

  return (
    <div className="space-y-6">
      <div className="card p-6">
        <div className="flex items-center justify-between gap-4">
          <h2 className="text-lg font-semibold tracking-tight">Password Generator</h2>
          <button onClick={regenerate} className="btn-primary">
            <RefreshCw className="h-4 w-4" />
            Generate
          </button>
        </div>

        <div className="mt-5 flex items-center justify-between gap-4 rounded-2xl border border-border bg-secondary/60 px-5 py-4">
          {password ? (
            <code className="break-all font-mono text-lg">{password}</code>
          ) : (
            <span className="text-muted-foreground">Generating…</span>
          )}
          <button
            onClick={handleCopy}
            disabled={!password}
            className="cursor-pointer rounded-xl bg-background p-2.5 transition-colors hover:bg-accent disabled:opacity-50"
            aria-label="Copy password"
          >
            {copied ? (
              <Check className="h-5 w-5 text-emerald-400" />
            ) : (
              <Copy className="h-5 w-5" />
            )}
          </button>
        </div>

        <div className="mt-4 flex items-center gap-3">
          <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-secondary">
            <div
              className={cn('h-full rounded-full transition-all', strength?.color)}
              style={{ width: `${((strength?.score ?? 0) + 1) * 25}%` }}
            />
          </div>
          <span className="text-sm font-medium">{strength?.label ?? '—'}</span>
        </div>
      </div>

      <div className="card space-y-6 p-6">
        <div>
          <div className="mb-2 flex items-center justify-between">
            <label className="label !mb-0" htmlFor="pw-length">Length</label>
            <span className="rounded-lg bg-secondary px-2.5 py-1 font-mono text-xs font-semibold">
              {length}
            </span>
          </div>
          <input
            id="pw-length"
            type="range"
            min={8}
            max={64}
            value={length}
            onChange={(e) => {
              setLength(Number(e.target.value));
              setPassword(
                generatePassword(
                  Number(e.target.value),
                  uppercase,
                  lowercase,
                  numbers,
                  symbols
                )
              );
            }}
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          {[
            { label: 'Uppercase', value: uppercase, setter: setUppercase },
            { label: 'Lowercase', value: lowercase, setter: setLowercase },
            { label: 'Numbers', value: numbers, setter: setNumbers },
            { label: 'Symbols', value: symbols, setter: setSymbols },
          ].map((opt) => (
            <label
              key={opt.label}
              className={cn(
                'flex cursor-pointer items-center justify-between gap-3 rounded-xl border px-4 py-3 transition-colors',
                opt.value
                  ? 'border-white/20 bg-white/[0.08] text-foreground'
                  : 'border-border bg-secondary/40 text-muted-foreground hover:border-white/15 hover:bg-secondary/70'
              )}
            >
              <input
                type="checkbox"
                checked={opt.value}
                onChange={(e) => {
                  opt.setter(e.target.checked);
                  setPassword(
                    generatePassword(
                      length,
                      opt.label === 'Uppercase' ? e.target.checked : uppercase,
                      opt.label === 'Lowercase' ? e.target.checked : lowercase,
                      opt.label === 'Numbers' ? e.target.checked : numbers,
                      opt.label === 'Symbols' ? e.target.checked : symbols
                    )
                  );
                }}
                className="peer sr-only"
              />
              <span className="text-sm">{opt.label}</span>
              <span
                aria-hidden
                className={cn(
                  'flex h-5 w-5 shrink-0 items-center justify-center rounded-full border transition-colors',
                  opt.value ? 'border-silver bg-silver text-ink' : 'border-white/20 bg-transparent'
                )}
              >
                {opt.value && <Check className="h-3 w-3" strokeWidth={3} />}
              </span>
            </label>
          ))}
        </div>
      </div>
    </div>
  );
}