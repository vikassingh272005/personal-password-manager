'use client';

import { PasswordGenerator } from '@/components/PasswordGenerator';

export default function GeneratorPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Generator</h1>
        <p className="mt-1 text-muted-foreground">
          Generate strong passwords locally using cryptographically secure randomness.
        </p>
      </div>

      <PasswordGenerator />
    </div>
  );
}
