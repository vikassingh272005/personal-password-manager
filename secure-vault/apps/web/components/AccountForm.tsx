'use client';

import { useState } from 'react';
import { generatePassword } from '@/lib/crypto';
import { useVaultStore } from '@/hooks/useVault';
import { RefreshCw } from 'lucide-react';

export interface AccountValues {
  title: string;
  username: string;
  password: string;
  url: string;
  folder: string;
  notes: string;
  favorite: boolean;
}

export function AccountForm({
  initial,
  onCancel,
  onSubmit,
}: {
  /** Prefill for editing an existing entry. */
  initial?: Partial<AccountValues>;
  onCancel: () => void;
  onSubmit: (values: AccountValues) => void;
}) {
  const { folders } = useVaultStore();
  const [title, setTitle] = useState(initial?.title ?? '');
  const [username, setUsername] = useState(initial?.username ?? '');
  const [password, setPassword] = useState(initial?.password ?? '');
  const [url, setUrl] = useState(initial?.url ?? '');
  const [folder, setFolder] = useState(initial?.folder ?? '');
  const [notes, setNotes] = useState(initial?.notes ?? '');
  const [favorite, setFavorite] = useState(initial?.favorite ?? false);

  const handleGenerate = () => {
    setPassword(generatePassword(24, true, true, true, true));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({ title, username, password, url, folder, notes, favorite });
  };

  return (
    <form onSubmit={handleSubmit} className="card mt-6 space-y-5 p-6">
      <div>
        <label className="label" htmlFor="title">
          Name
        </label>
        <input
          id="title"
          type="text"
          required
          autoFocus
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="GitHub"
          className="input"
        />
      </div>

      <div>
        <label className="label" htmlFor="username">
          Username / Email
        </label>
        <input
          id="username"
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="user@example.com"
          className="input"
        />
      </div>

      <div>
        <label className="label" htmlFor="password">
          Password
        </label>
        <div className="flex gap-2">
          <input
            id="password"
            type="text"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••••••"
            className="input font-mono"
          />
          <button
            type="button"
            onClick={handleGenerate}
            className="btn-ghost shrink-0"
            title="Generate a strong password"
          >
            <RefreshCw className="h-4 w-4" />
            Generate
          </button>
        </div>
      </div>

      <div>
        <label className="label" htmlFor="url">
          Website
        </label>
        <input
          id="url"
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://github.com"
          className="input"
        />
      </div>

      <div>
        <label className="label" htmlFor="folder">
          Folder
        </label>
        <input
          id="folder"
          type="text"
          value={folder}
          onChange={(e) => setFolder(e.target.value)}
          placeholder="Development"
          list="folder-list"
          className="input"
        />
        <datalist id="folder-list">
          {folders.map((f) => (
            <option key={f} value={f} />
          ))}
        </datalist>
      </div>

      <div>
        <label className="label" htmlFor="notes">
          Notes
        </label>
        <textarea
          id="notes"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          rows={3}
          className="input resize-none"
        />
      </div>

      <label className="flex w-fit cursor-pointer items-center gap-2.5 text-sm">
        <input
          type="checkbox"
          checked={favorite}
          onChange={(e) => setFavorite(e.target.checked)}
          className="h-4 w-4 cursor-pointer rounded accent-primary"
        />
        Mark as favorite
      </label>

      <div className="flex gap-3 border-t border-border/60 pt-5">
        <button type="button" onClick={onCancel} className="btn-ghost">
          Cancel
        </button>
        <button type="submit" className="btn-primary">
          {initial ? 'Save Changes' : 'Save'}
        </button>
      </div>
    </form>
  );
}
