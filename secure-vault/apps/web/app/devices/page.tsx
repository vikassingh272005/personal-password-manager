'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { Smartphone, Laptop, Monitor, RotateCcw, ShieldAlert } from 'lucide-react';

interface Device {
  id: string;
  name: string;
  device_type: string | null;
  last_seen_at: string | null;
  created_at: string;
  is_current: boolean;
}

export default function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.devices
      .list()
      .then(setDevices)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const handleRevoke = async (id: string) => {
    if (!confirm('Revoke this device? This will invalidate its sessions.')) return;
    await api.devices.revoke(id);
    setDevices(devices.filter((d) => d.id !== id));
  };

  const DeviceIcon = ({ type }: { type: string | null }) => {
    switch (type) {
      case 'mobile':
      case 'phone':
        return <Smartphone className="h-5 w-5" />;
      case 'laptop':
        return <Laptop className="h-5 w-5" />;
      default:
        return <Monitor className="h-5 w-5" />;
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Your Devices</h1>
        <p className="mt-1.5 text-muted-foreground">
          Manage devices that can access your encrypted vault.
        </p>
      </div>

      {error && (
        <div className="alert-error flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {loading ? (
        <div className="card flex items-center justify-center p-12 text-sm text-muted-foreground">
          <span className="animate-pulse">Loading devices…</span>
        </div>
      ) : (
        <div className="space-y-3">
          {devices.length === 0 && (
            <div className="card flex flex-col items-center gap-3 border-dashed p-14 text-center">
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/10">
                <Monitor className="h-5 w-5 text-primary" />
              </div>
              <p className="text-sm text-muted-foreground">No devices registered yet.</p>
            </div>
          )}
          {devices.map((device) => (
            <div
              key={device.id}
              className="card flex flex-wrap items-center justify-between gap-4 p-4"
            >
              <div className="flex min-w-0 items-center gap-3.5">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-secondary text-muted-foreground">
                  <DeviceIcon type={device.device_type} />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-medium">{device.name}</span>
                    {device.is_current && (
                      <span className="rounded-md bg-primary/10 px-2 py-0.5 text-xs font-semibold text-primary">
                        Current
                      </span>
                    )}
                  </div>
                  <p className="truncate text-sm text-muted-foreground">
                    {device.last_seen_at
                      ? `Last active: ${new Date(device.last_seen_at).toLocaleString()}`
                      : 'Never seen'}
                  </p>
                </div>
              </div>
              {!device.is_current && (
                <button
                  onClick={() => handleRevoke(device.id)}
                  className="btn-danger"
                >
                  <RotateCcw className="h-4 w-4" />
                  Revoke
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}