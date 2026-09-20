'use client';

import { useEffect, useCallback } from 'react';
import { useVaultStore } from '@/hooks/useVault';

export function useAutoLock() {
  const { isLocked, lockTimeout, lastActivity, updateActivity, lock } = useVaultStore();

  const handleActivity = useCallback(() => {
    updateActivity();
  }, [updateActivity]);

  useEffect(() => {
    if (isLocked) return;

    const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    events.forEach((event) => window.addEventListener(event, handleActivity));

    return () => {
      events.forEach((event) => window.removeEventListener(event, handleActivity));
    };
  }, [isLocked, handleActivity]);

  useEffect(() => {
    if (isLocked) return;

    const interval = setInterval(() => {
      const elapsed = (Date.now() - lastActivity) / 1000 / 60;
      // lockTimeout 0 means "Never" — only lock when a positive timeout is set.
      if (lockTimeout > 0 && elapsed >= lockTimeout) {
        lock();
      }
    }, 10000);

    return () => clearInterval(interval);
  }, [isLocked, lastActivity, lockTimeout, lock]);
}
