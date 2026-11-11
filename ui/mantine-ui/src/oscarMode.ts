import { useEffect, useState } from 'react';

type OscarMode = 'light' | 'dark';

const normalizeMode = (value: unknown): OscarMode | null => {
  if (value === 'light' || value === 'semi-dark') return 'light';
  if (value === 'dark') return 'dark';
  return null;
};

export const readOscarMode = (): OscarMode => {
  const cookie = document.cookie
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith('oscar-ui-mode='));
  const cookieMode = normalizeMode(cookie?.slice('oscar-ui-mode='.length));
  if (cookieMode) return cookieMode;

  try {
    const settings = JSON.parse(window.localStorage.getItem('settings') || 'null');
    const storedMode = normalizeMode(settings?.mode);
    if (storedMode) return storedMode;
  } catch {
    // The native page can still use OSCAR's default appearance.
  }
  return 'dark';
};

export const useOscarMode = (): OscarMode => {
  const [mode, setMode] = useState(readOscarMode);

  useEffect(() => {
    const refresh = () => setMode(readOscarMode());
    window.addEventListener('storage', refresh);
    document.addEventListener('visibilitychange', refresh);
    return () => {
      window.removeEventListener('storage', refresh);
      document.removeEventListener('visibilitychange', refresh);
    };
  }, []);

  return mode;
};
