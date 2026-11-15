import { useState } from 'react';

import { Text, useComputedColorScheme } from '@mantine/core';

export const BrandingLogo = () => {
  const mode = useComputedColorScheme('dark');
  const src = `/api/branding/assets/logo${mode === 'dark' ? 'Dark' : 'Light'}/`;
  const [failed, setFailed] = useState<string | null>(null);
  if (failed === src) return <Text fz={20}>Alertmanager</Text>;
  return (
    <img
      src={src}
      alt="OSCAR — Alertmanager home"
      width={140}
      height={32}
      style={{ objectFit: 'contain' }}
      onError={() => setFailed(src)}
    />
  );
};
