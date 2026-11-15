import { MantineProvider } from '@mantine/core';
import { fireEvent, render, screen } from '@testing-library/react';

import { BrandingLogo } from './BrandingLogo';

it('uses the managed logo for each appearance and keeps an accessible failure fallback', () => {
  const { rerender } = render(
    <MantineProvider forceColorScheme="dark">
      <BrandingLogo />
    </MantineProvider>
  );
  expect(screen.getByRole('img')).toHaveAttribute('src', '/api/branding/assets/logoDark/');
  rerender(
    <MantineProvider forceColorScheme="light">
      <BrandingLogo />
    </MantineProvider>
  );
  expect(screen.getByRole('img')).toHaveAttribute('src', '/api/branding/assets/logoLight/');
  fireEvent.error(screen.getByRole('img'));
  expect(screen.getByText('Alertmanager')).toBeInTheDocument();
});
