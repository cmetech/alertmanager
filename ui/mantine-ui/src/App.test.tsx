import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import App from './App';
import headerClasses from './components/Header.module.css';

afterEach(() => {
  window.location.hash = '';
  document.cookie = 'oscar-ui-mode=; Max-Age=0; Path=/';
  vi.unstubAllGlobals();
});

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) =>
      Response.json(
        String(input).includes('/oscar/alerts/page')
          ? {
              contract_version: 2,
              records: [],
              total_records: 0,
              total_pages: 0,
              timing_by_fingerprint: {},
            }
          : []
      )
    )
  );
});

describe('App routing', () => {
  it('renders native alert records from the URL hash', async () => {
    window.location.hash = '#/alerts';

    render(<App />);

    expect(await screen.findByText('No native alerts are currently active.')).toBeInTheDocument();
  });

  it('uses OSCAR mode when opened and follows changes from the OSCAR tab', () => {
    document.cookie = 'oscar-ui-mode=light; Path=/';
    render(<App />);
    expect(document.documentElement).toHaveAttribute('data-mantine-color-scheme', 'light');

    document.cookie = 'oscar-ui-mode=dark; Path=/';
    window.localStorage.setItem('settings', JSON.stringify({ mode: 'dark' }));
    fireEvent(window, new StorageEvent('storage', { key: 'settings' }));
    expect(document.documentElement).toHaveAttribute('data-mantine-color-scheme', 'dark');
  });

  it('applies the header style class', () => {
    render(<App />);

    expect(screen.getByRole('banner')).toHaveClass(headerClasses.header);
  });

  it('provides navigation from the mobile menu', async () => {
    const user = userEvent.setup();
    render(<App />);

    const menuButton = screen.getByRole('button', { name: 'Toggle navigation menu' });
    await user.click(menuButton);

    expect(menuButton).toHaveAttribute('aria-expanded', 'true');

    const menu = await screen.findByRole('menu', { hidden: true });
    const activeMenuItem = within(menu).getByRole('menuitem', { name: 'Alerts', hidden: true });
    expect(activeMenuItem).toHaveAttribute('aria-current', 'page');
    expect(activeMenuItem).toHaveClass(headerClasses.menuItem);
    expect(
      within(menu).getByRole('menuitem', { name: 'Silences', hidden: true })
    ).toBeInTheDocument();
    expect(
      within(menu).getByRole('menuitem', { name: 'Runtime & Build Information', hidden: true })
    ).toBeInTheDocument();
    expect(
      within(menu).getByRole('menuitem', { name: 'Configuration', hidden: true })
    ).toBeInTheDocument();
  });
});
