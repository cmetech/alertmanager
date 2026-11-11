import { readOscarMode } from './oscarMode';

afterEach(() => {
  document.cookie = 'oscar-ui-mode=; Max-Age=0; Path=/';
  window.localStorage.removeItem('settings');
});

it('uses the OSCAR light or dark cookie when opening the native UI', () => {
  document.cookie = 'oscar-ui-mode=light; Path=/';
  expect(readOscarMode()).toBe('light');
  document.cookie = 'oscar-ui-mode=dark; Path=/';
  expect(readOscarMode()).toBe('dark');
});

it('falls back to OSCAR settings when the cookie is absent and treats semi-dark as light', () => {
  window.localStorage.setItem('settings', JSON.stringify({ mode: 'semi-dark' }));
  expect(readOscarMode()).toBe('light');
  window.localStorage.setItem('settings', JSON.stringify({ mode: 'dark' }));
  expect(readOscarMode()).toBe('dark');
});
