import { render } from '@test-utils';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import type { Alert } from '@/data/groups';

import { AlertsPage } from './Alerts.page';

const alert = (name: string, id: string, state: 'active' | 'suppressed' = 'active'): Alert => ({
  annotations: { summary: `${name} summary` },
  endsAt: '2026-11-14T17:23:01Z',
  fingerprint: id,
  receivers: [{ name: 'oscar-alerts' }],
  startsAt: '2026-11-11T17:23:01Z',
  status: {
    state,
    silencedBy: state === 'suppressed' ? ['silence-1'] : [],
    inhibitedBy: [],
    mutedBy: [],
  },
  updatedAt: '2026-11-11T17:23:01Z',
  labels: { alertname: name, application: 'oscar', instance: `${name}-01` },
});

const page = (records: Alert[], total = records.length) => ({
  contract_version: 2,
  records,
  total_records: total,
  total_pages: Math.ceil(total / 20),
  timing_by_fingerprint: {},
});

afterEach(() => vi.unstubAllGlobals());

it('requests bounded native alert pages and renders only the selected page at 1,000 alerts', async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://localhost');
    expect(url.pathname).toBe('/api/v2/oscar/alerts/page');
    expect(url.searchParams.get('perPage')).toBe('20');
    const current = Number(url.searchParams.get('page'));
    return Response.json(
      page(
        Array.from({ length: 20 }, (_, i) => alert(`Alert-${current}-${i}`, `${current}-${i}`)),
        1000
      )
    );
  });
  vi.stubGlobal('fetch', fetchMock);
  render(<AlertsPage />);

  expect(await screen.findByText('1,000 matching native alerts')).toBeInTheDocument();
  expect(screen.getAllByRole('heading', { level: 3 })).toHaveLength(20);
  expect(screen.getByText('Page 1 of 50')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Next page' }));
  expect(await screen.findByRole('heading', { name: 'Alert-2-0' })).toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Alert-1-0' })).not.toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it('keeps pagination mounted and focused while the next page loads', async () => {
  let finishPageTwo: ((response: Response) => void) | undefined;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const current = new URL(String(input), 'http://localhost').searchParams.get('page');
      if (current === '2') {
        return new Promise<Response>((resolve) => {
          finishPageTwo = resolve;
        });
      }
      return Response.json(page([alert('FirstPage', 'fp-1')], 1000));
    })
  );
  render(<AlertsPage />);
  expect(await screen.findByRole('heading', { name: 'FirstPage' })).toBeInTheDocument();
  const next = screen.getByRole('button', { name: 'Next page' });
  await userEvent.click(next);
  await waitFor(() => expect(finishPageTwo).toBeDefined());
  expect(next).toBeInTheDocument();
  expect(next).toHaveFocus();
  expect(screen.getByText('Loading page 2…')).toBeInTheDocument();
  finishPageTwo?.(Response.json(page([alert('SecondPage', 'fp-2')], 1000)));
  expect(await screen.findByRole('heading', { name: 'SecondPage' })).toBeInTheDocument();
});

it('applies search and a native label matcher before counting and resets to page one', async () => {
  const urls: URL[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input), 'http://localhost');
      urls.push(url);
      return Response.json(page([alert('DiskFull', 'fp-1', 'suppressed')], 25));
    })
  );
  render(<AlertsPage />);
  expect(await screen.findByRole('heading', { name: 'DiskFull' })).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Next page' }));
  await waitFor(() => expect(urls.at(-1)?.searchParams.get('page')).toBe('2'));
  fireEvent.change(screen.getByRole('textbox', { name: 'Search alerts' }), {
    target: { value: 'disk' },
  });
  fireEvent.change(screen.getByRole('textbox', { name: 'Label matcher' }), {
    target: { value: 'instance="db1"' },
  });
  await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  await waitFor(() => expect(urls.at(-1)?.searchParams.get('quick_search')).toBe('disk'));
  expect(urls.at(-1)?.searchParams.get('page')).toBe('1');
  expect(urls.at(-1)?.searchParams.getAll('filter')).toEqual(['instance="db1"']);
  expect(screen.queryByRole('combobox', { name: 'Status' })).not.toBeInTheDocument();
});

it('shows a route time mute and mixed notification paths without claiming every route is suppressed', async () => {
  const mixed = {
    ...alert('LinkDown', 'fp-1'),
    status: { ...alert('LinkDown', 'fp-1').status, state: 'active' as const },
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      Response.json({
        ...page([mixed]),
        timing_by_fingerprint: {
          'fp-1': {
            muted_by: ['quiet'],
            repeat_lookup_state: 'ready',
            repeat_schedules: [
              { receiver: 'team', integration: 'webhook/0', state: 'suppressed' },
              { receiver: 'team', integration: 'email/0', state: 'no_repeat_baseline' },
            ],
          },
        },
      })
    )
  );
  render(<AlertsPage />);
  expect(await screen.findByText('Time muted on some routes')).toBeInTheDocument();
  expect(screen.getByText('Time interval: quiet')).toBeInTheDocument();
  expect(screen.getByText('team · webhook/0 · Time muted')).toBeInTheDocument();
  expect(screen.getByText('team · email/0 · Not time muted')).toBeInTheDocument();
});

it('does not call a route active when time-mute evidence is unavailable', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      Response.json({
        ...page([alert('UncertainRoute', 'fp-1')]),
        timing_by_fingerprint: {
          'fp-1': { muted_by: null, repeat_lookup_state: 'unavailable', repeat_schedules: [] },
        },
      })
    )
  );
  render(<AlertsPage />);
  expect(await screen.findByText('Route mute state unavailable')).toBeInTheDocument();
  expect(screen.queryByText('Active')).not.toBeInTheDocument();
});

it('preserves native labels, receiver and silence evidence on a page', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json(page([alert('DiskFull', 'fp-1', 'suppressed')])))
  );
  render(<AlertsPage />);
  expect(await screen.findByText('Silenced')).toBeInTheDocument();
  expect(screen.getByText('Receiver: oscar-alerts')).toBeInTheDocument();
  expect(screen.getByText('Silence IDs: silence-1')).toBeInTheDocument();
  expect(screen.getByText('application="oscar"')).toBeInTheDocument();
});

it('shows a page-contract error instead of treating an incompatible native response as no alerts', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json({ ...page([]), contract_version: 1 }))
  );
  render(<AlertsPage />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Native alert paging is unavailable');
  expect(screen.queryByText('No native alerts are currently active.')).not.toBeInTheDocument();
});

it('shows a native matcher error without claiming paging is incompatible', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json('invalid label matcher', { status: 400 }))
  );
  render(<AlertsPage />);
  expect(await screen.findByRole('alert')).toHaveTextContent('invalid label matcher');
  expect(screen.queryByText(/incompatible response/)).not.toBeInTheDocument();
});

it('moves focus to a page-load error so keyboard users can recover', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const current = new URL(String(input), 'http://localhost').searchParams.get('page');
      return current === '2'
        ? Response.json('native service unavailable', { status: 503 })
        : Response.json(page([alert('FirstPage', 'fp-1')], 1000));
    })
  );
  render(<AlertsPage />);
  expect(await screen.findByRole('heading', { name: 'FirstPage' })).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Next page' }));
  const error = await screen.findByRole('alert');
  expect(error).toHaveTextContent('native service unavailable');
  await waitFor(() => expect(error).toHaveFocus());
});
