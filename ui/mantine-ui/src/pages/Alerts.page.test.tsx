import { Suspense } from 'react';

import { render } from '@test-utils';
import { screen } from '@testing-library/react';

import { AlertsPage } from './Alerts.page';

const alert = (name: string, state: 'active' | 'suppressed', id: string) => ({
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
  labels: { alertname: name, application: 'oscar', instance: `${name}-01`, uat_run: 'uat-1' },
});

afterEach(() => vi.unstubAllGlobals());

it('shows both active and silenced native alerts with their labels and receivers', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      expect(String(input)).toContain('/api/v2/alerts/groups?');
      return Response.json([
        {
          labels: {},
          routeLabels: {},
          receiver: { name: 'oscar-alerts' },
          alerts: [
            alert('OSCAR_UAT_Control', 'active', 'fingerprint-1'),
            alert('OSCAR_UAT_Disk', 'suppressed', 'fingerprint-2'),
          ],
        },
      ]);
    })
  );

  render(
    <Suspense fallback="Loading">
      <AlertsPage />
    </Suspense>
  );

  expect(await screen.findByRole('heading', { name: 'OSCAR_UAT_Control' })).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'OSCAR_UAT_Disk' })).toBeInTheDocument();
  expect(screen.getByText('Silenced')).toBeInTheDocument();
  expect(screen.getByText('fingerprint-2')).toBeInTheDocument();
  expect(screen.getAllByText('Receiver: oscar-alerts')).toHaveLength(2);
  expect(screen.getAllByText('uat_run="uat-1"')).toHaveLength(2);
});

it('explains an empty native alert list', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json([]))
  );
  render(
    <Suspense fallback="Loading">
      <AlertsPage />
    </Suspense>
  );
  expect(await screen.findByText('No native alerts are currently active.')).toBeInTheDocument();
});

it('counts each fingerprint once across receiver groups and labels time-muted alerts accurately', async () => {
  const routedTwice = {
    ...alert('OSCAR_UAT_Control', 'active', 'fingerprint-1'),
    receivers: [{ name: 'oscar-alerts' }, { name: 'default' }],
  };
  const timeMuted = {
    ...alert('OSCAR_UAT_NightWindow', 'suppressed', 'fingerprint-3'),
    status: { state: 'suppressed', silencedBy: [], inhibitedBy: [], mutedBy: ['night_silence'] },
  };
  const secondRoute = {
    ...routedTwice,
    status: {
      state: 'suppressed' as const,
      silencedBy: ['silence-route-2'],
      inhibitedBy: [],
      mutedBy: [],
    },
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      Response.json([
        {
          labels: {},
          routeLabels: {},
          receiver: { name: 'oscar-alerts' },
          alerts: [routedTwice, timeMuted],
        },
        { labels: {}, routeLabels: {}, receiver: { name: 'default' }, alerts: [secondRoute] },
      ])
    )
  );

  render(
    <Suspense fallback="Loading">
      <AlertsPage />
    </Suspense>
  );

  expect(await screen.findByRole('heading', { name: 'OSCAR_UAT_NightWindow' })).toBeInTheDocument();
  expect(screen.getAllByRole('heading', { name: 'OSCAR_UAT_Control' })).toHaveLength(1);
  expect(screen.getByText('2 native alerts')).toBeInTheDocument();
  expect(screen.getByText('Muted')).toBeInTheDocument();
  expect(screen.getByText('Receiver: oscar-alerts, default')).toBeInTheDocument();
  expect(screen.getByText('Mixed route states')).toBeInTheDocument();
  expect(screen.getByText('default: Silenced')).toBeInTheDocument();
  expect(screen.getByText('Silence IDs: silence-route-2')).toBeInTheDocument();
});
