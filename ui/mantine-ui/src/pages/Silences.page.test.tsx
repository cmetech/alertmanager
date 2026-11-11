import { Suspense } from 'react';

import { render } from '@test-utils';
import { screen } from '@testing-library/react';

import { SilencesPage } from './Silences.page';

afterEach(() => vi.unstubAllGlobals());

it('shows native silence status, name, reason, creator, and matcher operators', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      expect(String(input)).toBe('/api/v2/silences');
      return Response.json([
        {
          id: 'silence-1',
          status: { state: 'active' },
          startsAt: '2026-11-11T17:23:01Z',
          endsAt: '2026-11-14T17:23:01Z',
          updatedAt: '2026-11-11T17:23:01Z',
          createdBy: 'oscar-local-uat',
          comment:
            'OSCAR ingest suppression v1\nName: UAT advanced payments\nReason: Staging only\nReason: Follow up',
          matchers: [
            { name: 'service', value: 'payments', isRegex: false, isEqual: true },
            { name: 'alertname', value: 'OSCAR_UAT_App.*', isRegex: true, isEqual: true },
            { name: 'environment', value: 'production', isRegex: false, isEqual: false },
            { name: 'team', value: '(security|infra)', isRegex: true, isEqual: false },
          ],
        },
        {
          id: 'silence-2',
          status: { state: 'expired' },
          startsAt: '2026-11-10T17:23:01Z',
          endsAt: '2026-11-11T17:23:01Z',
          updatedAt: '2026-11-11T17:23:01Z',
          createdBy: 'external-admin',
          comment: 'External maintenance',
          matchers: [],
        },
      ]);
    })
  );

  render(
    <Suspense fallback="Loading">
      <SilencesPage />
    </Suspense>
  );

  expect(await screen.findByRole('heading', { name: 'UAT advanced payments' })).toBeInTheDocument();
  expect(screen.getByText('Staging only Reason: Follow up')).toBeInTheDocument();
  expect(screen.getByText('silence-1')).toBeInTheDocument();
  expect(screen.getByText('Created by: oscar-local-uat')).toBeInTheDocument();
  expect(screen.getByText('service = "payments"')).toBeInTheDocument();
  expect(screen.getByText('alertname =~ "OSCAR_UAT_App.*"')).toBeInTheDocument();
  expect(screen.getByText('environment != "production"')).toBeInTheDocument();
  expect(screen.getByText('team !~ "(security|infra)"')).toBeInTheDocument();
  expect(screen.getByText('External maintenance')).toBeInTheDocument();
  expect(screen.getByText('Expired')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /create|delete|edit|end/i })).not.toBeInTheDocument();
});

it('explains an empty native silence list', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json([]))
  );
  render(
    <Suspense fallback="Loading">
      <SilencesPage />
    </Suspense>
  );
  expect(await screen.findByText('No native silences found.')).toBeInTheDocument();
});
