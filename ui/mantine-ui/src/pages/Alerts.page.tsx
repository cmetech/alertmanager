import { useEffect, useMemo, useRef, useState } from 'react';

import {
  Badge,
  Button,
  Card,
  Code,
  Group,
  Alert as MantineAlert,
  Pagination,
  Select,
  Stack,
  Text,
  TextInput,
  Title,
} from '@mantine/core';

import { LabelPill } from '@/components/LabelPill';
import { isNativeAlertPage, useNativeAlertPage } from '@/data/alertPage';
import type { Alert, AlertStatus } from '@/data/groups';

type RouteSchedule = { receiver: string; integration: string; state: string };

const routeSchedules = (value: unknown): RouteSchedule[] => {
  if (typeof value !== 'object' || value === null || !('repeat_schedules' in value)) return [];
  const schedules = value.repeat_schedules;
  if (!Array.isArray(schedules)) return [];
  return schedules.filter(
    (schedule): schedule is RouteSchedule =>
      typeof schedule === 'object' &&
      schedule !== null &&
      typeof schedule.receiver === 'string' &&
      typeof schedule.integration === 'string' &&
      typeof schedule.state === 'string'
  );
};

const routeMutes = (value: unknown): string[] => {
  if (typeof value !== 'object' || value === null || !('muted_by' in value)) return [];
  return Array.isArray(value.muted_by)
    ? value.muted_by.filter((name): name is string => typeof name === 'string')
    : [];
};

const alertState = (
  status: AlertStatus,
  schedules: RouteSchedule[],
  mutedBy: string[],
  routeMuteKnown: boolean
) => {
  const { state, silencedBy, inhibitedBy } = status;
  if (silencedBy.length) return { label: 'Silenced', color: 'yellow' };
  if (inhibitedBy.length) return { label: 'Inhibited', color: 'gray' };
  if (mutedBy.length) {
    const hasUnmutedPath = schedules.some((schedule) =>
      ['estimated', 'no_repeat_baseline'].includes(schedule.state)
    );
    return {
      label: hasUnmutedPath ? 'Time muted on some routes' : 'Time muted on a route',
      color: 'gray',
    };
  }
  if (!routeMuteKnown && state === 'active') {
    return { label: 'Route mute state unavailable', color: 'gray' };
  }
  if (state === 'active') return { label: 'Active', color: 'green' };
  if (state === 'suppressed') return { label: 'Suppressed', color: 'gray' };
  return { label: 'Unprocessed', color: 'blue' };
};

function AlertCard({ alert, timing }: { alert: Alert; timing: unknown }) {
  const schedules = routeSchedules(timing);
  const mutedBy = routeMutes(timing);
  const routeMuteKnown =
    typeof timing === 'object' &&
    timing !== null &&
    'muted_by' in timing &&
    Array.isArray(timing.muted_by);
  const state = alertState(alert.status, schedules, mutedBy, routeMuteKnown);
  const showRouteMute =
    mutedBy.length > 0 &&
    alert.status.silencedBy.length === 0 &&
    alert.status.inhibitedBy.length === 0;
  return (
    <Card key={alert.fingerprint} withBorder shadow="xs" p="md">
      <Stack gap="sm">
        <Group justify="space-between" align="flex-start">
          <div>
            <Title order={3}>{alert.labels.alertname || 'Unnamed alert'}</Title>
            <Text size="xs" c="dimmed">
              Fingerprint: <Code>{alert.fingerprint}</Code>
            </Text>
          </div>
          <Badge color={state.color} variant="light">
            {state.label}
          </Badge>
        </Group>
        {alert.annotations.summary && <Text>{alert.annotations.summary}</Text>}
        <Group gap="xs">
          {Object.entries(alert.labels)
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([name, value]) => (
              <LabelPill key={name} name={name} value={value} />
            ))}
        </Group>
        <Text size="sm">
          Receiver: {alert.receivers.map((receiver) => receiver.name).join(', ') || '—'}
        </Text>
        <Text size="xs" c="dimmed">
          Starts: {new Date(alert.startsAt).toLocaleString()} · Ends:{' '}
          {new Date(alert.endsAt).toLocaleString()}
        </Text>
        {alert.status.silencedBy.length > 0 && (
          <Text size="xs" c="dimmed">
            Silence IDs: {alert.status.silencedBy.join(', ')}
          </Text>
        )}
        {showRouteMute && (
          <>
            <Text size="xs" c="dimmed">
              Time interval: {mutedBy.join(', ')}
            </Text>
            {schedules.map((schedule, index) => (
              <Text
                key={`${schedule.receiver}-${schedule.integration}-${index}`}
                size="xs"
                c="dimmed"
              >
                {schedule.receiver} · {schedule.integration} ·{' '}
                {schedule.state === 'suppressed'
                  ? 'Time muted'
                  : schedule.state === 'unavailable'
                    ? 'Repeat timing unavailable'
                    : 'Not time muted'}
              </Text>
            ))}
          </>
        )}
      </Stack>
    </Card>
  );
}

export function AlertsPage() {
  const errorRef = useRef<HTMLDivElement>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState('20');
  const [searchDraft, setSearchDraft] = useState('');
  const [matcherDraft, setMatcherDraft] = useState('');
  const [severityDraft, setSeverityDraft] = useState('');
  const [search, setSearch] = useState('');
  const [matcher, setMatcher] = useState('');
  const [severity, setSeverity] = useState('');
  const [sort, setSort] = useState('startsAt:desc');

  const params = useMemo(() => {
    const [column, order] = sort.split(':');
    const query: Record<string, string | string[]> = {
      page: String(page),
      perPage: pageSize,
      column,
      order,
      active: 'true',
      silenced: 'true',
      inhibited: 'true',
    };
    if (search) query.quick_search = search;
    if (matcher) query.filter = [matcher];
    if (severity) query.severity = severity;
    return query;
  }, [page, pageSize, search, matcher, severity, sort]);
  const query = useNativeAlertPage(params);
  const nativePage = isNativeAlertPage(query.data) ? query.data : null;
  const invalidPage = query.data !== undefined && !nativePage;
  const totalPages = nativePage?.total_pages ?? 0;

  useEffect(() => {
    if (nativePage && page > Math.max(1, totalPages)) setPage(Math.max(1, totalPages));
  }, [nativePage, page, totalPages]);

  useEffect(() => {
    if (query.isError && !nativePage) errorRef.current?.focus();
  }, [query.isError, nativePage]);

  const applyFilters = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSearch(searchDraft.trim());
    setMatcher(matcherDraft.trim());
    setSeverity(severityDraft.trim());
    setPage(1);
  };

  return (
    <Stack maw={1100} mx="auto" mt="xs" gap="md">
      <Group justify="space-between">
        <Title order={2}>Alerts</Title>
        <Badge variant="light">
          {nativePage?.total_records.toLocaleString() ?? '—'} matching native alerts
        </Badge>
      </Group>
      <form onSubmit={applyFilters}>
        <Stack gap="sm">
          <Group align="end" grow>
            <TextInput
              label="Search alerts"
              placeholder="Name, severity, summary or fingerprint"
              value={searchDraft}
              maxLength={200}
              onChange={(event) => setSearchDraft(event.currentTarget.value)}
            />
            <TextInput
              label="Label matcher"
              placeholder={'instance="db1"'}
              value={matcherDraft}
              onChange={(event) => setMatcherDraft(event.currentTarget.value)}
            />
            <TextInput
              label="Severity"
              placeholder="Exact severity, for example critical"
              value={severityDraft}
              onChange={(event) => setSeverityDraft(event.currentTarget.value)}
            />
            <Button type="submit">Apply filters</Button>
          </Group>
          <Group align="end">
            <Select
              label="Sort"
              value={sort}
              data={[
                { value: 'startsAt:desc', label: 'Newest first' },
                { value: 'startsAt:asc', label: 'Oldest first' },
                { value: 'alertname:asc', label: 'Alert name A–Z' },
                { value: 'severity:asc', label: 'Severity A–Z' },
              ]}
              onChange={(value) => {
                setSort(value || 'startsAt:desc');
                setPage(1);
              }}
            />
            <Select
              label="Per page"
              value={pageSize}
              data={['20', '50', '100']}
              onChange={(value) => {
                setPageSize(value || '20');
                setPage(1);
              }}
            />
            <Button variant="light" onClick={() => query.refetch()} disabled={query.isFetching}>
              Refresh
            </Button>
          </Group>
        </Stack>
      </form>
      {query.isPending && <Text role="status">Loading native alerts…</Text>}
      {query.isError && (
        <MantineAlert color="red" role="alert" ref={errorRef} tabIndex={-1}>
          Could not load native alerts: {query.error.message}
        </MantineAlert>
      )}
      {invalidPage && (
        <MantineAlert color="red" role="alert">
          Native alert paging is unavailable: incompatible response.
        </MantineAlert>
      )}
      {nativePage && (
        <>
          {query.isPlaceholderData && <Text role="status">Loading page {page}…</Text>}
          {!query.isPlaceholderData && nativePage.total_records === 0 && (
            <Text>
              {search || matcher || severity
                ? 'No native alerts match these filters.'
                : 'No native alerts are currently active.'}
            </Text>
          )}
          {!query.isPlaceholderData &&
            nativePage.records.map((alert) => (
              <AlertCard
                key={alert.fingerprint}
                alert={alert}
                timing={nativePage.timing_by_fingerprint[alert.fingerprint]}
              />
            ))}
          {totalPages > 1 && (
            <Group justify="space-between">
              <Text size="sm">
                Page {page} of {totalPages}
              </Text>
              <Pagination
                total={totalPages}
                value={page}
                onChange={setPage}
                withEdges
                getControlProps={(control) => ({
                  'aria-label': `${control[0].toUpperCase()}${control.slice(1)} page`,
                })}
              />
            </Group>
          )}
        </>
      )}
    </Stack>
  );
}
