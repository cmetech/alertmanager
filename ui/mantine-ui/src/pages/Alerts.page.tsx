import { Badge, Card, Code, Group, Stack, Text, Title } from '@mantine/core';

import { LabelPill } from '@/components/LabelPill';
import { type Alert, type AlertStatus, useGroups } from '@/data/groups';

const alertState = (status: AlertStatus) => {
  const { state, silencedBy, inhibitedBy, mutedBy } = status;
  if (silencedBy.length) return { label: 'Silenced', color: 'yellow' };
  if (inhibitedBy.length) return { label: 'Inhibited', color: 'gray' };
  if (mutedBy.length) return { label: 'Muted', color: 'gray' };
  if (state === 'active') return { label: 'Active', color: 'green' };
  return { label: 'Unprocessed', color: 'blue' };
};

export function AlertsPage() {
  const { data: groups } = useGroups();
  const byFingerprint = new Map<
    string,
    { alert: Alert; routes: { receiver: string; status: AlertStatus }[] }
  >();
  for (const group of groups) {
    for (const alert of group.alerts) {
      const entry = byFingerprint.get(alert.fingerprint) || { alert, routes: [] };
      entry.routes.push({ receiver: group.receiver.name, status: alert.status });
      byFingerprint.set(alert.fingerprint, entry);
    }
  }
  const alerts = [...byFingerprint.values()];

  return (
    <Stack maw={1100} mx="auto" mt="xs" gap="md">
      <Group justify="space-between">
        <Title order={2}>Alerts</Title>
        <Badge variant="light">{alerts.length} native alerts</Badge>
      </Group>
      {alerts.length === 0 && <Text>No native alerts are currently active.</Text>}
      {alerts.map(({ alert, routes }) => {
        const routeStates = routes.map((route) => alertState(route.status));
        const silenceIds = [...new Set(routes.flatMap((route) => route.status.silencedBy))];
        const state = routeStates.every((routeState) => routeState.label === routeStates[0].label)
          ? routeStates[0]
          : { label: 'Mixed route states', color: 'blue' };
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
              {routes.length > 1 && (
                <Group gap="xs">
                  {routes.map((route, index) => {
                    const routeState = alertState(route.status);
                    return (
                      <Badge
                        key={`${route.receiver}:${index}`}
                        color={routeState.color}
                        variant="light"
                      >
                        {route.receiver}: {routeState.label}
                      </Badge>
                    );
                  })}
                </Group>
              )}
              <Text size="xs" c="dimmed">
                Starts: {new Date(alert.startsAt).toLocaleString()} · Ends:{' '}
                {new Date(alert.endsAt).toLocaleString()}
              </Text>
              {silenceIds.length > 0 && (
                <Text size="xs" c="dimmed">
                  Silence IDs: {silenceIds.join(', ')}
                </Text>
              )}
            </Stack>
          </Card>
        );
      })}
    </Stack>
  );
}
