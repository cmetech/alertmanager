import { Badge, Card, Code, Group, Stack, Text, Title } from '@mantine/core';

import { useSilences } from '@/data/silences';

const commentParts = (comment: string) => {
  const prefix = 'OSCAR ingest suppression v1\nName: ';
  if (!comment.startsWith(prefix)) return { name: 'External silence', reason: comment };
  const remainder = comment.slice(prefix.length);
  const separator = remainder.indexOf('\nReason: ');
  const name = separator < 0 ? '' : remainder.slice(0, separator);
  const reason = separator < 0 ? '' : remainder.slice(separator + '\nReason: '.length);
  if (!name?.trim() || !reason?.trim() || /[\r\n]/.test(name))
    return { name: 'External silence', reason: comment };
  return { name, reason };
};

const matcherText = (matcher: {
  name: string;
  value: string;
  isRegex: boolean;
  isEqual: boolean;
}) => {
  const operator = matcher.isRegex ? (matcher.isEqual ? '=~' : '!~') : matcher.isEqual ? '=' : '!=';
  return `${matcher.name} ${operator} "${matcher.value}"`;
};

export function SilencesPage() {
  const { data: silences } = useSilences();
  const stateOrder = { active: 0, pending: 1, expired: 2 };
  const sorted = [...silences].sort(
    (left, right) => stateOrder[left.status.state] - stateOrder[right.status.state]
  );

  return (
    <Stack maw={1100} mx="auto" mt="xs" gap="md">
      <Group justify="space-between">
        <Title order={2}>Silences</Title>
        <Badge variant="light">{sorted.length} native silences</Badge>
      </Group>
      {sorted.length === 0 && <Text>No native silences found.</Text>}
      {sorted.map((silence) => {
        const { name, reason } = commentParts(silence.comment);
        return (
          <Card key={silence.id} withBorder shadow="xs" p="md">
            <Stack gap="sm">
              <Group justify="space-between" align="flex-start">
                <div>
                  <Title order={3}>{name}</Title>
                  <Text size="xs" c="dimmed">
                    ID: <Code>{silence.id}</Code>
                  </Text>
                </div>
                <Badge
                  color={
                    silence.status.state === 'active'
                      ? 'green'
                      : silence.status.state === 'pending'
                        ? 'yellow'
                        : 'gray'
                  }
                  variant="light"
                >
                  {silence.status.state[0].toUpperCase() + silence.status.state.slice(1)}
                </Badge>
              </Group>
              <Text>{reason}</Text>
              <Text size="sm">Created by: {silence.createdBy}</Text>
              <Text size="sm">
                Starts: {new Date(silence.startsAt).toLocaleString()} · Ends:{' '}
                {new Date(silence.endsAt).toLocaleString()}
              </Text>
              <Group gap="xs">
                {silence.matchers.map((matcher, index) => (
                  <Code key={`${matcher.name}:${index}`}>{matcherText(matcher)}</Code>
                ))}
              </Group>
            </Stack>
          </Card>
        );
      })}
    </Stack>
  );
}
