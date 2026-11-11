import { useEffect, useMemo, useState } from 'react';

import {
  Badge,
  Card,
  Code,
  Group,
  Pagination,
  Select,
  Stack,
  Text,
  TextInput,
  Title,
} from '@mantine/core';

import { useSilences } from '@/data/silences';

const commentParts = (comment: string) => {
  const prefix = 'OSCAR ingest suppression v1\nName: ';
  if (!comment.startsWith(prefix)) return { name: 'Unnamed silence', reason: comment };
  const remainder = comment.slice(prefix.length);
  const separator = remainder.indexOf('\nReason: ');
  const name = separator < 0 ? '' : remainder.slice(0, separator);
  const reason = separator < 0 ? '' : remainder.slice(separator + '\nReason: '.length);
  if (!name?.trim() || !reason?.trim() || /[\r\n]/.test(name))
    return { name: 'Unnamed silence', reason: comment };
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
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState('20');
  const filtered = useMemo(() => {
    const stateOrder = { active: 0, pending: 1, expired: 2 };
    const needle = search.trim().toLocaleLowerCase();
    return silences
      .filter((silence) => {
        if (status !== 'all' && silence.status.state !== status) return false;
        if (!needle) return true;
        const { name, reason } = commentParts(silence.comment);
        const content = [
          silence.id,
          name,
          reason,
          silence.createdBy,
          ...silence.matchers.map(matcherText),
        ]
          .join(' ')
          .toLocaleLowerCase();
        return content.includes(needle);
      })
      .sort(
        (left, right) =>
          (stateOrder[left.status.state] ?? 3) - (stateOrder[right.status.state] ?? 3)
      );
  }, [silences, search, status]);
  const totalPages = Math.ceil(filtered.length / Number(pageSize));
  useEffect(() => {
    if (page > Math.max(1, totalPages)) setPage(Math.max(1, totalPages));
  }, [page, totalPages]);
  const visible = filtered.slice((page - 1) * Number(pageSize), page * Number(pageSize));

  return (
    <Stack maw={1100} mx="auto" mt="xs" gap="md">
      <Group justify="space-between">
        <Title order={2}>Silences</Title>
        <Badge variant="light">{filtered.length.toLocaleString()} matching native silences</Badge>
      </Group>
      <Group align="end">
        <TextInput
          label="Search silences"
          placeholder="Name, reason, ID, creator or matcher"
          value={search}
          onChange={(event) => {
            setSearch(event.currentTarget.value);
            setPage(1);
          }}
        />
        <Select
          label="Status"
          value={status}
          data={[
            { value: 'all', label: 'All' },
            { value: 'active', label: 'Active' },
            { value: 'pending', label: 'Pending' },
            { value: 'expired', label: 'Expired' },
          ]}
          onChange={(value) => {
            setStatus(value || 'all');
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
      </Group>
      {silences.length === 0 && <Text>No native silences found.</Text>}
      {silences.length > 0 && filtered.length === 0 && (
        <Text>No silences match these filters.</Text>
      )}
      {visible.map((silence) => {
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
      {filtered.length > 0 && (
        <Group justify="space-between">
          <Text size="sm">
            Page {page} of {totalPages}
          </Text>
          {totalPages > 1 && (
            <Pagination
              total={totalPages}
              value={page}
              onChange={setPage}
              withEdges
              getControlProps={(control) => ({
                'aria-label': `${control[0].toUpperCase()}${control.slice(1)} page`,
              })}
            />
          )}
        </Group>
      )}
    </Stack>
  );
}
