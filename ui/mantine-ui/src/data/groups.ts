import { useSuspenseAPIQuery } from '@/data/api';

export type Group = {
  alerts: Alert[];
  labels: Record<string, string>;
  routeLabels: Record<string, string>;
  receiver: Receiver;
};

type Receiver = {
  name: string;
};

export type AlertStatus = {
  inhibitedBy: string[];
  silencedBy: string[];
  mutedBy: string[];
  state: 'active' | 'suppressed' | 'unprocessed';
};

export type Alert = {
  annotations: Record<string, string>;
  endsAt: string;
  fingerprint: string;
  receivers: Receiver[];
  startsAt: string;
  status: AlertStatus;
  updatedAt: string;
  labels: Record<string, string>;
};

export const useGroups = () => {
  return useSuspenseAPIQuery<Array<Group>>({
    path: '/alerts/groups',
    params: { active: 'true', silenced: 'true', inhibited: 'true', muted: 'true' },
  });
};
