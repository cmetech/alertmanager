import { useAPIQuery } from '@/data/api';
import type { Alert } from '@/data/groups';

export type NativeAlertPage = {
  contract_version: number;
  records: Alert[];
  total_records: number;
  total_pages: number;
  timing_by_fingerprint: Record<string, unknown>;
};

export const isNativeAlertPage = (value: unknown): value is NativeAlertPage => {
  if (typeof value !== 'object' || value === null) return false;
  const page = value as Partial<NativeAlertPage>;
  return (
    page.contract_version === 2 &&
    Array.isArray(page.records) &&
    Number.isSafeInteger(page.total_records) &&
    (page.total_records ?? -1) >= 0 &&
    Number.isSafeInteger(page.total_pages) &&
    (page.total_pages ?? -1) >= 0 &&
    typeof page.timing_by_fingerprint === 'object' &&
    page.timing_by_fingerprint !== null
  );
};

export const useNativeAlertPage = (params: Record<string, string | string[]>) =>
  useAPIQuery<unknown>({ path: '/oscar/alerts/page', params, preservePreviousData: true });
