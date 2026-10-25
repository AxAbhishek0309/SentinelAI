/**
 * Dashboard store — recent scans list fetched from the backend.
 */

import { create } from "zustand";
import type { ScanSummary } from "@/types";
import { listScans } from "@/lib/api/scans";

interface DashboardStoreState {
  scans: ScanSummary[];
  loading: boolean;
  error: string | null;
  lastFetched: number | null;
  fetch: () => Promise<void>;
}

export const useDashboardStore = create<DashboardStoreState>((set) => ({
  scans: [],
  loading: false,
  error: null,
  lastFetched: null,

  fetch: async () => {
    set({ loading: true, error: null });
    try {
      const { scans } = await listScans();
      set({ scans, loading: false, lastFetched: Date.now() });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to fetch scans";
      set({ loading: false, error: msg });
    }
  },
}));
