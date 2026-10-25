/**
 * Scan store — tracks the active scan (URL input → live progress → report).
 * Lives entirely in memory; the source of truth is the backend SSE stream.
 */

import { create } from "zustand";
import type { ScanLogEntry, ScanStatus, ScanStatusResponse, SecurityReport } from "@/types";
import { startScan, streamScan, cancelScan } from "@/lib/api/scans";
import { ApiError } from "@/lib/api/client";

interface ScanStoreState {
  // Input
  url: string;
  setUrl: (url: string) => void;

  // Active scan
  scanId: string | null;
  status: ScanStatus | null;
  progress: number;
  currentStep: string;
  logs: ScanLogEntry[];
  report: SecurityReport | null;
  error: string | null;

  // Actions
  startScan: () => Promise<void>;
  cancelScan: () => Promise<void>;
  reset: () => void;

  // SSE cleanup
  _cleanup: (() => void) | null;
}

const INITIAL: Omit<
  ScanStoreState,
  "url" | "setUrl" | "startScan" | "cancelScan" | "reset" | "_cleanup"
> = {
  scanId: null,
  status: null,
  progress: 0,
  currentStep: "",
  logs: [],
  report: null,
  error: null,
};

export const useScanStore = create<ScanStoreState>((set, get) => ({
  url: "",
  setUrl: (url) => set({ url }),

  ...INITIAL,
  _cleanup: null,

  startScan: async () => {
    const { url, _cleanup } = get();

    // Close any existing SSE connection
    if (_cleanup) _cleanup();

    set({ ...INITIAL, status: "queued", currentStep: "Queued", error: null });

    try {
      const { scan_id } = await startScan(url.trim());

      set({ scanId: scan_id });

      // Open SSE stream
      const cleanup = streamScan(
        scan_id,
        (data: ScanStatusResponse) => {
          set({
            status: data.status,
            progress: data.progress,
            currentStep: data.current_step,
            logs: data.logs,
            report: data.report ?? null,
            error: data.error ?? null,
          });
        },
        () => {
          // SSE error — try to re-fetch state once
          setTimeout(async () => {
            try {
              const { getScan } = await import("@/lib/api/scans");
              const data = await getScan(scan_id);
              set({
                status: data.status,
                progress: data.progress,
                currentStep: data.current_step,
                logs: data.logs,
                report: data.report ?? null,
                error: data.error ?? null,
              });
            } catch {
              // Ignore polling fetch error
            }
          }, 2000);
        },
      );

      set({ _cleanup: cleanup });
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? (err.detail ?? err.message)
          : "Could not connect to Sentinel backend. Make sure it is running on port 8000.";
      set({ status: "failed", error: msg, currentStep: "Failed" });
    }
  },

  cancelScan: async () => {
    const { scanId, _cleanup } = get();
    if (!scanId) return;
    if (_cleanup) _cleanup();
    try {
      await cancelScan(scanId);
    } catch {
      // Ignore cancel network failure
    }
    set({ status: "cancelled", currentStep: "Cancelled", _cleanup: null });
  },

  reset: () => {
    const { _cleanup } = get();
    if (_cleanup) _cleanup();
    // Preserve the URL — only wipe scan results
    set({ ...INITIAL, url: get().url, _cleanup: null });
  },
}));
