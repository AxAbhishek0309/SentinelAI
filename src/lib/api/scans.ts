import { get, post, del, openSSE } from "./client";
import type { ScanCreateResponse, ScanStatusResponse, ScanSummary } from "@/types";

export type { ScanCreateResponse };

export async function startScan(url: string): Promise<ScanCreateResponse> {
  return post<ScanCreateResponse>("/api/scans", { url });
}

export async function getScan(scanId: string): Promise<ScanStatusResponse> {
  return get<ScanStatusResponse>(`/api/scans/${scanId}`);
}

export async function cancelScan(scanId: string): Promise<void> {
  return del(`/api/scans/${scanId}`);
}

export async function listScans(): Promise<{ scans: ScanSummary[] }> {
  return get<{ scans: ScanSummary[] }>("/api/scans");
}

export function streamScan(
  scanId: string,
  onUpdate: (data: ScanStatusResponse) => void,
  onError?: (err: Event) => void,
): () => void {
  return openSSE(
    `/api/scans/${scanId}/stream`,
    (data) => onUpdate(data as ScanStatusResponse),
    onError,
  );
}
