/**
 * Base HTTP client.
 * All API calls go through here so the base URL is configured once.
 */

// Always use relative path in dev (Vite proxy handles /api/* → backend).
// In production, use VITE_API_URL env var set at build time.
export const API_BASE = import.meta.env.VITE_API_URL ?? "";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public detail?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail: string | undefined;
    try {
      const body = await res.json();
      detail = body?.detail ?? body?.message;
    } catch {
      // Ignore parse failure
    }
    throw new ApiError(res.status, detail ?? `HTTP ${res.status}`, detail);
  }
  return res.json() as Promise<T>;
}

export async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Accept: "application/json" },
  });
  return handleResponse<T>(res);
}

export async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  return handleResponse<T>(res);
}

export async function del(path: string): Promise<void> {
  const res = await fetch(`${API_BASE}${path}`, { method: "DELETE" });
  if (!res.ok && res.status !== 204) {
    throw new ApiError(res.status, `HTTP ${res.status}`);
  }
}

/** Open an SSE connection and call onMessage for each event. Returns a cleanup fn. */
export function openSSE(
  path: string,
  onMessage: (data: unknown) => void,
  onError?: (err: Event) => void,
): () => void {
  const es = new EventSource(`${API_BASE}${path}`);
  es.onmessage = (ev) => {
    try {
      onMessage(JSON.parse(ev.data));
    } catch {
      // Ignore SSE parse failure
    }
  };
  if (onError) es.onerror = onError;
  return () => es.close();
}
