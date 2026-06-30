// Vite replaces import.meta.env at build time; the main tsconfig includes vite/client types.
export const BACKEND_URL: string =
  (import.meta.env as Record<string, string | undefined>).VITE_BACKEND_URL ??
  "http://localhost:8000";

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${BACKEND_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const err: unknown = await res.json().catch(() => ({ message: res.statusText }));
    const msg =
      typeof err === "object" && err !== null && "message" in err
        ? String((err as { message: unknown }).message)
        : `HTTP ${res.status}`;
    throw new Error(msg);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}
