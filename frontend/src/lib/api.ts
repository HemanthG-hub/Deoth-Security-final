import axios, { type AxiosRequestConfig } from "axios";

// Relative API paths work with the Vite proxy and behind a same-origin production proxy.
const client = axios.create({ baseURL: "/api", timeout: 30_000, withCredentials: true });

// Fields are declared, not constructor parameter properties: tsconfig sets
// erasableSyntaxOnly, which rejects `constructor(readonly status: number)`.
export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, body: unknown) {
    super(`request failed with ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

type JsonBody = unknown;

async function request<T>(method: string, path: string, body?: JsonBody): Promise<T> {
  try {
    const response = await client.request<T>({ method, url: path, data: body });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new ApiError(error.response?.status ?? 0, error.response?.data ?? null);
    }
    throw error;
  }
}

// The response type is yours to declare: nothing infers across the Python boundary, so a
// TS interface here mirrors the endpoint's Pydantic model by hand — keep the two in sync.
export const apiGet = <T>(path: string) => request<T>("GET", path);
export const apiPost = <T>(path: string, body?: JsonBody) => request<T>("POST", path, body ?? null);
export const apiPut = <T>(path: string, body?: JsonBody) => request<T>("PUT", path, body ?? null);
export const apiPatch = <T>(path: string, body?: JsonBody) =>
  request<T>("PATCH", path, body ?? null);
export const apiDelete = <T>(path: string) => request<T>("DELETE", path);

export async function apiDownload(path: string, fallbackName: string) {
  const response = await client.get<Blob>(path, { responseType: "blob" } satisfies AxiosRequestConfig);
  const header = response.headers["content-disposition"] as string | undefined;
  const fileName = header?.match(/filename="?([^";]+)"?/i)?.[1] ?? fallbackName;
  const url = URL.createObjectURL(response.data);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}
