// Thin client for the MalvaX API. Runs on the server only: pages call it from server components
// and the token is read from the httpOnly session cookie. Every returned value is untrusted
// sandbox data, so pages render it as plain text; nothing here is inserted as HTML.

import { readToken } from "@/lib/session";

export const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8080";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export type Sample = {
  id: string;
  filename: string;
  size: number;
  sha256: string;
  sha1: string;
  md5: string;
  file_type: string;
  uploaded_at: string;
  analysis_status: string;
};

export type Analysis = {
  id: string;
  sample_id: string;
  state: string;
  created_at: string;
  updated_at: string;
};

export type RiskContribution = {
  component: string;
  points: number;
  reason: string;
  evidence: string[];
};

export type Findings = {
  analysis_id: string;
  report_id: number;
  risk_contributions: RiskContribution[];
  yara_matches: { rule_id: string; severity: string; description: string }[];
};

export type Report = {
  schema_version: string;
  generated_at: string;
  sample: Record<string, unknown>;
  static: Record<string, unknown>;
  execution: Record<string, unknown>;
  behavior: Record<string, unknown>;
  risk: { total: number; contributions: RiskContribution[] } | string;
  limitations: string[];
};

async function getJson<T>(path: string): Promise<T> {
  const token = readToken();
  if (token === null) {
    throw new ApiError("not signed in", 401);
  }
  const res = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new ApiError(`${path} returned ${res.status}`, res.status);
  }
  return (await res.json()) as T;
}

export const api = {
  health: () => getJson<{ status: string; database: boolean; queue: boolean }>("/api/v1/health"),
  samples: () => getJson<Sample[]>("/api/v1/samples?limit=100"),
  sample: (id: string) => getJson<Sample>(`/api/v1/samples/${encodeURIComponent(id)}`),
  analyses: () => getJson<Analysis[]>("/api/v1/analyses?limit=100"),
  analysis: (id: string) => getJson<Analysis>(`/api/v1/analyses/${encodeURIComponent(id)}`),
  findings: (analysisId: string) =>
    getJson<Findings>(`/api/v1/findings?analysis_id=${encodeURIComponent(analysisId)}`),
  report: (id: number) => getJson<Report>(`/api/v1/reports/${id}`),
};
