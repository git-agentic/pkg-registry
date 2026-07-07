import type { AuditReport } from "@sentinel/core";

export class ProxyError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "ProxyError";
  }
}

/** Shape of the /-/manifest response (a superset of the audit fields the tools use). */
export interface ManifestResponse {
  meta: AuditReport["meta"];
  score: number;
  verdict: string;
  findings: AuditReport["findings"];
  capabilities: AuditReport["capabilities"];
  capabilityDelta: AuditReport["capabilityDelta"];
  approvalRequired: AuditReport["capabilities"];
  approvalState: string;
  inheritedFrom: string | null;
}

export interface ViolationRecordDTO {
  name: string; version: string; integrity: string;
  kind: string; target: string | null; confidence: string;
  quarantined: boolean;
}

/** Thin HTTP client over the proxy's /-/* endpoints. Every method returns parsed
 *  JSON or throws ProxyError — never a fabricated verdict. */
export class ProxyClient {
  constructor(
    private readonly baseUrl: string,
    private readonly authToken: string | undefined = process.env.SENTINEL_AUTH_TOKEN,
  ) {}

  private async getJson<T>(path: string): Promise<T> {
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${path}`, { headers: { accept: "application/json" } });
    } catch (e) {
      throw new ProxyError(`cannot reach Sentinel proxy at ${this.baseUrl}: ${(e as Error).message}`);
    }
    if (!res.ok) {
      throw new ProxyError(`proxy ${path} returned ${res.status}: ${await safeText(res)}`, res.status);
    }
    return (await res.json()) as T;
  }

  private async postJson<T>(path: string, body: unknown): Promise<T> {
    const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json" };
    if (this.authToken) headers.authorization = `Bearer ${this.authToken}`;
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    } catch (e) {
      throw new ProxyError(`cannot reach Sentinel proxy at ${this.baseUrl}: ${(e as Error).message}`);
    }
    if (!res.ok) throw new ProxyError(`proxy ${path} returned ${res.status}: ${await safeText(res)}`, res.status);
    return (await res.json()) as T;
  }

  /** Resolve latest via the packument's dist-tags when version is omitted. */
  private async resolveVersion(pkg: string, version?: string): Promise<string> {
    if (version) return version;
    const doc = await this.getJson<{ "dist-tags"?: Record<string, string> }>(`/${encodeURIComponent(pkg).replace("%40", "@")}`);
    const latest = doc["dist-tags"]?.latest;
    if (!latest) throw new ProxyError(`no latest version for ${pkg}`);
    return latest;
  }

  async audit(pkg: string, version?: string): Promise<AuditReport> {
    const v = await this.resolveVersion(pkg, version);
    return this.getJson<AuditReport>(`/-/audit/${encodeURIComponent(pkg)}/${encodeURIComponent(v)}`);
  }

  async manifest(pkg: string, version?: string): Promise<ManifestResponse> {
    const v = await this.resolveVersion(pkg, version);
    return this.getJson<ManifestResponse>(`/-/manifest/${encodeURIComponent(pkg)}/${encodeURIComponent(v)}`);
  }

  async auditTree(packages: { name: string; version: string }[]): Promise<{ aggregate: { verdict: string; gated: boolean; counts: Record<string, number> }; packages: unknown[] }> {
    return this.postJson(`/-/audit-tree`, { packages });
  }

  async violations(): Promise<ViolationRecordDTO[]> {
    return (await this.getJson<{ violations: ViolationRecordDTO[] }>(`/-/violations`)).violations;
  }

  async approvalRequest(body: { name: string; version: string; integrity: string; reason: string; requestedBy?: { type: "agent" | "human"; id: string } }): Promise<unknown> {
    return this.postJson(`/-/approval-requests`, body);
  }
}

async function safeText(res: Response): Promise<string> {
  try { return (await res.text()).slice(0, 200); } catch { return ""; }
}
