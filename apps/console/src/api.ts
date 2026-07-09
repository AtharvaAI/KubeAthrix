import type { ApprovalRequest, AuditEvent, ChaosExperiment, ChaosExperimentRun, Dashboard, Finding, Integration, ModelProviderSettings, RemediationPlan } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {})
    }
  });
  if (!response.ok) {
    throw new Error(`API ${response.status} for ${path}`);
  }
  return response.json() as Promise<T>;
}

export async function loadDashboard(): Promise<Dashboard> {
  return request<Dashboard>("/dashboard");
}

export async function loadFindings(): Promise<Finding[]> {
  const payload = await request<{ items: Finding[] }>("/findings");
  return payload.items;
}

export async function createRemediationPlan(findingId: string): Promise<RemediationPlan> {
  return request<RemediationPlan>("/remediation-plans", {
    method: "POST",
    body: JSON.stringify({ findingId, requestedBy: "operator-console" })
  });
}

export async function approveRemediationPlan(planId: string): Promise<ApprovalRequest> {
  return request<ApprovalRequest>(`/approvals/approval-${planId}/approve`, {
    method: "POST",
    body: JSON.stringify({ actor: "operator-console", reason: "Approved from operator console." })
  });
}

export async function rejectRemediationPlan(planId: string): Promise<ApprovalRequest> {
  return request<ApprovalRequest>(`/approvals/approval-${planId}/reject`, {
    method: "POST",
    body: JSON.stringify({ actor: "operator-console", reason: "Rejected from operator console." })
  });
}

export async function loadAuditEvents(): Promise<AuditEvent[]> {
  const payload = await request<{ items: AuditEvent[] }>("/audit-events");
  return payload.items;
}

export async function loadIntegrations(): Promise<Integration[]> {
  const payload = await request<{ items: Integration[] }>("/integrations");
  return payload.items;
}

export async function loadExperiments(): Promise<ChaosExperiment[]> {
  const payload = await request<{ items: ChaosExperiment[] }>("/experiments");
  return payload.items;
}

export async function startChaosExperiment(experimentId: string, manifest: string): Promise<ChaosExperimentRun> {
  return request<ChaosExperimentRun>(`/experiments/${experimentId}/runs`, {
    method: "POST",
    body: JSON.stringify({ requestedBy: "operator-console", manifest })
  });
}

export async function loadModelProviders(): Promise<ModelProviderSettings> {
  return request<ModelProviderSettings>("/settings/model-providers");
}
