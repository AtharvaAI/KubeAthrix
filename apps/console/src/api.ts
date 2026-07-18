import type { ApprovalRequest, AuditEvent, ChaosExperiment, ChaosExperimentRun, Dashboard, EvidenceBundle, Finding, FindingException, FindingStatus, Integration, IntegrationHealth, ManagedResourceSnapshot, ModelProviderSettings, RemediationDiff, RemediationPlan, RemediationPreview, RemediationRun } from "./types";
import { accessToken } from "./auth";

const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
	const token = accessToken();
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
	  ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers ?? {})
    }
  });
  if (!response.ok) {
    let message = `API request failed with status ${response.status}`;
    try {
      const payload = await response.json() as { error?: { message?: string } | string; message?: string };
      if (typeof payload.error === "string") message = payload.error;
      else if (payload.error?.message) message = payload.error.message;
      else if (payload.message) message = payload.message;
    } catch {
      // The status remains useful when an upstream proxy does not return JSON.
    }
    throw new APIError(response.status, message, path);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export class APIError extends Error {
  constructor(public readonly status: number, message: string, public readonly path: string) {
    super(message);
    this.name = "APIError";
  }
}

export async function loadDashboard(): Promise<Dashboard> {
  return request<Dashboard>("/dashboard");
}

export async function loadFindings(): Promise<Finding[]> {
  const payload = await request<{ items: Finding[] }>("/findings");
  return payload.items ?? [];
}

export async function updateFindingStatus(findingId: string, status: FindingStatus, reason: string): Promise<Finding> {
	return request<Finding>(`/findings/${encodeURIComponent(findingId)}/status`, { method: "PATCH", body: JSON.stringify({ status, reason }) });
}

export async function createFindingException(scope: string, reason: string, expiresAt: string): Promise<FindingException> {
	return request<FindingException>("/exceptions", { method: "POST", body: JSON.stringify({ scope, reason, expiresAt }) });
}

export async function loadFindingExceptions(): Promise<FindingException[]> {
  const payload = await request<{ items: FindingException[] }>("/exceptions");
  return payload.items ?? [];
}

export async function deleteFindingException(id: string): Promise<void> {
  await request<unknown>(`/exceptions/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function createRemediationPlan(findingId: string): Promise<RemediationPlan> {
  return request<RemediationPlan>("/remediation-plans", {
    method: "POST",
    headers: { "Idempotency-Key": crypto.randomUUID() },
    body: JSON.stringify({ findingId })
  });
}

export async function previewRemediationPlan(findingId: string): Promise<RemediationPreview> {
  return request<RemediationPreview>("/remediation-plans/preview", {
    method: "POST",
    body: JSON.stringify({ findingId })
  });
}

export async function loadRemediationPlanDiff(planId: string): Promise<RemediationDiff> {
  return request<RemediationDiff>(`/remediation-plans/${planId}/diff`);
}

export async function executeRemediationPlan(planId: string): Promise<RemediationRun> {
  return request<RemediationRun>(`/remediation-plans/${planId}/execute`, {
    method: "POST",
    body: JSON.stringify({})
  });
}

export async function loadRemediationRun(runId: string): Promise<RemediationRun> {
  return request<RemediationRun>(`/remediation-runs/${runId}`);
}

export async function rollbackRemediationRun(runId: string): Promise<RemediationRun> {
  return request<RemediationRun>(`/remediation-runs/${runId}/rollback`, {
    method: "POST",
    body: JSON.stringify({})
  });
}

export async function approveRemediationPlan(planId: string, reason: string): Promise<ApprovalRequest> {
  return request<ApprovalRequest>(`/approvals/approval-${planId}/approve`, {
    method: "POST",
	body: JSON.stringify({ reason })
  });
}

export async function rejectRemediationPlan(planId: string, reason: string): Promise<ApprovalRequest> {
  return request<ApprovalRequest>(`/approvals/approval-${planId}/reject`, {
    method: "POST",
	body: JSON.stringify({ reason })
  });
}

export async function loadAuditEvents(): Promise<AuditEvent[]> {
  const payload = await request<{ items: AuditEvent[] }>("/audit-events");
  return payload.items ?? [];
}

export async function loadIntegrations(): Promise<Integration[]> {
  const payload = await request<{ items: Integration[] }>("/integrations");
  return payload.items ?? [];
}

export async function loadIntegrationHealth(name: string): Promise<IntegrationHealth> {
  return request<IntegrationHealth>(`/integrations/${encodeURIComponent(name)}/health`);
}

export async function loadManagedResources(): Promise<ManagedResourceSnapshot> {
  return request<ManagedResourceSnapshot>("/managed-resources");
}

export async function loadEvidenceBundle(scope: string): Promise<EvidenceBundle> {
  return request<EvidenceBundle>(`/evidence-bundles/${encodeURIComponent(scope)}`);
}

export async function loadExperiments(): Promise<ChaosExperiment[]> {
  const payload = await request<{ items: ChaosExperiment[] }>("/experiments");
  return payload.items ?? [];
}

export async function startChaosExperiment(experimentId: string, manifest: string): Promise<ChaosExperimentRun> {
  return request<ChaosExperimentRun>(`/experiments/${experimentId}/runs`, {
    method: "POST",
    body: JSON.stringify({ manifest })
  });
}

export async function loadChaosRuns(): Promise<ChaosExperimentRun[]> {
  const payload = await request<{ items: ChaosExperimentRun[] }>("/experiment-runs");
  return payload.items ?? [];
}

export async function loadChaosRun(id: string): Promise<ChaosExperimentRun> {
  return request<ChaosExperimentRun>(`/experiment-runs/${encodeURIComponent(id)}`);
}

export async function approveChaosRun(id: string, reason: string): Promise<ChaosExperimentRun> {
  return request<ChaosExperimentRun>(`/experiment-runs/${encodeURIComponent(id)}/approve`, { method: "POST", body: JSON.stringify({ reason }) });
}

export async function rejectChaosRun(id: string, reason: string): Promise<ChaosExperimentRun> {
  return request<ChaosExperimentRun>(`/experiment-runs/${encodeURIComponent(id)}/reject`, { method: "POST", body: JSON.stringify({ reason }) });
}

export async function executeChaosRun(id: string): Promise<ChaosExperimentRun> {
  return request<ChaosExperimentRun>(`/experiment-runs/${encodeURIComponent(id)}/execute`, { method: "POST", body: JSON.stringify({}) });
}

export async function abortChaosRun(id: string, reason: string): Promise<ChaosExperimentRun> {
  return request<ChaosExperimentRun>(`/experiment-runs/${encodeURIComponent(id)}/abort`, { method: "POST", body: JSON.stringify({ reason }) });
}

export async function loadModelProviders(): Promise<ModelProviderSettings> {
  return request<ModelProviderSettings>("/settings/model-providers");
}
