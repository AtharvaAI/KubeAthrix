import { demoAuditEvents, demoDashboard, demoFindings, demoIntegrations, demoModelProviders } from "./demoData";
import type { AuditEvent, Dashboard, Finding, Integration, ModelProviderSettings, RemediationPlan } from "./types";

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
  try {
    return await request<Dashboard>("/dashboard");
  } catch {
    return demoDashboard;
  }
}

export async function loadFindings(): Promise<Finding[]> {
  try {
    const payload = await request<{ items: Finding[] }>("/findings");
    return payload.items;
  } catch {
    return demoFindings;
  }
}

export async function createRemediationPlan(findingId: string): Promise<RemediationPlan> {
  try {
    return await request<RemediationPlan>("/remediation-plans", {
      method: "POST",
      body: JSON.stringify({ findingId, requestedBy: "console-dev" })
    });
  } catch {
    const finding = demoFindings.find((item) => item.id === findingId) ?? demoFindings[0];
    return {
      id: `plan-${finding.id}`,
      findingId: finding.id,
      rootCause: "Demo mode: KubeAthrix would ask the model for a structured explanation, then map it to typed controller actions.",
      actions: [
        {
          type: finding.fixability === "safe_deterministic" ? "apply_resource_governance" : "propose_security_hardening",
          target: finding.resources[0],
          description: finding.recommendedAction,
          params: { dryRun: "required", arbitraryCommands: "disabled" }
        }
      ],
      riskTier:
        finding.fixability === "safe_deterministic"
          ? "A"
          : finding.fixability === "dry_run_then_gated"
            ? "B"
            : finding.fixability === "human_approved_only"
              ? "C"
              : "D",
      dryRunResult: {
        passed: finding.fixability !== "informational_no_fix",
        message: "Demo dry-run queued; live clusters use Kubernetes server-side dry-run."
      },
      verificationSteps: ["Validate resource drift", "Run source scanner", "Record audit event"],
      rollbackSteps: ["Restore pre-change object snapshot", "Re-run policy validation"],
      approvalPolicy: {
        required: finding.fixability !== "safe_deterministic",
        categories: finding.fixability === "human_approved_only" ? ["network", "iam", "image-trust"] : ["reliability"]
      },
      status: "proposed",
      createdAt: new Date().toISOString()
    };
  }
}

export async function loadAuditEvents(): Promise<AuditEvent[]> {
  try {
    const payload = await request<{ items: AuditEvent[] }>("/audit-events");
    return payload.items;
  } catch {
    return demoAuditEvents;
  }
}

export async function loadIntegrations(): Promise<Integration[]> {
  try {
    const payload = await request<{ items: Integration[] }>("/integrations");
    return payload.items;
  } catch {
    return demoIntegrations;
  }
}

export async function loadModelProviders(): Promise<ModelProviderSettings> {
  try {
    return await request<ModelProviderSettings>("/settings/model-providers");
  } catch {
    return demoModelProviders;
  }
}
