import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BellRing,
  Bot,
  CheckCircle2,
  Database,
  FileClock,
  FlaskConical,
  Gauge,
  GitPullRequest,
  KeyRound,
  LogOut,
  LockKeyhole,
  Network,
  PlayCircle,
  RotateCcw,
  Search,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  UserCheck,
  Wrench
} from "lucide-react";
import {
  abortChaosRun,
  approveChaosRun,
  approveRemediationPlan,
  createFindingException,
  deleteFindingException,
  createRemediationPlan,
  executeChaosRun,
  executeRemediationPlan,
  loadEvidenceBundle,
  loadAuditEvents,
  loadChaosRuns,
  loadChaosRun,
  loadDashboard,
  loadExperiments,
  loadFindings,
  loadFindingExceptions,
  loadIntegrationHealth,
  loadIntegrations,
  loadManagedResources,
  loadModelProviders,
  loadRemediationRun,
  loadRemediationPlanDiff,
  rejectChaosRun,
  rejectRemediationPlan,
  rollbackRemediationRun,
  startChaosExperiment,
	updateFindingStatus,
  APIError
} from "./api";
import { beginLogin, clearAuthentication, initializeAuth } from "./auth";
import type { AuthState } from "./auth";
import type { AuditEvent, ChaosExperiment, ChaosExperimentRun, ClusterInventory, Dashboard, EvidenceBundle, Finding, FindingException, Integration, IntegrationHealth, ManagedResource, ManagedResourceReference, ManagedResourceSnapshot, ModelProviderSettings, RemediationDiff, RemediationPlan, RemediationRun, ScanSummary, Severity } from "./types";

type View = "dashboard" | "findings" | "fix-center" | "runtime" | "policy" | "managed-resources" | "experiments" | "audit" | "integrations" | "settings";
type ManagedResourceAccess = "ready" | "forbidden" | "unavailable";

const viewItems: Array<{ id: View; label: string; icon: typeof ShieldCheck }> = [
  { id: "dashboard", label: "Dashboard", icon: Gauge },
  { id: "findings", label: "Findings", icon: ShieldCheck },
  { id: "fix-center", label: "Fix Center", icon: Wrench },
  { id: "runtime", label: "Runtime", icon: Activity },
  { id: "policy", label: "Policy", icon: LockKeyhole },
  { id: "managed-resources", label: "Managed resources", icon: Database },
  { id: "experiments", label: "Experiments", icon: FlaskConical },
  { id: "audit", label: "Audit", icon: FileClock },
  { id: "integrations", label: "Integrations", icon: BellRing },
  { id: "settings", label: "Settings", icon: Settings }
];

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

const emptyCluster: ClusterInventory = {
  nodes: 0,
  readyNodes: 0,
  namespaces: 0,
  pods: 0,
  runningPods: 0,
  pendingPods: 0,
  deployments: 0,
  statefulSets: 0,
  daemonSets: 0,
  services: 0,
  ingresses: 0,
  jobs: 0,
  configMaps: 0,
  secrets: 0,
  serviceAccounts: 0,
  roles: 0,
  roleBindings: 0,
  clusterRoles: 0,
  clusterRoleBindings: 0,
  networkPolicies: 0,
  resourceQuotas: 0,
  limitRanges: 0,
  persistentVolumeClaims: 0,
  podDisruptionBudgets: 0,
  horizontalPodAutoscalers: 0,
  events: 0
};

const emptyScan: ScanSummary = {
  lastRunAt: "",
  resourcesScanned: 0,
  policyChecks: 0,
  permissionChecks: 0,
  configurationChecks: 0,
  complianceControls: 0,
  passedControls: 0,
  failedControls: 0
};

function App() {
	const [authState, setAuthState] = useState<AuthState | null>(null);
  const [activeView, setActiveView] = useState<View>("dashboard");
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [exceptions, setExceptions] = useState<FindingException[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState("");
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [integrationHealth, setIntegrationHealth] = useState<Record<string, IntegrationHealth>>({});
  const [managedResources, setManagedResources] = useState<ManagedResourceSnapshot | null>(null);
  const [managedResourceAccess, setManagedResourceAccess] = useState<ManagedResourceAccess>("ready");
  const [managedResourceMessage, setManagedResourceMessage] = useState("");
  const [experiments, setExperiments] = useState<ChaosExperiment[]>([]);
  const [experimentRun, setExperimentRun] = useState<ChaosExperimentRun | null>(null);
  const [experimentMessage, setExperimentMessage] = useState("");
  const [modelProviders, setModelProviders] = useState<ModelProviderSettings | null>(null);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [plan, setPlan] = useState<RemediationPlan | null>(null);
  const [planDiff, setPlanDiff] = useState<RemediationDiff | null>(null);
  const [remediationRun, setRemediationRun] = useState<RemediationRun | null>(null);
  const [evidenceBundle, setEvidenceBundle] = useState<EvidenceBundle | null>(null);
  const [workflowMessage, setWorkflowMessage] = useState("No remediation has been submitted in this console session.");
	const [findingMessage, setFindingMessage] = useState("");
  const [approvalBusy, setApprovalBusy] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
	void initializeAuth().then((state) => {
	  setAuthState(state);
	  if (state.status === "authenticated") void refreshData();
	});
  }, []);

  useEffect(() => {
    if (!remediationRun || !["execution_requested", "running", "verifying", "dry_run_passed", "rollback_requested"].includes(remediationRun.state)) {
      return;
    }
    const timer = window.setInterval(() => {
      void loadRemediationRun(remediationRun.id).then((run) => {
        setRemediationRun(run);
        setWorkflowMessage(`${run.id}: ${humanize(run.state)} — ${run.validationResult}`);
      }).catch(() => undefined);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [remediationRun?.id, remediationRun?.state]);

  useEffect(() => {
    if (!experimentRun || !["pending_approval", "approved", "execution_requested", "running", "cleanup_requested", "abort_requested", "verifying_recovery"].includes(experimentRun.status)) return;
    const timer = window.setInterval(() => {
      void loadChaosRun(experimentRun.id).then((run) => {
        setExperimentRun(run);
        setExperimentMessage(run.message);
      }).catch(() => undefined);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [experimentRun?.id, experimentRun?.status]);

  async function refreshData() {
    setLoading(true);
    try {
      const [dashboardData, findingData, exceptionData, auditData, integrationData, experimentData, chaosRuns, managedResourceResult] = await Promise.all([
        loadDashboard(),
        loadFindings(),
        loadFindingExceptions(),
        loadAuditEvents(),
        loadIntegrations(),
        loadExperiments(),
        loadChaosRuns(),
        loadManagedResources()
          .then((snapshot) => ({ snapshot, access: "ready" as const, message: "" }))
          .catch((error: unknown) => ({
            snapshot: null,
            access: error instanceof APIError && error.status === 403 ? "forbidden" as const : "unavailable" as const,
            message: error instanceof Error ? error.message : "Managed-resource discovery is unavailable."
          }))
      ]);
      const providerData = await loadModelProviders().catch((error: unknown) => {
        if (error instanceof APIError && error.status === 403) return null;
        throw error;
      });
      setDashboard(dashboardData);
      setFindings(findingData);
      setExceptions(exceptionData);
      setAuditEvents(auditData);
      setIntegrations(integrationData);
      void refreshIntegrationHealth(integrationData);
      setManagedResources(managedResourceResult.snapshot);
      setManagedResourceAccess(managedResourceResult.access);
      setManagedResourceMessage(managedResourceResult.message);
      setModelProviders(providerData);
      setExperiments(dashboardData.experiments?.length ? dashboardData.experiments : experimentData);
      setExperimentRun(chaosRuns[0] ?? null);
      setLoadError(null);
      if (findingData.length > 0 && !findingData.some((finding) => finding.id === selectedFindingId)) {
        setSelectedFindingId(findingData[0].id);
      }
      if (findingData.length === 0) {
        setSelectedFindingId("");
      }
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "API unavailable");
    } finally {
      setLoading(false);
    }
  }

  async function refreshIntegrationHealth(items: Integration[]) {
    const entries = await Promise.all(
      items.map(async (integration) => {
        try {
          return [integration.name, await loadIntegrationHealth(integration.name)] as const;
        } catch {
          return [integration.name, null] as const;
        }
      })
    );
    setIntegrationHealth(
      Object.fromEntries(entries.filter((entry): entry is readonly [string, IntegrationHealth] => entry[1] !== null))
    );
  }

  const selectedFinding = useMemo(
    () => findings.find((finding) => finding.id === selectedFindingId) ?? findings[0],
    [findings, selectedFindingId]
  );

  const filteredFindings = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return findings.filter((finding) => {
      const matchesSeverity = severityFilter === "all" || finding.severity === severityFilter;
      const haystack = `${finding.title} ${finding.blastRadius} ${finding.source} ${finding.correlationGroup}`.toLowerCase();
      return matchesSeverity && (normalizedQuery === "" || haystack.includes(normalizedQuery));
    });
  }, [findings, query, severityFilter]);

  async function handleCreatePlan(findingId: string) {
    try {
      const nextPlan = await createRemediationPlan(findingId);
      const nextDiff = await loadRemediationPlanDiff(nextPlan.id);
      setPlan(nextPlan);
      setPlanDiff(nextDiff);
      setRemediationRun(null);
      setEvidenceBundle(null);
      setWorkflowMessage(
        nextPlan.approvalPolicy.required
          ? "Plan created and waiting for explicit approval."
          : "Plan created as deterministic; it is eligible for an explicit execution request."
      );
      setLoadError(null);
      setActiveView("fix-center");
    } catch (error) {
      setWorkflowMessage(error instanceof Error ? error.message : "Unable to create remediation plan.");
    }
  }

	async function handleFindingStatus(findingId: string, status: "open" | "in_review", reason: string) {
		try {
			const updated = await updateFindingStatus(findingId, status, reason);
			setFindings((items) => items.map((item) => item.id === updated.id ? updated : item));
			setFindingMessage(`Finding moved to ${humanize(status)}. The authenticated actor and reason were audited.`);
			setAuditEvents(await loadAuditEvents());
		} catch (error) { setFindingMessage(error instanceof Error ? error.message : "Unable to update finding status."); }
	}

	async function handleSuppressFinding(findingId: string, reason: string, expiresAt: string) {
		try {
			const created = await createFindingException(findingId, reason, expiresAt);
			setFindings(await loadFindings());
			setExceptions((items) => [created, ...items]);
			setAuditEvents(await loadAuditEvents());
			setFindingMessage("Time-bounded exception created; owner identity and expiration were audited.");
		} catch (error) { setFindingMessage(error instanceof Error ? error.message : "Unable to create exception."); }
	}

  async function handleDeleteException(id: string) {
    try {
      await deleteFindingException(id);
      const [findingData, exceptionData, auditData] = await Promise.all([loadFindings(), loadFindingExceptions(), loadAuditEvents()]);
      setFindings(findingData);
      setExceptions(exceptionData);
      setAuditEvents(auditData);
      setFindingMessage("Exception removed; matching findings were reopened when no other active exception applied.");
    } catch (error) {
      setFindingMessage(error instanceof Error ? error.message : "Unable to remove exception.");
    }
  }

  async function handleExecutePlan() {
    if (!plan) {
      return;
    }
    setApprovalBusy(true);
    try {
      const run = await executeRemediationPlan(plan.id);
      setRemediationRun(run);
      setWorkflowMessage(`${run.id} is ${humanize(run.state)}; operator reconciliation has the typed action queue.`);
      const [dashboardData, findingData, auditData] = await Promise.all([loadDashboard(), loadFindings(), loadAuditEvents()]);
      setDashboard(dashboardData);
      setFindings(findingData);
      setAuditEvents(auditData);
      setPlan((current) => current ? { ...current, status: "execution_requested" } : current);
      setLoadError(null);
    } catch (error) {
      setWorkflowMessage(error instanceof Error ? error.message : "Unable to request execution.");
    } finally {
      setApprovalBusy(false);
    }
  }

  async function handleRollback() {
    if (!remediationRun) {
      return;
    }
    setApprovalBusy(true);
    try {
      const run = await rollbackRemediationRun(remediationRun.id);
      setRemediationRun(run);
      setWorkflowMessage(`${run.id}: rollback requested from the controller-owned pre-change snapshot.`);
    } catch (error) {
      setWorkflowMessage(error instanceof Error ? error.message : "Unable to request rollback.");
    } finally {
      setApprovalBusy(false);
    }
  }

  async function handleLoadEvidenceBundle() {
    if (!plan) {
      return;
    }
    try {
      const bundle = await loadEvidenceBundle(plan.id);
      setEvidenceBundle(bundle);
      setWorkflowMessage(`Evidence bundle generated with ${bundle.summary.auditEvents ?? 0} audit event(s).`);
    } catch (error) {
      setWorkflowMessage(error instanceof Error ? error.message : "Unable to load evidence bundle.");
    }
  }

  function handleExportEvidenceBundle() {
    if (!evidenceBundle) return;
    const blob = new Blob([JSON.stringify(evidenceBundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `kubeathrix-evidence-${safeFilename(evidenceBundle.scope)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function handleLogout() {
    if (authState?.status !== "authenticated" || authState.config.mode === "development") return;
    clearAuthentication();
    setAuthState({ status: "login_required", config: authState.config });
    setDashboard(null);
    setFindings([]);
    setExceptions([]);
  }

	async function handleApproval(decision: "approved" | "rejected", reason: string) {
    if (!plan) {
      return;
    }
    setApprovalBusy(true);
    try {
	  const approval = decision === "approved" ? await approveRemediationPlan(plan.id, reason) : await rejectRemediationPlan(plan.id, reason);
      const nextStatus = approval.status === "approved" ? "approved" : "rejected";
      setPlan((current) =>
        current
          ? {
              ...current,
              status: nextStatus,
              approvalPolicy: { ...current.approvalPolicy, decision: approval.status },
              dryRunResult: {
                passed: false,
                message:
                  approval.status === "approved"
                    ? "Approval recorded; no server-side dry-run or cluster write has occurred yet."
                    : "Approval rejected; no cluster change will be attempted."
              }
            }
          : current
      );
      setWorkflowMessage(
        decision === "approved"
          ? `Approved ${plan.id}; execution remains a separate operator action and dry-run is still pending.`
          : `Rejected ${plan.id}; no cluster change will be attempted.`
      );
      const [dashboardData, findingData, auditData] = await Promise.all([loadDashboard(), loadFindings(), loadAuditEvents()]);
      setDashboard(dashboardData);
      setFindings(findingData);
      setAuditEvents(auditData);
      setLoadError(null);
    } catch (error) {
      setWorkflowMessage(error instanceof Error ? error.message : "Unable to record approval decision.");
    } finally {
      setApprovalBusy(false);
    }
  }

  async function handleStartExperiment(experimentId: string, manifest: string) {
    try {
      const run = await startChaosExperiment(experimentId, manifest);
      setExperimentRun(run);
      setExperimentMessage(run.message);
      const auditData = await loadAuditEvents();
      setAuditEvents(auditData);
      setLoadError(null);
    } catch (error) {
      setExperimentMessage(error instanceof Error ? error.message : "Unable to start experiment.");
    }
  }

  async function handleChaosDecision(action: "approve" | "reject" | "execute" | "abort", reason: string) {
    if (!experimentRun) return;
    try {
      const run = action === "approve"
        ? await approveChaosRun(experimentRun.id, reason)
        : action === "reject"
          ? await rejectChaosRun(experimentRun.id, reason)
          : action === "execute"
            ? await executeChaosRun(experimentRun.id)
            : await abortChaosRun(experimentRun.id, reason);
      setExperimentRun(run);
      setExperimentMessage(run.message);
      setAuditEvents(await loadAuditEvents());
    } catch (error) {
      setExperimentMessage(error instanceof Error ? error.message : `Unable to ${action} chaos run.`);
    }
  }

  const currentView = viewItems.find((item) => item.id === activeView) ?? viewItems[0];
  const openFindings = findings.filter((finding) => finding.status === "open" || finding.status === "in_review");
  const priorityFinding = [...openFindings].sort((a, b) => b.riskScore - a.riskScore)[0];
  const aiAgentIntegration = integrations.find((integration) => integration.name.toLowerCase().includes("openai") || integration.name.toLowerCase().includes("ai agent"));
  const agentOnline = Boolean(aiAgentIntegration?.enabled);

	if (authState === null) {
		return <main className="auth-gate"><ShieldCheck size={32} aria-hidden="true" /><h1>KubeAthrix</h1><p>Loading authentication configuration…</p></main>;
	}
	if (authState.status === "error") {
		return <main className="auth-gate"><AlertTriangle size={32} aria-hidden="true" /><h1>Authentication unavailable</h1><p>{authState.message}</p></main>;
	}
	if (authState.status === "login_required") {
		return <main className="auth-gate"><ShieldCheck size={32} aria-hidden="true" /><h1>Sign in to KubeAthrix</h1><p>Use your configured OpenID Connect provider. Authorization Code with PKCE keeps client secrets out of the browser.</p><button className="primary-button" type="button" onClick={() => void beginLogin(authState.config)}>Sign in with OIDC</button></main>;
	}

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            KA
          </div>
          <div>
            <strong>KubeAthrix</strong>
            <span>Guardrail control plane</span>
          </div>
        </div>
        <div className="sidebar-status" aria-label="Cluster status summary">
          <div>
            <span>Risk index</span>
            <strong>{Math.round(dashboard?.meanRiskScore ?? 0)}</strong>
          </div>
          <div>
            <span>Approvals</span>
            <strong>{dashboard?.pendingApprovals ?? 0}</strong>
          </div>
          <div>
            <span>AI agent</span>
            <strong>{agentOnline ? "on" : "off"}</strong>
          </div>
        </div>
        <nav className="nav-list">
          {viewItems.map((item) => {
            const Icon = item.icon;
            const badge = item.id === "findings" && dashboard?.openCritical ? dashboard.openCritical : item.id === "fix-center" && dashboard?.pendingApprovals ? dashboard.pendingApprovals : null;
            return (
              <button
                className={activeView === item.id ? "nav-item active" : "nav-item"}
                key={item.id}
                onClick={() => setActiveView(item.id)}
                type="button"
              >
                <Icon size={18} aria-hidden="true" />
                <span>{item.label}</span>
                {badge ? <em>{badge}</em> : null}
              </button>
            );
          })}
        </nav>
        <div className="guardrail-note">
		  <ShieldCheck size={18} aria-hidden="true" />
		  <span>AI can explain and plan, but controllers execute only versioned typed actions with dry-run, approval, verification, and rollback metadata.</span>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="page-title">
            <p className="eyebrow">Cluster cockpit / {currentView.label}</p>
            <h1>{currentView.label}</h1>
            <span>Live security operations for findings, typed remediation, policy posture, runtime signal, experiments, audit, and integrations.</span>
          </div>
          <div className="topbar-actions">
            <span className="status-pill">
              <CheckCircle2 size={16} aria-hidden="true" />
              {dashboard?.bundledEnginesOnline ?? 0} engines configured
            </span>
            <span className={agentOnline ? "status-pill signal" : "status-pill muted"}>
              <Bot size={16} aria-hidden="true" />
              AI agent {agentOnline ? "watching" : "not configured"}
            </span>
            <button className="icon-button" type="button" title="Refresh data" aria-label="Refresh data" onClick={() => void refreshData()}>
              <RotateCcw size={18} aria-hidden="true" />
            </button>
            {authState.config.mode === "oidc" && (
              <button className="secondary-button" type="button" onClick={handleLogout}>
                <LogOut size={18} aria-hidden="true" />
                Sign out
              </button>
            )}
          </div>
        </header>

        <section className="command-strip" aria-label="Operational command strip">
          <div className="command-card danger">
            <span>Critical queue</span>
            <strong>{dashboard?.openCritical ?? 0}</strong>
            <small>{priorityFinding ? `Top risk: ${priorityFinding.riskScore}` : "No active critical queue"}</small>
          </div>
          <div className="command-card warning">
            <span>Pending approvals</span>
            <strong>{dashboard?.pendingApprovals ?? 0}</strong>
            <small>Human-gated actions stay separated from execution.</small>
          </div>
          <div className="command-card signal">
            <span>Cluster coverage</span>
            <strong>{dashboard?.scan?.resourcesScanned ?? 0}</strong>
            <small>{dashboard?.evidenceFreshness ?? "unknown"} evidence freshness.</small>
          </div>
          <div className="command-actions">
            <button className="primary-button" type="button" disabled={!priorityFinding} onClick={() => {
              if (!priorityFinding) return;
              setSelectedFindingId(priorityFinding.id);
              setActiveView("findings");
            }}>
              <Search size={18} aria-hidden="true" />
              Triage top risk
            </button>
            <button className="secondary-button" type="button" onClick={() => setActiveView("fix-center")}>
              <Wrench size={18} aria-hidden="true" />
              Open Fix Center
            </button>
          </div>
        </section>

        {loadError && <ErrorPanel message={loadError} onRetry={() => void refreshData()} />}
        {!loadError && loading && <LoadingPanel />}
        {!loadError && !loading && activeView === "dashboard" && dashboard && (
          <DashboardView dashboard={dashboard} findings={findings} onOpenFinding={(id) => {
            setSelectedFindingId(id);
            setActiveView("findings");
          }} />
        )}
        {!loadError && !loading && activeView === "findings" && (
          <FindingsView
            findings={filteredFindings}
            selectedFinding={selectedFinding}
            query={query}
            severityFilter={severityFilter}
            onQueryChange={setQuery}
            onSeverityChange={setSeverityFilter}
            onSelect={setSelectedFindingId}
            onCreatePlan={handleCreatePlan}
			onStatus={handleFindingStatus}
			onSuppress={handleSuppressFinding}
			onDeleteException={handleDeleteException}
			exceptions={exceptions}
			message={findingMessage}
          />
        )}
        {!loadError && !loading && activeView === "fix-center" && (
          <FixCenterView plan={plan} run={remediationRun} diff={planDiff} evidenceBundle={evidenceBundle} finding={selectedFinding} workflowMessage={workflowMessage} approvalBusy={approvalBusy} onCreatePlan={handleCreatePlan} onApproval={handleApproval} onExecute={handleExecutePlan} onRollback={handleRollback} onEvidenceBundle={handleLoadEvidenceBundle} onExportEvidenceBundle={handleExportEvidenceBundle} />
        )}
        {!loadError && !loading && activeView === "runtime" && <RuntimeView findings={findings.filter((finding) => finding.source === "falco" || finding.source === "tetragon")} />}
        {!loadError && !loading && activeView === "policy" && dashboard && <PolicyView findings={findings} dashboard={dashboard} />}
        {!loadError && !loading && activeView === "managed-resources" && <ManagedResourcesView snapshot={managedResources} access={managedResourceAccess} message={managedResourceMessage} />}
        {!loadError && !loading && activeView === "experiments" && <ExperimentsView experiments={experiments} run={experimentRun} message={experimentMessage} onStart={handleStartExperiment} onDecision={handleChaosDecision} />}
        {!loadError && !loading && activeView === "audit" && <AuditView events={auditEvents} />}
        {!loadError && !loading && activeView === "integrations" && <IntegrationsView integrations={integrations} health={integrationHealth} />}
        {!loadError && !loading && activeView === "settings" && <SettingsView providers={modelProviders} />}
      </main>
    </div>
  );
}

function LoadingPanel() {
  return (
    <section className="view-grid" aria-live="polite" aria-busy="true">
      <div className="panel wide-panel">
        <div className="panel-heading">
          <div><p className="eyebrow">Live control plane</p><h2>Loading authorized cluster data</h2></div>
          <Activity size={20} aria-hidden="true" />
        </div>
        <p className="summary-text">Reading findings, evidence freshness, workflow state, integrations, and audit history.</p>
      </div>
    </section>
  );
}

function ErrorPanel({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <section className="view-grid">
      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Data plane</p>
            <h2>API unavailable</h2>
          </div>
          <AlertTriangle size={20} aria-hidden="true" />
        </div>
        <p className="summary-text">{message}</p>
        <button className="primary-button" type="button" onClick={onRetry}>
          <RotateCcw size={18} aria-hidden="true" />
          Retry
        </button>
      </div>
    </section>
  );
}

function DashboardView({ dashboard, findings, onOpenFinding }: { dashboard: Dashboard; findings: Finding[]; onOpenFinding: (id: string) => void }) {
  const topFindings = [...findings].sort((a, b) => b.riskScore - a.riskScore).slice(0, 3);
  const cluster = dashboard.cluster ?? emptyCluster;
  const scan = dashboard.scan ?? emptyScan;
  const compliance = dashboard.compliance ?? [];
  const workloadCount = (cluster.deployments ?? 0) + (cluster.statefulSets ?? 0) + (cluster.daemonSets ?? 0) + (cluster.jobs ?? 0);
  const severityDenominator = Math.max(dashboard.totalFindings, 1);
  return (
    <section className="view-grid dashboard-grid">
      <div className="panel command-hero wide4-panel">
        <div className="hero-copy">
          <p className="eyebrow">Autonomous remediation cockpit</p>
          <h2>Correlated cluster risk</h2>
          <p>
            KubeAthrix correlates scanner evidence, Kubernetes inventory, runtime adapters, policy posture, and typed remediation state so operators can move from detection to approval to verified fix without losing context.
          </p>
          <div className="hero-actions">
            {topFindings[0] && (
              <button className="primary-button" type="button" onClick={() => onOpenFinding(topFindings[0].id)}>
                <Sparkles size={18} aria-hidden="true" />
                Investigate highest risk
              </button>
            )}
            <span className="status-pill muted">No arbitrary kubectl path</span>
            <span className="status-pill signal">Typed action catalog</span>
          </div>
        </div>
        <div className="hero-radar" aria-label="Current risk posture">
          <div className="radar-orbit" />
          <strong>{Math.round(dashboard.meanRiskScore)}</strong>
          <span>mean risk</span>
        </div>
      </div>
      <Metric label="Total findings" value={dashboard.totalFindings} tone="neutral" icon={ShieldCheck} />
      <Metric label="Open critical" value={dashboard.openCritical} tone="danger" icon={AlertTriangle} />
      <Metric label="Pending approvals" value={dashboard.pendingApprovals} tone="warning" icon={UserCheck} />
      <Metric label="Mean risk score" value={Math.round(dashboard.meanRiskScore)} tone="signal" icon={Gauge} />
      <Metric label="Safe fixes" value={dashboard.findingsWithSafeFix ?? 0} tone="signal" icon={Wrench} />
      <Metric label="Verified fixes" value={dashboard.verifiedRemediations ?? 0} tone="signal" icon={CheckCircle2} />
      <Metric label="Risk reduced" value={dashboard.riskReduced ?? 0} tone="neutral" icon={ShieldCheck} />
      <Metric label="Nodes ready" value={cluster.readyNodes ?? 0} tone="signal" icon={Activity} />
      <Metric label="Pods running" value={cluster.runningPods ?? 0} tone="neutral" icon={Database} />
      <Metric label="Namespaces" value={cluster.namespaces ?? 0} tone="neutral" icon={Network} />
      <Metric label="Workloads" value={workloadCount} tone="neutral" icon={GitPullRequest} />

      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Live inventory</p>
            <h2>Cluster resources</h2>
          </div>
          <span className="status-pill muted">
            <Activity size={16} aria-hidden="true" />
            {cluster.nodes ?? 0} nodes
          </span>
        </div>
        <div className="fact-grid dense">
          <Fact label="Pods" value={`${cluster.runningPods ?? 0}/${cluster.pods ?? 0} running`} />
          <Fact label="Deployments" value={cluster.deployments ?? 0} />
          <Fact label="DaemonSets" value={cluster.daemonSets ?? 0} />
          <Fact label="StatefulSets" value={cluster.statefulSets ?? 0} />
          <Fact label="Services" value={cluster.services ?? 0} />
          <Fact label="Ingresses" value={cluster.ingresses ?? 0} />
          <Fact label="Jobs" value={cluster.jobs ?? 0} />
          <Fact label="PVCs" value={cluster.persistentVolumeClaims ?? 0} />
        </div>
      </div>

      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Scan coverage</p>
            <h2>Configuration, policy, permissions</h2>
          </div>
          <span className="status-pill signal">{scan.resourcesScanned ?? 0} objects</span>
        </div>
        <div className="fact-grid dense">
          <Fact label="Config checks" value={scan.configurationChecks ?? 0} />
          <Fact label="Policy checks" value={scan.policyChecks ?? 0} />
          <Fact label="Permission checks" value={scan.permissionChecks ?? 0} />
          <Fact label="Compliance controls" value={`${scan.passedControls ?? 0}/${scan.complianceControls ?? 0} pass`} />
          <Fact label="Evidence freshness" value={dashboard.evidenceFreshness ?? "unknown"} />
          <Fact label="NetworkPolicies" value={cluster.networkPolicies ?? 0} />
          <Fact label="ResourceQuotas" value={cluster.resourceQuotas ?? 0} />
          <Fact label="LimitRanges" value={cluster.limitRanges ?? 0} />
          <Fact label="PDBs / HPAs" value={`${cluster.podDisruptionBudgets ?? 0} / ${cluster.horizontalPodAutoscalers ?? 0}`} />
        </div>
      </div>

      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">RBAC and operational metadata</p>
            <h2>Access surface</h2>
          </div>
          <LockKeyhole size={20} aria-hidden="true" />
        </div>
        <div className="fact-grid dense">
          <Fact label="ServiceAccounts" value={cluster.serviceAccounts ?? 0} />
          <Fact label="Roles" value={cluster.roles ?? 0} />
          <Fact label="RoleBindings" value={cluster.roleBindings ?? 0} />
          <Fact label="ClusterRoles" value={cluster.clusterRoles ?? 0} />
          <Fact label="ClusterRoleBindings" value={cluster.clusterRoleBindings ?? 0} />
          <Fact label="ConfigMaps" value={cluster.configMaps ?? 0} />
          <Fact label="Recent events" value={cluster.events ?? 0} />
        </div>
      </div>

      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Issue graph</p>
            <h2>Risk topology</h2>
          </div>
          <span className="status-pill muted">
            <Network size={16} aria-hidden="true" />
            {dashboard.protectedNamespaces} namespaces
          </span>
        </div>
        <div className="topology-map" aria-label="Correlated risk topology">
          <div className="topology-node severe">Public service</div>
          <div className="topology-line" />
          <div className="topology-node warning">RBAC drift</div>
          <div className="topology-line" />
          <div className="topology-node neutral">Image trust</div>
          <div className="topology-line" />
          <div className="topology-node signal">Typed fix plan</div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Severity</p>
            <h2>Open distribution</h2>
          </div>
        </div>
        <div className="bar-stack">
          {severityOrder.map((severity) => (
            <div className="bar-row" key={severity}>
              <span>{severity}</span>
              <div className="bar-track">
                <div className={`bar-fill ${severity}`} style={{ width: `${((dashboard.findingsBySeverity[severity] ?? 0) / severityDenominator) * 100}%` }} />
              </div>
              <strong>{dashboard.findingsBySeverity[severity] ?? 0}</strong>
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Compliance</p>
            <h2>Control status</h2>
          </div>
        </div>
        <div className="timeline compact-timeline">
          {compliance.slice(0, 4).map((control) => (
            <div className={`timeline-item ${control.status === "pass" ? "pass" : "fail"}`} key={control.id}>
              <strong>{control.id} - {humanize(control.status)}</strong>
              <span>{control.title}</span>
              <small>{control.framework}</small>
            </div>
          ))}
          {compliance.length === 0 && <p className="summary-text">Live compliance controls will appear after the API can read the cluster.</p>}
        </div>
      </div>

      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Highest risk</p>
            <h2>Operator queue</h2>
          </div>
        </div>
        <div className="finding-list compact">
          {topFindings.map((finding) => (
            <button className="finding-row" key={finding.id} onClick={() => onOpenFinding(finding.id)} type="button">
              <SeverityBadge severity={finding.severity} />
              <span>{finding.title}</span>
              <strong>{finding.riskScore}</strong>
            </button>
          ))}
          {topFindings.length === 0 && <p className="summary-text">No open findings returned by the cluster scanner.</p>}
        </div>
      </div>
    </section>
  );
}

function FindingsView(props: {
  findings: Finding[];
  selectedFinding?: Finding;
  exceptions: FindingException[];
  query: string;
  severityFilter: string;
  onQueryChange: (value: string) => void;
  onSeverityChange: (value: string) => void;
  onSelect: (id: string) => void;
  onCreatePlan: (id: string) => void;
	onStatus: (id: string, status: "open" | "in_review", reason: string) => void | Promise<void>;
	onSuppress: (id: string, reason: string, expiresAt: string) => void | Promise<void>;
	onDeleteException: (id: string) => void | Promise<void>;
	message: string;
}) {
  return (
    <section className="split-view">
      <div className="panel list-panel">
        <div className="toolbar">
          <label className="search-box">
            <Search size={18} aria-hidden="true" />
            <input value={props.query} onChange={(event) => props.onQueryChange(event.target.value)} placeholder="Search findings" />
          </label>
          <label className="select-box">
            <SlidersHorizontal size={18} aria-hidden="true" />
            <select value={props.severityFilter} onChange={(event) => props.onSeverityChange(event.target.value)}>
              <option value="all">All severity</option>
              {severityOrder.map((severity) => (
                <option value={severity} key={severity}>
                  {severity}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="finding-list">
          {props.findings.map((finding) => (
            <button className={props.selectedFinding?.id === finding.id ? "finding-row selected" : "finding-row"} key={finding.id} onClick={() => props.onSelect(finding.id)} type="button">
              <SeverityBadge severity={finding.severity} />
              <span>{finding.title}</span>
              <strong>{finding.riskScore}</strong>
            </button>
          ))}
          {props.findings.length === 0 && <p className="summary-text">No findings match the current filters.</p>}
        </div>
      </div>

      {props.selectedFinding && (
		<FindingDetail finding={props.selectedFinding} exceptions={props.exceptions.filter((item) => item.scope === props.selectedFinding!.id || item.scope === props.selectedFinding!.correlationGroup || item.scope === `source:${props.selectedFinding!.source}`)} message={props.message} onStatus={props.onStatus} onSuppress={props.onSuppress} onDeleteException={props.onDeleteException} onCreatePlan={() => props.onCreatePlan(props.selectedFinding!.id)} />
      )}
    </section>
  );
}

function FindingDetail({ finding, exceptions, message, onCreatePlan, onStatus, onSuppress, onDeleteException }: { finding: Finding; exceptions: FindingException[]; message: string; onCreatePlan: () => void; onStatus: (id: string, status: "open" | "in_review", reason: string) => void | Promise<void>; onSuppress: (id: string, reason: string, expiresAt: string) => void | Promise<void>; onDeleteException: (id: string) => void | Promise<void> }) {
	const [reason, setReason] = useState("");
	const [expiresAt, setExpiresAt] = useState(() => new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 16));
  return (
    <article className="panel detail-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">{finding.source}</p>
          <h2>{finding.title}</h2>
        </div>
        <SeverityBadge severity={finding.severity} />
      </div>
      <p className="summary-text">{finding.blastRadius}</p>
      <div className="fact-grid">
        <Fact label="Fixability" value={humanize(finding.fixability)} />
        <Fact label="State" value={humanize(finding.remediationState)} />
        <Fact label="Group" value={finding.correlationGroup} />
        <Fact label="Status" value={humanize(finding.status)} />
      </div>
      <div className="action-callout">
        <Sparkles size={20} aria-hidden="true" />
        <div>
          <strong>Recommended next action</strong>
          <span>{finding.recommendedAction || "Generate a typed plan and review the deterministic diff before approval."}</span>
        </div>
      </div>
      <h3>Evidence</h3>
      <div className="timeline">
        {finding.evidence.map((item) => (
          <div className="timeline-item" key={`${item.sourceId}-${item.summary}`}>
            <strong>{item.summary}</strong>
            <span>{item.details}</span>
            <small>{item.sourceId}</small>
          </div>
        ))}
      </div>
	  {finding.riskExplanation && (
		<><h3>Why this risk score</h3><div className="timeline"><div className="timeline-item"><strong>Model {finding.riskExplanation.version}: base {finding.riskExplanation.baseScore}, final {finding.riskExplanation.finalScore}</strong>{finding.riskExplanation.factors.map((factor) => <span key={factor.name}>+{factor.points} {factor.reason}</span>)}</div></div></>
	  )}
      <h3>Affected resources</h3>
      <div className="resource-list">
        {finding.resources.map((resource) => (
          <code key={`${resource.kind}-${resource.namespace}-${resource.name}`}>
            {resource.kind}/{resource.namespace ? `${resource.namespace}/` : ""}
            {resource.name}
          </code>
        ))}
      </div>
	  <h3>Lifecycle and exception</h3>
	  <label><span>Audit reason</span><input value={reason} maxLength={2048} onChange={(event) => setReason(event.target.value)} placeholder="Required for lifecycle changes" /></label>
	  <label><span>Exception expires</span><input type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label>
	  <div className="button-row">
		<button className="secondary-button" disabled={!reason.trim()} type="button" onClick={() => void onStatus(finding.id, finding.status === "in_review" ? "open" : "in_review", reason.trim())}>{finding.status === "in_review" ? "Reopen" : "Mark in review"}</button>
		<button className="secondary-button" disabled={!reason.trim() || !expiresAt || finding.status === "suppressed"} type="button" onClick={() => void onSuppress(finding.id, reason.trim(), new Date(expiresAt).toISOString())}>Create exception</button>
	  </div>
	  {exceptions.length > 0 && <div className="timeline" aria-label="Matching exceptions">
		{exceptions.map((item) => <div className="timeline-item" key={item.id}>
		  <strong>{humanize(item.status)} until {new Date(item.expiresAt).toLocaleString()}</strong>
		  <span>{item.reason}</span>
		  <small>{item.owner} · {item.id}</small>
		  <button className="secondary-button" type="button" onClick={() => void onDeleteException(item.id)}>Remove exception</button>
		</div>)}
	  </div>}
	  {message && <p className="summary-text">{message}</p>}
      <button className="primary-button" type="button" onClick={onCreatePlan}>
        <Sparkles size={18} aria-hidden="true" />
        Generate typed plan
      </button>
    </article>
  );
}

function FixCenterView({
  plan,
  run,
  diff,
  evidenceBundle,
  finding,
  workflowMessage,
  approvalBusy,
  onCreatePlan,
  onApproval,
  onExecute,
  onRollback,
  onEvidenceBundle,
  onExportEvidenceBundle
}: {
  plan: RemediationPlan | null;
  run: RemediationRun | null;
  diff: RemediationDiff | null;
  evidenceBundle: EvidenceBundle | null;
  finding?: Finding;
  workflowMessage: string;
  approvalBusy: boolean;
  onCreatePlan: (id: string) => void;
	onApproval: (decision: "approved" | "rejected", reason: string) => void | Promise<void>;
  onExecute: () => void | Promise<void>;
  onRollback: () => void | Promise<void>;
  onEvidenceBundle: () => void | Promise<void>;
  onExportEvidenceBundle: () => void;
}) {
  const planBadge = plan ? remediationBadge(plan) : null;
	const [decisionReason, setDecisionReason] = useState("");
  const decisionLocked = plan?.approvalPolicy.decision === "approved" || plan?.approvalPolicy.decision === "rejected";
  const terminalPlanStatuses = ["proposal_only", "dry_run_passed", "succeeded", "failed", "rolled_back"];
  const executeLocked = !plan || (plan.approvalPolicy.required && plan.approvalPolicy.decision !== "approved") || ["rejected", "execution_requested", "running", ...terminalPlanStatuses].includes(plan.status);
  return (
    <section className="view-grid fix-grid">
      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Workflow</p>
            <h2>Find, explain, fix, verify, prove</h2>
          </div>
        </div>
        <div className="control-loop">
          {["Normalize", "Plan", "Approve", "Execute", "Dry-run", "Verify"].map((step, index) => (
            <div className="loop-step" key={step}>
              <span>{index + 1}</span>
              <strong>{step}</strong>
            </div>
          ))}
        </div>
        <p className="summary-text">{workflowMessage}</p>
      </div>

      <div className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Current target</p>
            <h2>{finding?.title ?? "No finding selected"}</h2>
          </div>
        </div>
        {finding && (
          <button className="primary-button" type="button" onClick={() => onCreatePlan(finding.id)}>
            <GitPullRequest size={18} aria-hidden="true" />
            Create plan
          </button>
        )}
      </div>

      {plan && (
        <div className="panel wide-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Plan {plan.id}</p>
              <h2>Risk tier {plan.riskTier}</h2>
            </div>
            <span className={`status-pill ${planBadge?.tone ?? "muted"}`}>
              {planBadge?.label}
            </span>
          </div>
          <p className="summary-text">{plan.rootCause}</p>
          <div className="fact-grid dense">
            <Fact label="Dry-run" value={plan.dryRunResult.passed ? "passed" : "pending"} />
            <Fact label="Catalog" value={plan.catalogVersion || "unknown"} />
            <Fact label="Plan status" value={humanize(plan.status)} />
            <Fact label="Approval gate" value={!plan.approvalPolicy.required ? "not required" : plan.approvalPolicy.decision ?? "pending"} />
            <Fact label="Actions" value={plan.actions.length} />
          </div>
          <div className="action-list">
            {plan.actions.map((action) => (
              <div className="action-row" key={`${action.type}-${action.target.name}`}>
                <Wrench size={18} aria-hidden="true" />
                <div>
                  <strong>{humanize(action.type)}</strong>
                  <span>{action.description}</span>
                </div>
                <code>{action.target.kind}/{action.target.name}</code>
              </div>
            ))}
          </div>
          {plan.ai && (
            <div className="ai-insight-card">
              <div className="action-row">
                <Sparkles size={18} aria-hidden="true" />
                <div>
                  <strong>AI decision support</strong>
                  <span>{plan.ai.provider} / {plan.ai.model} / confidence {plan.ai.confidence}</span>
                </div>
                <code>{plan.ai.mode}</code>
              </div>
              <p className="summary-text">{plan.ai.summary}</p>
              <div className="two-column-list">
                <div>
                  <h3>Reasoning</h3>
                  <ul>
                    <li>{plan.ai.rootCause}</li>
                    <li>{plan.ai.impact}</li>
                    <li>{plan.ai.recommendedAction}</li>
                  </ul>
                </div>
                <div>
                  <h3>Safety boundary</h3>
                  <ul>
                    <li>{plan.ai.autonomousPolicy}</li>
                    {(plan.ai.safetyNotes ?? []).map((note) => <li key={note}>{note}</li>)}
                  </ul>
                </div>
              </div>
            </div>
          )}
          <p className="summary-text">{plan.dryRunResult.message}</p>
          <div className="two-column-list">
            <div>
              <h3>Verification</h3>
              <ul>
                {plan.verificationSteps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ul>
            </div>
            <div>
              <h3>Rollback</h3>
              <ul>
                {plan.rollbackSteps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ul>
            </div>
          </div>
          <div className="button-row">
			<label><span>Approval decision reason</span><input value={decisionReason} maxLength={2048} onChange={(event) => setDecisionReason(event.target.value)} /></label>
			<button className="primary-button" type="button" disabled={approvalBusy || decisionLocked || !decisionReason.trim()} onClick={() => void onApproval("approved", decisionReason.trim())}>
              <PlayCircle size={18} aria-hidden="true" />
              {approvalBusy ? "Working" : "Approve"}
            </button>
			<button className="secondary-button" type="button" disabled={approvalBusy || decisionLocked || !decisionReason.trim()} onClick={() => void onApproval("rejected", decisionReason.trim())}>
              <RotateCcw size={18} aria-hidden="true" />
              Reject
            </button>
            <button className="primary-button" type="button" disabled={approvalBusy || executeLocked} onClick={() => void onExecute()}>
              <PlayCircle size={18} aria-hidden="true" />
              Execute
            </button>
            <button className="secondary-button" type="button" onClick={() => void onEvidenceBundle()}>
              <Database size={18} aria-hidden="true" />
              Build evidence bundle
            </button>
            <button className="secondary-button" type="button" disabled={!evidenceBundle} onClick={onExportEvidenceBundle}>
              <Database size={18} aria-hidden="true" />
              Export evidence JSON
            </button>
          </div>
        </div>
      )}

      {diff && (
        <div className="panel wide-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">{diff.mode}</p>
              <h2>Typed diff</h2>
            </div>
          </div>
          <p className="summary-text">{diff.summary}</p>
          <div className="action-list">
            {diff.manifests.map((manifest) => (
              <div className="manifest-block" key={`${manifest.actionType}-${manifest.target.kind}-${manifest.target.name}`}>
                <div className="action-row">
                  <GitPullRequest size={18} aria-hidden="true" />
                  <div>
                    <strong>{humanize(manifest.actionType)}</strong>
                    <span>{manifest.diff}</span>
                  </div>
                  <code>{manifest.writeMode}</code>
                </div>
                <div className="two-column-list">
                  <div>
                    <h3>Required permissions</h3>
                    <ul>{(manifest.requiredPermissions ?? []).map((item) => <li key={item}>{item}</li>)}</ul>
                  </div>
                  <div>
                    <h3>Failure and rollback</h3>
                    <ul>
                      <li>{manifest.failureHandling || "No failure policy reported."}</li>
                      {(manifest.rollbackProcedure ?? []).map((item) => <li key={item}>{item}</li>)}
                    </ul>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {run && (
        <div className="panel wide-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Controller-owned run {run.id}</p>
              <h2>{humanize(run.state)}</h2>
            </div>
            <span className="status-pill signal">live CRD status</span>
          </div>
          <p className="summary-text">{run.validationResult}</p>
          <div className="action-list">
            {(run.actionStatuses ?? []).map((status) => (
              <div className="action-row" key={`${status.actionType}-${status.state}`}>
                <Activity size={18} aria-hidden="true" />
                <div><strong>{humanize(status.actionType)}</strong><span>{status.message}</span></div>
                <code>{humanize(status.state)}</code>
              </div>
            ))}
          </div>
          <div className="fact-grid dense">
            <Fact label="Rollback snapshot" value={run.rollbackMetadata || "not captured"} />
            <Fact label="Last update" value={run.updatedAt ? new Date(run.updatedAt).toLocaleString() : "pending"} />
          </div>
          <button className="secondary-button" type="button" disabled={approvalBusy || !["succeeded", "failed", "verifying"].includes(run.state)} onClick={() => void onRollback()}>
            <RotateCcw size={18} aria-hidden="true" />
            Request rollback
          </button>
        </div>
      )}

      {evidenceBundle && (
        <div className="panel wide-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Proof bundle</p>
              <h2>{evidenceBundle.scope}</h2>
            </div>
            <span className="status-pill signal">{evidenceBundle.summary.auditEvents ?? 0} audit events</span>
          </div>
          <div className="fact-grid dense">
            <Fact label="Findings" value={evidenceBundle.summary.findings ?? 0} />
            <Fact label="Plans" value={evidenceBundle.summary.plans ?? 0} />
            <Fact label="Runs" value={evidenceBundle.summary.runs ?? 0} />
            <Fact label="Generated" value={new Date(evidenceBundle.generatedAt).toLocaleString()} />
          </div>
        </div>
      )}
    </section>
  );
}

function RuntimeView({ findings }: { findings: Finding[] }) {
  return (
    <section className="view-grid">
      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Runtime console</p>
            <h2>Falco and Tetragon adapter stream</h2>
          </div>
          <span className="status-pill muted">notify-first</span>
        </div>
        <div className="timeline">
          {(findings.length > 0 ? findings : []).map((finding) => (
            <div className="timeline-item" key={finding.id}>
              <strong>{finding.title}</strong>
              <span>{finding.blastRadius}</span>
              <small>{finding.resources[0]?.kind}/{finding.resources[0]?.name}</small>
            </div>
          ))}
          {findings.length === 0 && <p className="summary-text">No runtime findings are currently reported.</p>}
        </div>
      </div>
    </section>
  );
}

function PolicyView({ findings, dashboard }: { findings: Finding[]; dashboard: Dashboard }) {
  const policyFindings = findings.filter((finding) => ["kyverno", "kubescape", "correlator", "kubeathrix-scan"].includes(finding.source));
  const cluster = dashboard.cluster ?? emptyCluster;
  const compliance = dashboard.compliance ?? [];
  return (
    <section className="view-grid">
      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Compliance</p>
            <h2>Control posture</h2>
          </div>
          <LockKeyhole size={20} aria-hidden="true" />
        </div>
        <div className="control-grid">
          {compliance.map((control) => (
            <div className={`control-card ${control.status === "pass" ? "pass" : "fail"}`} key={control.id}>
              <span>{control.framework}</span>
              <strong>{control.id}</strong>
              <p>{control.title}</p>
              <small>{control.evidence}</small>
            </div>
          ))}
        </div>
      </div>

      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Guardrails</p>
            <h2>Policy and permission coverage</h2>
          </div>
        </div>
        <div className="fact-grid dense">
          <Fact label="NetworkPolicies" value={cluster.networkPolicies} />
          <Fact label="ResourceQuotas" value={cluster.resourceQuotas} />
          <Fact label="LimitRanges" value={cluster.limitRanges} />
          <Fact label="PodDisruptionBudgets" value={cluster.podDisruptionBudgets} />
          <Fact label="Roles" value={cluster.roles} />
          <Fact label="RoleBindings" value={cluster.roleBindings} />
          <Fact label="ClusterRoles" value={cluster.clusterRoles} />
          <Fact label="ClusterRoleBindings" value={cluster.clusterRoleBindings} />
        </div>
      </div>

      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Scanner output</p>
            <h2>Policy findings</h2>
          </div>
        </div>
        <div className="finding-list compact">
          {policyFindings.map((finding) => (
            <div className="static-row" key={finding.id}>
              <SeverityBadge severity={finding.severity} />
              <span>{finding.title}</span>
              <code>{humanize(finding.fixability)}</code>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function ManagedResourcesView({ snapshot, access, message }: { snapshot: ManagedResourceSnapshot | null; access: ManagedResourceAccess; message: string }) {
  if (access === "forbidden") {
    return (
      <section className="view-grid managed-resource-grid">
        <ManagedResourceBoundary />
        <ManagedResourceState
          eyebrow="Access boundary"
          title="Managed-resource inventory is not available to this identity"
          message="Your Kubernetes scope does not permit this cluster-wide inventory. Native findings and other authorized console data remain available."
        />
      </section>
    );
  }

  if (access === "unavailable" || !snapshot) {
    return (
      <section className="view-grid managed-resource-grid">
        <ManagedResourceBoundary />
        <ManagedResourceState
          eyebrow="Discovery status"
          title="Managed-resource discovery is unavailable"
          message={message || "The optional discovery endpoint is not configured or could not be reached."}
        />
      </section>
    );
  }

  if (!snapshot.enabled) {
    return (
      <section className="view-grid managed-resource-grid">
        <ManagedResourceBoundary />
        <ManagedResourceState
          eyebrow="Discovery status"
          title="Managed-resource discovery is disabled"
          message="Enable the allowlisted managed-external-resource adapter and its read-only RBAC rules to inventory Kubernetes-managed resources."
        />
      </section>
    );
  }

  const resources = snapshot.resources ?? [];
  const relationships = snapshot.relationships ?? [];
  const warnings = snapshot.warnings ?? [];
  const readyCount = resources.filter((resource) => resource.status.ready === true).length;
  const syncedCount = resources.filter((resource) => resource.status.synced === true).length;
  const gitOpsCount = resources.filter((resource) => resource.provenance.gitOps).length;

  return (
    <section className="view-grid managed-resource-grid">
      <ManagedResourceBoundary />
      <Metric label="Managed objects" value={resources.length} tone="neutral" icon={Database} />
      <Metric label="Ready" value={readyCount} tone="signal" icon={CheckCircle2} />
      <Metric label="Synced" value={syncedCount} tone="signal" icon={GitPullRequest} />
      <Metric label="GitOps-owned" value={gitOpsCount} tone="neutral" icon={Network} />

      {resources.map((resource) => {
        const related = relationships.filter((relationship) => referenceMatchesResource(relationship.from, resource) || referenceMatchesResource(relationship.to, resource));
        return (
          <article className="panel wide-panel managed-resource-card" key={resource.id}>
            <div className="panel-heading">
              <div>
                <p className="eyebrow">{resource.apiVersion} / {resource.plural}</p>
                <h2>{resource.kind}/{resource.name}</h2>
              </div>
              <div className="managed-resource-badges">
                <span className={resource.status.stalled === true ? "status-pill danger" : "status-pill muted"}>
                  {resource.status.stalled === true ? "Stalled" : resource.status.state || "Observed"}
                </span>
                {resource.provenance.gitOps && <span className="status-pill signal">GitOps</span>}
              </div>
            </div>
            <div className="fact-grid dense managed-resource-facts">
              <Fact label="Scope" value={resource.namespace ? `Namespace: ${resource.namespace}` : "Cluster-scoped"} />
              <Fact label="Controller" value={resource.provenance.controller || humanize(resource.provenance.system)} />
              <Fact label="Management" value={humanize(resource.provenance.system)} />
              <Fact label="Ready" value={managedBoolean(resource.status.ready)} />
              <Fact label="Synced" value={managedBoolean(resource.status.synced)} />
              <Fact label="Stalled" value={managedBoolean(resource.status.stalled)} />
              <Fact label="Generation" value={resource.generation ?? "unknown"} />
              <Fact label="Observed generation" value={resource.status.observedGeneration ?? "unknown"} />
              <Fact label="External ID" value={resource.externalId || "not reported"} />
              <Fact label="Relationships" value={related.length} />
            </div>
            <div className="managed-source-card">
              <GitPullRequest size={19} aria-hidden="true" />
              <div>
                <strong>Source of truth</strong>
                <span>{managedResourceSourceOfTruth(resource)}</span>
                <small>Any change is HITL and proposal-only; review and apply it at this source rather than mutating the external provider directly.</small>
              </div>
            </div>
            {(resource.status.conditions ?? []).length > 0 && (
              <div className="managed-condition-list" aria-label={`${resource.kind} ${resource.name} conditions`}>
                {(resource.status.conditions ?? []).slice(0, 4).map((condition) => (
                  <span key={`${condition.type}-${condition.reason ?? condition.status}`}>
                    <strong>{condition.type}: {condition.status}</strong>
                    {condition.reason ? ` / ${condition.reason}` : ""}
                  </span>
                ))}
              </div>
            )}
          </article>
        );
      })}

      {resources.length === 0 && (
        <ManagedResourceState
          eyebrow="Allowlisted discovery"
          title="No managed resources were returned"
          message="Discovery is enabled, but no objects matched the configured allowlist and current Kubernetes authorization scope."
        />
      )}

      {relationships.length > 0 && (
        <div className="panel wide4-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Ownership graph</p>
              <h2>Kubernetes source relationships</h2>
            </div>
            <span className="status-pill muted">{relationships.length} links</span>
          </div>
          <div className="managed-relationship-list">
            {relationships.slice(0, 12).map((relationship, index) => (
              <div className="managed-relationship" key={`${managedResourceRefLabel(relationship.from)}-${relationship.type}-${managedResourceRefLabel(relationship.to)}-${index}`}>
                <code>{managedResourceRefLabel(relationship.from)}</code>
                <span>{humanize(relationship.type)}</span>
                <code>{managedResourceRefLabel(relationship.to)}</code>
                {relationship.path && <small>{relationship.path}</small>}
              </div>
            ))}
          </div>
        </div>
      )}

      {warnings.length > 0 && (
        <div className="panel wide4-panel managed-warning-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Partial discovery</p>
              <h2>Warnings</h2>
            </div>
            <AlertTriangle size={20} aria-hidden="true" />
          </div>
          <div className="timeline compact-timeline">
            {warnings.map((warning, index) => (
              <div className="timeline-item fail" key={`${warning.apiGroup}-${warning.resource}-${warning.code}-${index}`}>
                <strong>{warning.code}</strong>
                <span>{warning.message}</span>
                <small>{warning.apiGroup}/{warning.version} / {warning.resource}</small>
              </div>
            ))}
          </div>
        </div>
      )}

      {snapshot.observedAt && <p className="managed-observed-at">Last observed {new Date(snapshot.observedAt).toLocaleString()} · {snapshot.findings?.length ?? 0} normalized finding(s)</p>}
    </section>
  );
}

function ManagedResourceBoundary() {
  return (
    <div className="panel wide4-panel managed-boundary">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Kubernetes-managed external resources</p>
          <h2>Read-only discovery with source-of-truth remediation</h2>
        </div>
        <ShieldCheck size={21} aria-hidden="true" />
      </div>
      <p className="summary-text">KubeAthrix observes only explicitly allowlisted Kubernetes APIs. It does not receive cloud IAM credentials or mutate external provider APIs. AI can explain evidence and propose a typed change, but every managed-resource change remains human-reviewed and proposal-only.</p>
    </div>
  );
}

function ManagedResourceState({ eyebrow, title, message }: { eyebrow: string; title: string; message: string }) {
  return (
    <div className="panel wide4-panel managed-resource-state">
      <div className="panel-heading">
        <div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2></div>
        <Database size={20} aria-hidden="true" />
      </div>
      <p className="summary-text">{message}</p>
    </div>
  );
}

function managedBoolean(value: boolean | undefined) {
  if (value === undefined) return "Unknown";
  return value ? "Yes" : "No";
}

function managedResourceSourceOfTruth(resource: ManagedResource) {
  if (resource.provenance.sourceRef) return resource.provenance.sourceRef;
  if (resource.provenance.gitOps) return `Git-backed manifests reconciled by ${resource.provenance.controller || humanize(resource.provenance.system)}`;
  if (resource.provenance.system === "helm") return "Helm release values and chart";
  if (resource.provenance.system === "crossplane" || resource.provenance.system === "operator") return `${resource.kind}/${resource.name} spec reconciled by ${resource.provenance.controller || humanize(resource.provenance.system)}`;
  return `${resource.kind}/${resource.name} Kubernetes object (ownership unconfirmed)`;
}

function referenceMatchesResource(reference: ManagedResourceReference, resource: ManagedResource) {
  if (reference.uid && resource.uid) return reference.uid === resource.uid;
  return reference.name === resource.name && reference.namespace === resource.namespace && (!reference.kind || reference.kind === resource.kind);
}

function managedResourceRefLabel(reference: ManagedResourceReference) {
  const identity = `${reference.kind || reference.apiVersion || "Resource"}/${reference.name}`;
  return reference.namespace ? `${reference.namespace}/${identity}` : identity;
}

function ExperimentsView({
  experiments,
  run,
  message,
  onStart,
  onDecision
}: {
  experiments: ChaosExperiment[];
  run: ChaosExperimentRun | null;
  message: string;
  onStart: (experimentId: string, manifest: string) => void | Promise<void>;
  onDecision: (action: "approve" | "reject" | "execute" | "abort", reason: string) => void | Promise<void>;
}) {
  const [customManifest, setCustomManifest] = useState(
    "apiVersion: chaos-mesh.org/v1alpha1\nkind: NetworkChaos\nmetadata:\n  name: kubeathrix-custom\n  namespace: default\nspec:\n  action: delay\n  direction: to\n  mode: one\n  selector:\n    namespaces:\n      - default\n    labelSelectors:\n      app.kubernetes.io/name: example\n  delay:\n    latency: \"100ms\"\n  duration: \"60s\""
  );
  const [targetNamespace, setTargetNamespace] = useState("default");
  const [targetLabelKey, setTargetLabelKey] = useState("app.kubernetes.io/name");
  const [targetLabelValue, setTargetLabelValue] = useState("");
  const [decisionReason, setDecisionReason] = useState("");
  const availableExperiments = experiments.length > 0 ? experiments : [];
  const targetReady = targetNamespace.trim() !== "" && targetLabelKey.trim() !== "" && targetLabelValue.trim() !== "";
  const prepareManifest = (manifest: string) =>
    manifest
      .replaceAll("{{TARGET_NAMESPACE}}", targetNamespace.trim())
      .replaceAll("{{TARGET_LABEL_KEY}}", targetLabelKey.trim())
      .replaceAll("{{TARGET_LABEL_VALUE}}", targetLabelValue.trim());
  return (
    <section className="view-grid">
      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Verification</p>
            <h2>Bounded chaos experiments</h2>
          </div>
          <FlaskConical size={20} aria-hidden="true" />
        </div>
        <div className="target-grid">
          <label>
            <span>Namespace</span>
            <input value={targetNamespace} onChange={(event) => setTargetNamespace(event.target.value)} />
          </label>
          <label>
            <span>Label key</span>
            <input value={targetLabelKey} onChange={(event) => setTargetLabelKey(event.target.value)} />
          </label>
          <label>
            <span>Label value</span>
            <input value={targetLabelValue} onChange={(event) => setTargetLabelValue(event.target.value)} />
          </label>
        </div>
        <div className="experiment-grid">
          {availableExperiments.map((experiment) => (
            <div className="experiment-card" key={experiment.id}>
              <div className="panel-heading compact-heading">
                <div>
                  <p className="eyebrow">{experiment.engine} / {experiment.category}</p>
                  <h2>{experiment.name}</h2>
                </div>
                <span className="status-pill signal">{experiment.status}</span>
              </div>
              <p className="summary-text">{experiment.description}</p>
              <div className="preflight-list">
                {experiment.preflight.map((step) => (
                  <span key={step}>
                    <CheckCircle2 size={15} aria-hidden="true" />
                    {step}
                  </span>
                ))}
              </div>
              <div className="button-row">
                <button className="primary-button" type="button" disabled={!targetReady} onClick={() => void onStart(experiment.id, prepareManifest(experiment.manifest))}>
                  <PlayCircle size={18} aria-hidden="true" />
                  Request bounded run
                </button>
                <code>{experiment.target}</code>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Custom experiment</p>
            <h2>YAML manifest</h2>
          </div>
          <span className="status-pill muted">engine-scoped</span>
        </div>
        <textarea className="manifest-editor" value={customManifest} onChange={(event) => setCustomManifest(event.target.value)} spellCheck={false} />
        <div className="button-row">
          <label className="secondary-button file-button">
            <input
              type="file"
              accept=".yaml,.yml,text/yaml,text/plain"
              onChange={(event) => {
                const file = event.currentTarget.files?.[0];
                if (file) {
                  void file.text().then(setCustomManifest);
                }
              }}
            />
            <FileClock size={18} aria-hidden="true" />
            Load YAML
          </label>
          <button className="primary-button" type="button" onClick={() => void onStart("custom", customManifest)}>
            <PlayCircle size={18} aria-hidden="true" />
            Request custom run
          </button>
        </div>
      </div>

      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Run state</p>
            <h2>Persistent experiment run</h2>
          </div>
          <span className="status-pill muted">{run && run.status !== "preflight_validated" ? "persistent lifecycle" : "preflight by default"}</span>
        </div>
        {run ? (
          <div>
            <div className="timeline">
              <div className={run.status === "failed" ? "timeline-item danger" : "timeline-item pass"}>
                <strong>{humanize(run.status)}</strong>
                <span>{run.message}</span>
                <small>{run.id} · {run.resource?.namespace}/{run.resource?.name} · {run.durationSeconds}s · target count {run.targetCount}</small>
                {run.injectionDeadline && run.status === "execution_requested" && <small>Injection proof deadline: {new Date(run.injectionDeadline).toLocaleString()}</small>}
                {run.failureReason && <small>Failure: {run.failureReason}</small>}
                {run.recoveryMessage && <small>Recovery: {run.recoveryMessage}</small>}
              </div>
            </div>
            {message && <p className="summary-text">{message}</p>}
            {["pending_approval", "approved", "execution_requested", "running", "cleanup_requested", "verifying_recovery"].includes(run.status) && (
              <label>
                <span>Decision or abort reason</span>
                <input value={decisionReason} onChange={(event) => setDecisionReason(event.target.value)} placeholder="Required for approval, rejection, or abort" />
              </label>
            )}
            <div className="button-row">
              {run.status === "pending_approval" && <>
                <button className="primary-button" type="button" disabled={!decisionReason.trim()} onClick={() => void onDecision("approve", decisionReason)}>Approve</button>
                <button className="secondary-button" type="button" disabled={!decisionReason.trim()} onClick={() => void onDecision("reject", decisionReason)}>Reject</button>
              </>}
              {run.status === "approved" && <button className="primary-button" type="button" onClick={() => void onDecision("execute", "")}>Execute approved run</button>}
              {["approved", "execution_requested", "running", "cleanup_requested", "verifying_recovery"].includes(run.status) && (
                <button className="secondary-button" type="button" disabled={run.status !== "approved" && !decisionReason.trim()} onClick={() => void onDecision("abort", decisionReason || "cancelled before execution")}>Abort and clean up</button>
              )}
            </div>
          </div>
        ) : (
          <p className="summary-text">Request a predefined or custom manifest. Execution-enabled installations persist a separate approval, execution, cleanup, and recovery lifecycle; default installations stop after preflight.</p>
        )}
      </div>
    </section>
  );
}

function AuditView({ events }: { events: AuditEvent[] }) {
  return (
    <section className="view-grid">
      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Audit trail</p>
            <h2>Every decision stays visible</h2>
          </div>
          <Database size={20} aria-hidden="true" />
        </div>
        <div className="timeline">
          {events.map((event) => (
            <div className="timeline-item" key={event.id}>
              <strong>{humanize(event.action)}</strong>
              <span>{event.message || event.subject}</span>
              <small>{event.actor} - {new Date(event.createdAt).toLocaleString()}</small>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function IntegrationsView({ integrations, health }: { integrations: Integration[]; health: Record<string, IntegrationHealth> }) {
  return (
    <section className="integration-grid">
      {integrations.map((integration) => {
        const details = health[integration.name];
        return (
          <div className="panel integration-panel" key={integration.name}>
            <div className="panel-heading">
              <div>
                <p className="eyebrow">{integration.type}</p>
                <h2>{integration.name}</h2>
              </div>
              <span className={integration.enabled ? "status-dot online" : "status-dot"} />
            </div>
            <p className="summary-text">{integration.enabled ? "A supported Kubernetes report API was discovered and queried." : "No supported report API was discovered; configuration flags alone do not count as healthy."}</p>
            <div className="fact-grid dense">
              <Fact label="Health" value={details?.health ?? integration.status} />
              <Fact label="Data last seen" value={details?.dataLastSeen ?? "unknown"} />
              <Fact label="Normalized findings" value={details?.findingsCount ?? 0} />
            </div>
            <div className="preflight-list">
              {(details?.permissions ?? []).slice(0, 3).map((permission) => (
                <span key={permission}>
                  <CheckCircle2 size={15} aria-hidden="true" />
                  {permission}
                </span>
              ))}
              {(details?.setupGaps ?? []).slice(0, 2).map((gap) => (
                <span key={gap}>
                  <AlertTriangle size={15} aria-hidden="true" />
                  {gap}
                </span>
              ))}
              {(details?.supportedVersions ?? []).map((version) => (
                <span key={version}>
                  <Database size={15} aria-hidden="true" />
                  {version}
                </span>
              ))}
            </div>
            {details?.errorState && <p className="summary-text">{details.errorState}</p>}
            <span className="status-pill muted">{integration.status}</span>
          </div>
        );
      })}
    </section>
  );
}

function SettingsView({ providers }: { providers: ModelProviderSettings | null }) {
  return (
    <section className="view-grid">
      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
			<p className="eyebrow">Optional AI assist</p>
			<h2>Provider references and gateway</h2>
          </div>
          <KeyRound size={20} aria-hidden="true" />
        </div>
        <div className="action-list">
          {(providers?.providers ?? []).map((provider) => (
            <div className="action-row" key={provider.name}>
              <Bot size={18} aria-hidden="true" />
              <div>
                <strong>{provider.name}</strong>
                <span>{provider.type} / {provider.model}</span>
              </div>
              <code>{provider.apiKeySecretRef ? `${provider.apiKeySecretRef.name}:${provider.apiKeySecretRef.key}` : provider.externalSecretRef?.path}</code>
            </div>
          ))}
        </div>
		<p className="summary-text">When enabled by the API server, AI decision support explains findings and typed plans using structured output. It cannot add executable actions or bypass dry-run, approval, verification, or rollback controls.</p>
      </div>
    </section>
  );
}

function Metric({ label, value, tone, icon: Icon }: { label: string; value: number; tone: string; icon: typeof ShieldCheck }) {
  return (
    <div className={`metric-card ${tone}`}>
      <Icon size={20} aria-hidden="true" />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge ${severity}`}>{severity}</span>;
}

function Fact({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="fact">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function remediationBadge(plan: RemediationPlan) {
  if (plan.status === "execution_requested") {
    return { label: "Execution requested", tone: "signal" };
  }
  if (plan.status === "proposal_only") {
    return { label: "Proposal only", tone: "signal" };
  }
  if (plan.status === "dry_run_passed") {
    return { label: "Dry-run passed", tone: "signal" };
  }
  if (plan.status === "succeeded") {
    return { label: "Verified", tone: "signal" };
  }
  if (plan.status === "failed") {
    return { label: "Failed", tone: "danger" };
  }
  if (plan.status === "approved" || plan.approvalPolicy.decision === "approved") {
    return { label: "Approved; not executed", tone: "signal" };
  }
  if (plan.status === "rejected") {
    return { label: "Rejected", tone: "danger" };
  }
  if (plan.status === "running") {
    return { label: "Running", tone: "signal" };
  }
  if (plan.approvalPolicy.required) {
    return { label: "Approval required", tone: "warning" };
  }
  return { label: "Deterministic", tone: "signal" };
}

function humanize(value: string) {
  return value.replaceAll("_", " ");
}

function safeFilename(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 96) || "bundle";
}

export default App;
