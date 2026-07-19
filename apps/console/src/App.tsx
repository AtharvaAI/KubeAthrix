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
  PauseCircle,
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
	storeModelProviderSecret,
	updateModelProviders,
	updateFindingStatus,
  APIError
} from "./api";
import { beginLogin, clearAuthentication, initializeAuth } from "./auth";
import type { AuthState } from "./auth";
import type { AuditEvent, ChaosExperiment, ChaosExperimentRun, ClusterInventory, Dashboard, EvidenceBundle, Finding, FindingException, Integration, IntegrationHealth, ManagedResource, ManagedResourceReference, ManagedResourceSnapshot, ModelProvider, ModelProviderSettings, RemediationDiff, RemediationPlan, RemediationRun, ScanSummary, Severity } from "./types";

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
	const [providerBusy, setProviderBusy] = useState(false);
	const [providerMessage, setProviderMessage] = useState("");
	const [feedLive, setFeedLive] = useState(true);
	const [planConfirmation, setPlanConfirmation] = useState<Finding | null>(null);
	const [planBusy, setPlanBusy] = useState(false);
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

	useEffect(() => {
		if (!feedLive || activeView !== "dashboard" || authState?.status !== "authenticated") return;
		const refreshLiveFeed = () => {
			void Promise.all([loadDashboard(), loadFindings(), loadAuditEvents()]).then(([dashboardData, findingData, auditData]) => {
				setDashboard(dashboardData);
				setFindings(findingData);
				setAuditEvents(auditData);
			}).catch(() => undefined);
		};
		const timer = window.setInterval(refreshLiveFeed, 10_000);
		return () => window.clearInterval(timer);
	}, [activeView, authState?.status, feedLive]);

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
	setPlanBusy(true);
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
	} finally {
		setPlanBusy(false);
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

	async function handleSaveProviders(settings: ModelProviderSettings): Promise<ModelProviderSettings> {
		setProviderBusy(true);
		try {
			const updated = await updateModelProviders(settings);
			setModelProviders(updated);
			setProviderMessage("Provider references saved. No raw key was stored in the provider configuration.");
			return updated;
		} catch (error) {
			setProviderMessage(error instanceof Error ? error.message : "Unable to save provider settings.");
			throw error;
		} finally {
			setProviderBusy(false);
		}
	}

	async function handleStoreProviderSecret(settings: ModelProviderSettings, providerIndex: number, value: string): Promise<ModelProviderSettings> {
		const provider = settings.providers[providerIndex];
		if (!provider?.apiKeySecretRef) throw new Error("A Kubernetes Secret name and key are required.");
		setProviderBusy(true);
		try {
			const stored = await storeModelProviderSecret(provider.name, provider.apiKeySecretRef.name, provider.apiKeySecretRef.key, value);
			const nextSettings: ModelProviderSettings = {
				providers: settings.providers.map((item, index) => index === providerIndex
					? { ...item, apiKeySecretRef: stored.secretRef, externalSecretRef: undefined }
					: item)
			};
			const updated = await updateModelProviders(nextSettings);
			setModelProviders(updated);
			setAuditEvents(await loadAuditEvents());
			setProviderMessage(`Secret ${stored.namespace}/${stored.secretRef.name}:${stored.secretRef.key} was created or rotated and its reference was saved.`);
			return updated;
		} catch (error) {
			setProviderMessage(error instanceof Error ? error.message : "Unable to store the provider secret.");
			throw error;
		} finally {
			setProviderBusy(false);
		}
	}

  const currentView = viewItems.find((item) => item.id === activeView) ?? viewItems[0];
  const openFindings = findings.filter((finding) => finding.status === "open" || finding.status === "in_review");
  const priorityFinding = [...openFindings].sort((a, b) => b.riskScore - a.riskScore)[0];
  const pageTitle = activeView === "dashboard" ? "Defender dashboard" : currentView.label;
	const agent = dashboard?.agent;

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
            <strong>KubeAthrix Defender</strong>
            <span className="sr-only">KubeAthrix</span>
            <span>In-cluster agent · v1.7.2</span>
          </div>
        </div>
        <div className="agent-status-card" aria-label="Cluster status summary">
          <div className="agent-health">
            <span className="health-dot" aria-hidden="true" />
            <strong>Agent healthy</strong>
            <code>{agent?.runtimeIdentity ?? "api/default"}</code>
          </div>
          <div className="sidebar-status">
            <div>
              <span>Mode</span>
              <strong>{formatAgentMode(agent?.autonomyMode ?? "recommend")}</strong>
            </div>
            <div>
              <span>Uptime</span>
              <strong>{formatUptime(agent?.uptimeSeconds ?? 0)}</strong>
            </div>
            <div>
              <span>Acts 24h</span>
              <strong>{agent?.actionsLast24h ?? 0}</strong>
            </div>
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
		  <span>The agent explains and plans; controllers execute only versioned typed actions with dry-run, approval, verification, and rollback.</span>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="page-title">
            <p className="page-context">In-cluster defender · {agent?.runtimeIdentity ?? "cluster scope"}</p>
            <h1>{pageTitle}</h1>
          </div>
          <div className="topbar-actions">
            <span className="status-pill">
              <span className="health-dot" aria-hidden="true" />
              Watching {dashboard?.cluster?.namespaces ?? 0} namespaces
            </span>
            <span className="status-pill muted">
              {dashboard?.bundledEnginesOnline ?? 0} engines online
            </span>
            <span className="status-pill muted mono-pill">{agent?.runtimeIdentity ?? "controller/gated-write"}</span>
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
            <span className="sr-only">Open critical</span>
            <strong>{dashboard?.openCritical ?? 0}</strong>
            <small>{priorityFinding ? `Top risk score ${priorityFinding.riskScore} · ${priorityFinding.source}` : "No active critical queue"}</small>
          </div>
          <div className="command-card warning">
            <span>Pending approvals</span>
            <strong>{dashboard?.pendingApprovals ?? 0}</strong>
            <small>Human gates separate from execution</small>
          </div>
          <div className="command-card neutral">
            <span>Coverage</span>
            <strong>{dashboard?.scan?.resourcesScanned ?? 0}</strong>
            <small>Objects scanned · evidence {dashboard?.evidenceFreshness ?? "unknown"}</small>
          </div>
          <div className="command-card signal">
            <span>Mean risk</span>
            <strong>{Math.round(dashboard?.meanRiskScore ?? 0)}</strong>
            <small>{dashboard?.riskReduced ?? 0} risk reduced · {dashboard?.verifiedRemediations ?? 0} fixes proven</small>
          </div>
        </section>

        {loadError && <ErrorPanel message={loadError} onRetry={() => void refreshData()} />}
        {!loadError && loading && <LoadingPanel />}
        {!loadError && !loading && activeView === "dashboard" && dashboard && (
          <DashboardView dashboard={dashboard} findings={findings} auditEvents={auditEvents} feedLive={feedLive} onToggleFeed={() => setFeedLive((current) => !current)} onPlanFinding={(finding) => setPlanConfirmation(finding)} />
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
        {!loadError && !loading && activeView === "managed-resources" && <ManagedResourcesTemplateView snapshot={managedResources} access={managedResourceAccess} message={managedResourceMessage} />}
        {!loadError && !loading && activeView === "experiments" && <ExperimentsTemplateView experiments={experiments} run={experimentRun} message={experimentMessage} onStart={handleStartExperiment} onDecision={handleChaosDecision} />}
        {!loadError && !loading && activeView === "audit" && <AuditView events={auditEvents} />}
        {!loadError && !loading && activeView === "integrations" && <IntegrationsView integrations={integrations} health={integrationHealth} />}
        {!loadError && !loading && activeView === "settings" && <SettingsTemplateView providers={modelProviders} busy={providerBusy} message={providerMessage} onSave={handleSaveProviders} onStoreSecret={handleStoreProviderSecret} />}

		{planConfirmation && (
			<div className="modal-backdrop" role="presentation" onMouseDown={(event) => {
				if (event.target === event.currentTarget && !planBusy) setPlanConfirmation(null);
			}}>
				<section className="confirmation-dialog" role="dialog" aria-modal="true" aria-labelledby="plan-confirmation-title">
					<div className="panel-heading">
						<div><p className="eyebrow">Explicit operator action</p><h2 id="plan-confirmation-title">Generate a remediation plan?</h2></div>
						<ShieldCheck size={20} aria-hidden="true" />
					</div>
					<p className="summary-text"><strong>{planConfirmation.title}</strong></p>
					<p className="summary-text">This creates a typed plan and diff only. It does not approve or execute any cluster change.</p>
					<div className="dialog-actions">
						<button className="secondary-button" type="button" disabled={planBusy} onClick={() => setPlanConfirmation(null)}>Cancel</button>
						<button className="primary-button" type="button" disabled={planBusy} onClick={() => {
							const findingId = planConfirmation.id;
							setPlanConfirmation(null);
							void handleCreatePlan(findingId);
						}}><GitPullRequest size={17} aria-hidden="true" />{planBusy ? "Generating…" : "Generate plan"}</button>
					</div>
				</section>
			</div>
		)}
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

function DashboardView({ dashboard, findings, auditEvents, feedLive, onToggleFeed, onPlanFinding }: { dashboard: Dashboard; findings: Finding[]; auditEvents: AuditEvent[]; feedLive: boolean; onToggleFeed: () => void; onPlanFinding: (finding: Finding) => void }) {
  const topFindings = [...findings]
    .filter((finding) => finding.status === "open" || finding.status === "in_review")
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 5);
  const cluster = dashboard.cluster ?? emptyCluster;
  const scan = dashboard.scan ?? emptyScan;
  const compliance = dashboard.compliance ?? [];
  const severityDenominator = Math.max(dashboard.totalFindings, 1);
  const auditFeed = auditEvents.slice(0, 7).map((event) => ({
    id: event.id,
    stage: auditStage(event.action),
    message: event.action,
    subject: event.subject || event.message,
    source: event.actor,
    time: event.createdAt
  }));
  const findingFeed = findings.slice(0, 7).map((finding) => ({
    id: finding.id,
    stage: "DETECT",
    message: finding.title,
    subject: findingResourceLabel(finding),
    source: finding.source,
    time: finding.updatedAt
  }));
  const feed = auditFeed.length > 0 ? auditFeed : findingFeed;
  const pipeline = [
    { label: "Detect", value: dashboard.totalFindings, tone: "neutral" },
    { label: "Plan", value: dashboard.findingsWithSafeFix ?? 0, tone: "plan" },
    { label: "Approve", value: dashboard.pendingApprovals, tone: "approve" },
    { label: "Execute", value: dashboard.activeRemediations, tone: "execute" },
    { label: "Verify", value: dashboard.verifiedRemediations ?? 0, tone: "verify" }
  ];

  return (
    <section className="dashboard-layout">
      <span className="sr-only">Correlated cluster risk</span>
      <div className="dashboard-column dashboard-primary">
        <article className="panel ops-panel">
          <div className="panel-heading">
            <div>
              <h2>Agent ops feed</h2>
              <p>Detections, plans, approvals, executions, verifications</p>
            </div>
            <button className={`status-pill signal live-toggle ${feedLive ? "" : "paused"}`} type="button" onClick={onToggleFeed} aria-pressed={!feedLive}>
              {feedLive ? <PauseCircle size={14} aria-hidden="true" /> : <PlayCircle size={14} aria-hidden="true" />}
              {feedLive ? "Live · pause" : "Paused · resume"}
            </button>
          </div>
          <div className="ops-feed">
            {feed.map((event) => (
              <div className={`ops-row event-${event.stage.toLowerCase()}`} key={event.id}>
                <span className="event-chip">{event.stage}</span>
                <div>
                  <strong>{event.message}</strong>
                  <code>{event.subject}</code>
                </div>
                <div className="event-meta">
                  <span>{formatEventTime(event.time)}</span>
                  <small>{event.source}</small>
                </div>
              </div>
            ))}
            {feed.length === 0 && <p className="summary-text">Operations will appear when the first finding or audited action is observed.</p>}
          </div>
        </article>

        <article className="panel triage-panel">
          <div className="panel-heading">
            <div>
              <h2>Triage queue</h2>
              <p>Highest-risk open findings</p>
            </div>
            <span className="status-pill muted">{topFindings.length} shown</span>
          </div>
          <div className="triage-list">
            {topFindings.map((finding) => (
              <div className="triage-row" key={finding.id}>
                <SeverityBadge severity={finding.severity} />
                <div>
                  <strong>{finding.title}</strong>
                  <code>{findingResourceLabel(finding)} · {humanize(finding.fixability)}</code>
                </div>
                <span className="risk-score">{finding.riskScore}</span>
                <button className="secondary-button compact-button" type="button" onClick={() => onPlanFinding(finding)}>Plan fix</button>
              </div>
            ))}
            {topFindings.length === 0 && <p className="summary-text">No open findings returned by the cluster scanner.</p>}
          </div>
        </article>
      </div>

      <div className="dashboard-column dashboard-secondary">
        <article className="panel posture-panel">
          <div className="panel-heading">
            <div><h2>Cluster posture</h2><p>Live inventory</p></div>
          </div>
          <div className="inventory-grid">
            <Fact label="Nodes" value={`${cluster.readyNodes ?? 0}/${cluster.nodes ?? 0} ready`} />
            <Fact label="Pods" value={`${cluster.runningPods ?? 0}/${cluster.pods ?? 0}`} />
            <Fact label="Namespaces" value={cluster.namespaces ?? 0} />
            <Fact label="Deployments" value={cluster.deployments ?? 0} />
            <Fact label="DaemonSets" value={cluster.daemonSets ?? 0} />
            <Fact label="StatefulSets" value={cluster.statefulSets ?? 0} />
            <Fact label="Services" value={cluster.services ?? 0} />
            <Fact label="NetPolicies" value={cluster.networkPolicies ?? 0} />
            <Fact label="RBAC roles" value={cluster.roles ?? 0} />
          </div>
        </article>

        <article className="panel pipeline-panel">
          <div className="panel-heading">
            <div><h2>Remediation pipeline</h2><p>Plan → approve → execute → verify</p></div>
          </div>
          <div className="pipeline-strip">
            {pipeline.map((item) => (
              <div className={`pipeline-step ${item.tone}`} key={item.label}>
                <strong>{item.value}</strong>
                <span>{item.label}</span>
              </div>
            ))}
          </div>
          <p className="panel-note">{dashboard.activeRemediations > 0 ? `${dashboard.activeRemediations} controller-owned run(s) are active.` : "No controller-owned run is active."} Rollback metadata is captured before mutable actions.</p>
        </article>

        <article className="panel severity-panel">
          <div className="panel-heading">
            <div><h2>Severity distribution</h2><p>{dashboard.totalFindings} open findings</p></div>
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
        </article>

        <article className="panel compliance-panel">
          <div className="panel-heading">
            <div><h2>Compliance</h2><p>{scan.passedControls ?? 0}/{scan.complianceControls ?? 0} controls passing</p></div>
          </div>
          <div className="control-summary-list">
            {compliance.slice(0, 4).map((control) => (
              <div className={`control-summary ${control.status === "pass" ? "pass" : "fail"}`} key={control.id}>
                <span>{control.status === "pass" ? "PASS" : "FAIL"}</span>
                <div><strong>{control.title}</strong><code>{control.id}</code></div>
              </div>
            ))}
            {compliance.length === 0 && <p className="summary-text">Live compliance controls will appear after the API can read the cluster.</p>}
          </div>
        </article>
      </div>
    </section>
  );
}

function LegacyDashboardView({ dashboard, findings, onOpenFinding }: { dashboard: Dashboard; findings: Finding[]; onOpenFinding: (id: string) => void }) {
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
        <Fact label="Risk score" value={finding.riskScore} />
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
		{finding.riskExplanation && (
		  <div className="timeline-item risk-evidence">
			<strong>Risk model {finding.riskExplanation.version}: {finding.riskExplanation.baseScore} → {finding.riskExplanation.finalScore}</strong>
			<span>{finding.riskExplanation.factors.map((factor) => `+${factor.points} ${factor.reason}`).join(" · ")}</span>
			<small>Deterministic score explanation</small>
		  </div>
		)}
      </div>
      <h3>Affected resources</h3>
      <div className="resource-list">
        {finding.resources.map((resource) => (
          <code key={`${resource.kind}-${resource.namespace}-${resource.name}`}>
            {resource.kind}/{resource.namespace ? `${resource.namespace}/` : ""}
            {resource.name}
          </code>
        ))}
      </div>
	  {exceptions.length > 0 && <div className="matching-exceptions" aria-label="Matching exceptions">
		{exceptions.map((item) => <div className="exception-row" key={item.id}>
		  <div><strong>{humanize(item.status)} until {new Date(item.expiresAt).toLocaleString()}</strong><span>{item.reason}</span></div>
		  <button className="secondary-button compact-button" type="button" onClick={() => void onDeleteException(item.id)}>Remove</button>
		</div>)}
	  </div>}
	  <div className="finding-action-row">
		<label className="audit-reason-field"><span className="sr-only">Audit reason</span><input value={reason} maxLength={2048} onChange={(event) => setReason(event.target.value)} placeholder="Audit reason (required)" /></label>
		<label className="exception-expiry-field" title="Time-bounded exception expiration"><span className="sr-only">Exception expires</span><input aria-label="Exception expires" type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label>
		<button className="secondary-button" disabled={!reason.trim()} type="button" onClick={() => void onStatus(finding.id, finding.status === "in_review" ? "open" : "in_review", reason.trim())}>{finding.status === "in_review" ? "Reopen" : "Mark in review"}</button>
		<button className="secondary-button" disabled={!reason.trim() || !expiresAt || finding.status === "suppressed"} type="button" onClick={() => void onSuppress(finding.id, reason.trim(), new Date(expiresAt).toISOString())}>Create exception</button>
		<button className="primary-button" type="button" onClick={onCreatePlan}><Sparkles size={18} aria-hidden="true" />Generate typed plan</button>
	  </div>
	  {message && <p className="workflow-message" aria-live="polite">{message}</p>}
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
    <section className="template-stack fix-center-layout">
      <article className="panel workflow-panel">
        <div className="panel-heading">
          <div><h2>Workflow</h2><p>Find, explain, fix, verify, prove</p></div>
        </div>
        <div className="control-loop">
          {["Normalize", "Plan", "Approve", "Execute", "Dry-run", "Verify"].map((step, index) => (
            <div className="loop-step" key={step}><span>{index + 1}</span><strong>{step}</strong></div>
          ))}
        </div>
        <p className="panel-note">{workflowMessage}</p>
      </article>

      <section className="fix-center-body">
        <article className="panel plan-panel">
          {plan ? <>
            <div className="panel-heading">
              <div><h2>Plan {plan.id} · risk tier {plan.riskTier}</h2><p>{plan.rootCause}</p></div>
              <span className={`status-pill ${planBadge?.tone ?? "muted"}`}>{planBadge?.label}</span>
            </div>
            <div className="plan-facts">
              <Fact label="Dry-run" value={plan.dryRunResult.passed ? "passed" : "pending"} />
              <Fact label="Catalog" value={plan.catalogVersion || "unknown"} />
              <Fact label="Approval" value={!plan.approvalPolicy.required ? "not required" : plan.approvalPolicy.decision ?? "pending"} />
              <Fact label="Actions" value={plan.actions.length} />
            </div>
            <div className="plan-action-list">
              {plan.actions.map((action) => (
                <div className="plan-action-row" key={`${action.type}-${action.target.name}`}>
                  <div><strong>{humanize(action.type)}</strong><span>{action.description}</span></div>
                  <code>{action.target.kind}/{action.target.name}</code>
                </div>
              ))}
            </div>
            {plan.ai && <div className="plan-ai-note">
              <Sparkles size={16} aria-hidden="true" />
              <div><strong>AI decision support · {plan.ai.provider}/{plan.ai.model} · confidence {plan.ai.confidence}</strong><span>{plan.ai.summary} {plan.ai.autonomousPolicy}</span></div>
            </div>}
            <div className="plan-checks">
              <div><h3>Verification</h3><ul>{plan.verificationSteps.map((step) => <li key={step}>{step}</li>)}</ul></div>
              <div><h3>Rollback</h3><ul>{plan.rollbackSteps.map((step) => <li key={step}>{step}</li>)}</ul></div>
            </div>
            <div className="plan-decision-row">
              <label><span className="sr-only">Decision reason</span><input aria-label="Approval decision reason" value={decisionReason} maxLength={2048} placeholder="Decision reason (required)" onChange={(event) => setDecisionReason(event.target.value)} /></label>
              <button className="primary-button" type="button" disabled={approvalBusy || decisionLocked || !decisionReason.trim()} onClick={() => void onApproval("approved", decisionReason.trim())}>{approvalBusy ? "Working" : "Approve"}</button>
              <button className="primary-button" type="button" disabled={approvalBusy || executeLocked} onClick={() => void onExecute()}>Execute</button>
              <button className="secondary-button" type="button" disabled={approvalBusy || decisionLocked || !decisionReason.trim()} onClick={() => void onApproval("rejected", decisionReason.trim())}>Reject</button>
              <button className="secondary-button" type="button" onClick={() => void onEvidenceBundle()}>Build evidence bundle</button>
              {evidenceBundle && <button className="secondary-button" type="button" onClick={onExportEvidenceBundle}>Export JSON</button>}
            </div>
          </> : <>
            <div className="panel-heading"><div><h2>Current target</h2><p>{finding?.title ?? "No finding selected"}</p></div><span className="status-pill muted">No plan</span></div>
            <p className="summary-text">Select a finding and create a typed plan to populate the deterministic workflow.</p>
            {finding && <button className="primary-button" type="button" onClick={() => onCreatePlan(finding.id)}><GitPullRequest size={18} aria-hidden="true" />Create plan</button>}
          </>}
        </article>

        <div className="fix-side-stack">
          <article className="panel typed-diff-panel">
            <div className="panel-heading"><div><h2>Typed diff</h2><p>{diff ? `${humanize(diff.mode)} · deterministic` : "Waiting for a generated plan"}</p></div></div>
            {diff ? <>
              <p className="summary-text">{diff.summary}</p>
              {diff.manifests.map((manifest) => <div className="typed-diff-entry" key={`${manifest.actionType}-${manifest.target.kind}-${manifest.target.name}`}>
                <div><strong>{humanize(manifest.actionType)}</strong><code>{manifest.writeMode}</code></div>
                <pre>{manifest.diff}</pre>
                <p>Required: {(manifest.requiredPermissions ?? []).join(", ") || "none reported"}. Failure: {manifest.failureHandling || "abort without partial apply"}.</p>
              </div>)}
            </> : <p className="summary-text">The server-side typed manifest diff will appear here before any approval or execution.</p>}
          </article>

          <article className="panel run-status-panel">
            <div className="panel-heading"><div><h2>{run ? `Run ${run.id} · ${humanize(run.state)}` : "Run status"}</h2><p>Controller-owned · live CRD status</p></div></div>
            {run ? <>
              <div className="run-status-list">
                {(run.actionStatuses ?? []).map((status) => <div className="run-status-row" key={`${status.actionType}-${status.state}`}><strong>{humanize(status.state)}</strong><span>{status.message}</span></div>)}
              </div>
              <p className="panel-note">{run.validationResult} · rollback snapshot {run.rollbackMetadata || "not captured"}</p>
              <button className="secondary-button" type="button" disabled={approvalBusy || !["succeeded", "failed", "verifying"].includes(run.state)} onClick={() => void onRollback()}><RotateCcw size={18} aria-hidden="true" />Request rollback</button>
            </> : <p className="summary-text">No controller-owned remediation run has been requested.</p>}
            {evidenceBundle && <div className="evidence-summary"><strong>Proof bundle ready</strong><span>{evidenceBundle.summary.findings ?? 0} findings · {evidenceBundle.summary.plans ?? 0} plans · {evidenceBundle.summary.runs ?? 0} runs · {evidenceBundle.summary.auditEvents ?? 0} audit events</span></div>}
          </article>
        </div>
      </section>
    </section>
  );
}

function RuntimeView({ findings }: { findings: Finding[] }) {
  const sensors = new Set(findings.map((finding) => finding.source)).size;
  return (
    <section className="template-stack">
      <article className="panel runtime-stream-panel">
        <div className="panel-heading">
          <div><h2>Runtime signal stream</h2><p>Falco and Tetragon adapters · notify-first</p></div>
          <span className="status-pill muted">{sensors} sensor{sensors === 1 ? "" : "s"} healthy</span>
        </div>
        <div className="runtime-event-list">
          {findings.map((finding) => (
            <div className={`runtime-event-row ${finding.severity}`} key={finding.id}>
              <span className="runtime-source-chip">{finding.source}</span>
              <div>
                <strong>{finding.title}</strong>
                <code>{findingResourceLabel(finding)}</code>
              </div>
              <time>{formatEventTime(finding.updatedAt)}</time>
            </div>
          ))}
          {findings.length === 0 && <p className="summary-text">No runtime findings are currently reported.</p>}
        </div>
      </article>
    </section>
  );
}

function PolicyView({ findings, dashboard }: { findings: Finding[]; dashboard: Dashboard }) {
  const policyFindings = findings.filter((finding) => ["kyverno", "kubescape", "correlator", "kubeathrix-scan"].includes(finding.source));
  const cluster = dashboard.cluster ?? emptyCluster;
  const compliance = dashboard.compliance ?? [];
  return (
    <section className="template-stack policy-layout">
      <article className="panel control-posture-panel">
        <div className="panel-heading">
          <div><h2>Control posture</h2><p>CIS, NSA, SOC 2 · {dashboard.scan?.passedControls ?? 0}/{dashboard.scan?.complianceControls ?? 0} passing</p></div>
        </div>
        <div className="control-grid">
          {compliance.map((control) => (
            <div className={`control-card ${control.status === "pass" ? "pass" : "fail"}`} key={control.id}>
              <span>{control.framework}</span>
              <strong>{control.id} · {humanize(control.status)}</strong>
              <p>{control.title}</p>
              <small>{control.evidence}</small>
            </div>
          ))}
        </div>
      </article>

      <section className="policy-body">
        <article className="panel">
          <div className="panel-heading"><div><h2>Guardrail coverage</h2><p>Policy and permission objects</p></div></div>
          <div className="guardrail-facts">
            {[
              ["NetworkPolicies", cluster.networkPolicies], ["ResourceQuotas", cluster.resourceQuotas],
              ["LimitRanges", cluster.limitRanges], ["PodDisruptionBudgets", cluster.podDisruptionBudgets],
              ["Roles", cluster.roles], ["RoleBindings", cluster.roleBindings],
              ["ClusterRoles", cluster.clusterRoles], ["ClusterRoleBindings", cluster.clusterRoleBindings]
            ].map(([label, value]) => <div className="inline-fact" key={label}><span>{label}</span><strong>{value}</strong></div>)}
          </div>
        </article>
        <article className="panel">
          <div className="panel-heading"><div><h2>Policy findings</h2><p>Kyverno, Kubescape, correlator</p></div></div>
          <div className="finding-list compact">
            {policyFindings.map((finding) => <div className="static-row" key={finding.id}><SeverityBadge severity={finding.severity} /><span>{finding.title}</span><code>{humanize(finding.fixability)}</code></div>)}
            {policyFindings.length === 0 && <p className="summary-text">No policy findings are currently reported.</p>}
          </div>
        </article>
      </section>
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

function ManagedResourcesTemplateView({ snapshot, access, message }: { snapshot: ManagedResourceSnapshot | null; access: ManagedResourceAccess; message: string }) {
  const resources = snapshot?.resources ?? [];
  const relationships = snapshot?.relationships ?? [];
  const warnings = snapshot?.warnings ?? [];
  let state: { eyebrow: string; title: string; message: string } | null = null;
  if (access === "forbidden") state = { eyebrow: "Access boundary", title: "Managed-resource inventory is not available to this identity", message: "Your Kubernetes scope does not permit this cluster-wide inventory. Native findings and other authorized console data remain available." };
  else if (access === "unavailable" || !snapshot) state = { eyebrow: "Discovery status", title: "Managed-resource discovery is unavailable", message: message || "The optional discovery endpoint is not configured or could not be reached." };
  else if (!snapshot.enabled) state = { eyebrow: "Discovery status", title: "Managed-resource discovery is disabled", message: "Enable the allowlisted managed-external-resource adapter and its read-only RBAC rules to inventory Kubernetes-managed resources." };
  else if (resources.length === 0) state = { eyebrow: "Allowlisted discovery", title: "No managed resources were returned", message: "Discovery is enabled, but no objects matched the configured allowlist and current Kubernetes authorization scope." };

  return (
    <section className="template-stack managed-resource-layout">
      <article className="panel managed-boundary">
        <strong>Read-only discovery with source-of-truth remediation</strong>
        <span>Only allowlisted Kubernetes APIs are observed — no cloud IAM credentials, no external provider mutation. Every managed-resource change is human-reviewed and proposal-only.</span>
        {snapshot && <small>{resources.length} objects · {relationships.length} ownership links · {snapshot.findings?.length ?? 0} normalized findings{snapshot.observedAt ? ` · observed ${new Date(snapshot.observedAt).toLocaleString()}` : ""}</small>}
        {warnings.length > 0 && <details className="managed-warning-details"><summary>{warnings.length} discovery warning{warnings.length === 1 ? "" : "s"}</summary>{warnings.map((warning, index) => <p key={`${warning.code}-${index}`}><strong>{warning.code}</strong> · {warning.message}</p>)}</details>}
      </article>
      <section className="managed-card-grid">
        {state && <ManagedResourceState {...state} />}
        {!state && resources.map((resource) => {
          const related = relationships.filter((relationship) => referenceMatchesResource(relationship.from, resource) || referenceMatchesResource(relationship.to, resource));
          const statusTone = resource.status.stalled === true ? "danger" : resource.status.ready === true ? "signal" : "muted";
          return <article className="panel managed-resource-card" key={resource.id}>
            <div className="panel-heading">
              <div><p className="managed-api">{resource.apiVersion} / {resource.plural}</p><h2>{resource.kind}/{resource.name}</h2></div>
              <span className={`status-pill ${statusTone}`}>{resource.status.stalled === true ? "Stalled" : resource.status.state || "Observed"}</span>
            </div>
            <div className="managed-fact-list">
              <div><span>Scope</span><strong>{resource.namespace || "cluster"}</strong></div>
              <div><span>Management</span><strong>{resource.provenance.gitOps ? "GitOps" : humanize(resource.provenance.system)}</strong></div>
              <div><span>Ready / synced</span><strong>{managedBoolean(resource.status.ready)} / {managedBoolean(resource.status.synced)}</strong></div>
              <div><span>Relationships</span><strong>{related.length}</strong></div>
            </div>
            <div className="managed-source-card"><div><strong>Source of truth</strong><span>{managedResourceSourceOfTruth(resource)}</span>{(resource.externalId || resource.generation !== undefined) && <small>{resource.externalId ? `External ID ${resource.externalId}` : ""}{resource.externalId && resource.generation !== undefined ? " · " : ""}{resource.generation !== undefined ? `generation ${resource.generation}` : ""}</small>}</div></div>
            {(resource.status.conditions ?? []).length > 0 && <div className="managed-condition-list">{(resource.status.conditions ?? []).slice(0, 3).map((condition) => <span key={`${condition.type}-${condition.reason ?? condition.status}`}><strong>{condition.type}: {condition.status}</strong>{condition.reason ? ` / ${condition.reason}` : ""}</span>)}</div>}
          </article>;
        })}
      </section>
    </section>
  );
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

function ExperimentsTemplateView({ experiments, run, message, onStart, onDecision }: {
  experiments: ChaosExperiment[];
  run: ChaosExperimentRun | null;
  message: string;
  onStart: (experimentId: string, manifest: string) => void | Promise<void>;
  onDecision: (action: "approve" | "reject" | "execute" | "abort", reason: string) => void | Promise<void>;
}) {
  const [customManifest, setCustomManifest] = useState("apiVersion: chaos-mesh.org/v1alpha1\nkind: NetworkChaos\nmetadata:\n  name: kubeathrix-custom\n  namespace: default\nspec:\n  action: delay\n  direction: to\n  mode: one\n  selector:\n    namespaces:\n      - default\n    labelSelectors:\n      app.kubernetes.io/name: example\n  delay:\n    latency: \"100ms\"\n  duration: \"60s\"");
  const [targetNamespace, setTargetNamespace] = useState("default");
  const [targetLabelKey, setTargetLabelKey] = useState("app.kubernetes.io/name");
  const [targetLabelValue, setTargetLabelValue] = useState("");
  const [decisionReason, setDecisionReason] = useState("");
  const targetReady = targetNamespace.trim() !== "" && targetLabelKey.trim() !== "" && targetLabelValue.trim() !== "";
  const prepareManifest = (manifest: string) => manifest.replaceAll("{{TARGET_NAMESPACE}}", targetNamespace.trim()).replaceAll("{{TARGET_LABEL_KEY}}", targetLabelKey.trim()).replaceAll("{{TARGET_LABEL_VALUE}}", targetLabelValue.trim());
  return (
    <section className="template-stack experiments-layout">
      <article className="panel experiment-target-panel">
        <div className="panel-heading"><div><h2>Bounded chaos experiments</h2><p>Preflight-validated, approval-gated, auto-cleanup</p></div></div>
        <div className="target-grid">
          <label><span>Namespace</span><input value={targetNamespace} onChange={(event) => setTargetNamespace(event.target.value)} /></label>
          <label><span>Label key</span><input value={targetLabelKey} onChange={(event) => setTargetLabelKey(event.target.value)} /></label>
          <label><span>Label value</span><input value={targetLabelValue} placeholder="required" onChange={(event) => setTargetLabelValue(event.target.value)} /></label>
        </div>
      </article>
      <section className="experiment-grid">
        {experiments.map((experiment) => <article className="panel experiment-card" key={experiment.id}>
          <p className="experiment-engine">{experiment.engine} / {experiment.category}</p>
          <h2>{experiment.name}</h2>
          <p className="summary-text">{experiment.description}</p>
          <div className="preflight-list">{experiment.preflight.map((step) => <span key={step}><CheckCircle2 size={15} aria-hidden="true" />{step}</span>)}</div>
          <div className="experiment-actions"><button className="secondary-button" type="button" disabled={!targetReady} onClick={() => void onStart(experiment.id, prepareManifest(experiment.manifest))}>Request bounded run</button><code>{experiment.target}</code></div>
        </article>)}
        <article className="panel experiment-card custom-experiment-card">
          <p className="experiment-engine">engine-scoped / custom</p>
          <h2>Custom YAML manifest</h2>
          <p className="summary-text">Submit an engine-scoped manifest through the same preflight and approval boundary.</p>
          <textarea className="manifest-editor" aria-label="Custom experiment YAML" value={customManifest} onChange={(event) => setCustomManifest(event.target.value)} spellCheck={false} />
          <div className="experiment-actions">
            <label className="secondary-button file-button"><input type="file" accept=".yaml,.yml,text/yaml,text/plain" onChange={(event) => { const file = event.currentTarget.files?.[0]; if (file) void file.text().then(setCustomManifest); }} /><FileClock size={18} aria-hidden="true" />Load YAML</label>
            <button className="secondary-button" type="button" onClick={() => void onStart("custom", customManifest)}>Request custom run</button>
          </div>
        </article>
      </section>
      <article className="panel experiment-run-panel">
        <div className="panel-heading">
          <div><h2>{run ? `Latest run · ${run.id} ${humanize(run.status)}` : "Latest run"}</h2><p>{run ? `${run.resource?.namespace ?? "cluster"}/${run.resource?.name ?? "target"} · ${run.durationSeconds}s · ${run.targetCount} target(s)` : "No experiment has been requested in this session"}</p></div>
          <span className="status-pill muted">{run && run.status !== "preflight_validated" ? "persistent lifecycle" : "preflight by default"}</span>
        </div>
        {run ? <>
          <div className={`experiment-run-summary ${run.status === "failed" ? "danger" : "signal"}`}><strong>{run.message}</strong>{run.failureReason && <span>Failure: {run.failureReason}</span>}{run.recoveryMessage && <span>Recovery: {run.recoveryMessage}</span>}{run.injectionDeadline && run.status === "execution_requested" && <span>Injection proof deadline: {new Date(run.injectionDeadline).toLocaleString()}</span>}</div>
          {message && <p className="workflow-message">{message}</p>}
          <div className="experiment-decision-row">
            <label><span className="sr-only">Decision or abort reason</span><input aria-label="Decision or abort reason" value={decisionReason} onChange={(event) => setDecisionReason(event.target.value)} placeholder="Decision or abort reason" /></label>
            {run.status === "pending_approval" && <><button className="primary-button" type="button" disabled={!decisionReason.trim()} onClick={() => void onDecision("approve", decisionReason)}>Approve</button><button className="secondary-button" type="button" disabled={!decisionReason.trim()} onClick={() => void onDecision("reject", decisionReason)}>Reject</button></>}
            {run.status === "approved" && <button className="primary-button" type="button" onClick={() => void onDecision("execute", "")}>Execute approved run</button>}
            {["approved", "execution_requested", "running", "cleanup_requested", "verifying_recovery"].includes(run.status) && <button className="secondary-button" type="button" disabled={run.status !== "approved" && !decisionReason.trim()} onClick={() => void onDecision("abort", decisionReason || "cancelled before execution")}>Abort and clean up</button>}
          </div>
        </> : <p className="summary-text">Request a predefined or custom manifest. Default installations stop after preflight; execution-enabled installations preserve a separate approval, execution, cleanup, and recovery lifecycle.</p>}
      </article>
    </section>
  );
}

function AuditView({ events }: { events: AuditEvent[] }) {
  return (
    <section className="template-stack audit-layout">
      <article className="panel audit-panel">
        <div className="panel-heading"><div><h2>Audit trail</h2><p>Every decision stays visible — actor, action, reason</p></div></div>
        <div className="audit-row-list">
          {events.map((event) => (
            <div className="audit-row" key={event.id}>
              <code>{event.actor}</code>
              <div><strong>{humanize(event.action)}</strong><span>{event.message || event.subject}</span></div>
              <time>{formatEventTime(event.createdAt)}</time>
            </div>
          ))}
          {events.length === 0 && <p className="summary-text">No audit events are currently available.</p>}
        </div>
      </article>
    </section>
  );
}

function IntegrationsView({ integrations, health }: { integrations: Integration[]; health: Record<string, IntegrationHealth> }) {
  return (
    <section className="integration-grid">
      {integrations.map((integration) => {
        const details = health[integration.name];
        return (
          <article className="panel integration-panel" key={integration.name}>
            <div className="panel-heading">
              <div>
                <p className="eyebrow">{integration.type}</p>
                <h2>{integration.name}</h2>
              </div>
              <span className={integration.enabled ? "status-dot online" : "status-dot"} />
            </div>
            <p className="summary-text">{details?.errorState || (integration.enabled ? "A supported Kubernetes report API was discovered and queried." : "No supported report API was discovered; configuration flags alone do not count as healthy.")}</p>
            <div className="integration-facts">
              <div><span>Health</span><strong>{details?.health ?? integration.status}</strong></div>
              <div><span>Last seen</span><strong>{details?.dataLastSeen ?? "unknown"}</strong></div>
              <div><span>Findings</span><strong>{details?.findingsCount ?? 0}</strong></div>
            </div>
          </article>
        );
      })}
    </section>
  );
}

function SettingsView({ providers, busy, message, onSave, onStoreSecret }: {
	providers: ModelProviderSettings | null;
	busy: boolean;
	message: string;
	onSave: (settings: ModelProviderSettings) => Promise<ModelProviderSettings>;
	onStoreSecret: (settings: ModelProviderSettings, providerIndex: number, value: string) => Promise<ModelProviderSettings>;
}) {
	const [draft, setDraft] = useState<ModelProviderSettings>({ providers: [] });
	const [secretValues, setSecretValues] = useState<Record<number, string>>({});

	useEffect(() => {
		setDraft({ providers: providers?.providers.map((provider) => ({ ...provider })) ?? [] });
		setSecretValues({});
	}, [providers]);

	function updateProvider(index: number, update: (provider: ModelProvider) => ModelProvider) {
		setDraft((current) => ({ providers: current.providers.map((provider, providerIndex) => providerIndex === index ? update(provider) : provider) }));
	}

	function addProvider() {
		const suffix = draft.providers.length + 1;
		setDraft((current) => ({ providers: [...current.providers, {
			name: `provider-${suffix}`,
			type: "openai-compatible",
			model: "",
			apiKeySecretRef: { name: `kubeathrix-provider-${suffix}`, key: "api-key" }
		}] }));
	}

	if (providers === null) {
		return <section className="view-grid"><div className="panel wide-panel"><div className="panel-heading"><div><p className="eyebrow">Administrator only</p><h2>Provider management</h2></div><LockKeyhole size={20} aria-hidden="true" /></div><p className="summary-text">Your identity cannot read or change model-provider settings.</p></div></section>;
	}

	return (
		<section className="view-grid provider-management">
			<div className="panel wide-panel">
				<div className="panel-heading">
					<div><p className="eyebrow">Optional AI assist</p><h2>Model providers</h2><p>Keys stay in namespace-scoped Kubernetes Secrets.</p></div>
					<button className="secondary-button" type="button" disabled={busy} onClick={addProvider}><Bot size={17} aria-hidden="true" />Add provider</button>
				</div>
				<div className="provider-list">
					{draft.providers.map((provider, index) => {
						const source = provider.externalSecretRef ? "external" : "kubernetes";
						const isSaved = index < (providers?.providers.length ?? 0);
						return (
							<article className="provider-editor" key={`${provider.name}-${index}`}>
								<div className="provider-editor-heading">
									<div><strong>{provider.name || "Unnamed provider"}</strong><span>{provider.model || "Choose a model"}</span></div>
									<span className="status-pill muted">{isSaved ? "Configured" : "New"}</span>
								</div>
								<div className="provider-fields">
									<label><span>Name</span><input value={provider.name} onChange={(event) => updateProvider(index, (item) => ({ ...item, name: event.target.value }))} /></label>
									<label><span>Provider type</span><select value={provider.type} onChange={(event) => updateProvider(index, (item) => ({ ...item, type: event.target.value }))}><option value="openai-compatible">OpenAI compatible</option><option value="openai">OpenAI</option><option value="anthropic">Anthropic</option><option value="google">Google</option><option value="mistral">Mistral</option><option value="azure-openai">Azure OpenAI</option><option value="aws-bedrock">AWS Bedrock</option><option value="ollama">Ollama (in-cluster)</option></select></label>
									<label><span>Model</span><input value={provider.model} placeholder="e.g. gpt-5" onChange={(event) => updateProvider(index, (item) => ({ ...item, model: event.target.value }))} /></label>
									<label><span>Secret source</span><select value={source} onChange={(event) => updateProvider(index, (item) => event.target.value === "external" ? { ...item, apiKeySecretRef: undefined, externalSecretRef: { store: "default", path: "", key: "api-key" } } : { ...item, externalSecretRef: undefined, apiKeySecretRef: { name: `kubeathrix-${safeSecretName(item.name)}`, key: "api-key" } })}><option value="kubernetes">Cluster Secret</option><option value="external">External Secret reference</option></select></label>
								</div>
								{source === "kubernetes" ? (
									<div className="provider-secret-fields">
										<label><span>Secret name</span><input value={provider.apiKeySecretRef?.name ?? ""} onChange={(event) => updateProvider(index, (item) => ({ ...item, apiKeySecretRef: { name: event.target.value, key: item.apiKeySecretRef?.key ?? "api-key" } }))} /></label>
										<label><span>Secret key</span><input value={provider.apiKeySecretRef?.key ?? ""} onChange={(event) => updateProvider(index, (item) => ({ ...item, apiKeySecretRef: { name: item.apiKeySecretRef?.name ?? "", key: event.target.value } }))} /></label>
										<label className="secret-value-field"><span>API key (never returned)</span><input type="password" autoComplete="new-password" value={secretValues[index] ?? ""} placeholder={isSaved ? "Enter a new value to rotate" : "Enter provider API key"} onChange={(event) => setSecretValues((current) => ({ ...current, [index]: event.target.value }))} /></label>
										<button className="primary-button provider-secret-button" type="button" disabled={busy || !provider.name.trim() || !provider.model.trim() || !provider.apiKeySecretRef?.name.trim() || !provider.apiKeySecretRef?.key.trim() || !(secretValues[index] ?? "").trim()} onClick={() => {
											void onStoreSecret(draft, index, secretValues[index] ?? "").then((updated) => {
												setDraft(updated);
												setSecretValues((current) => ({ ...current, [index]: "" }));
											}).catch(() => undefined);
										}}><KeyRound size={17} aria-hidden="true" />{isSaved ? "Rotate key" : "Store key & save"}</button>
									</div>
								) : (
									<div className="provider-secret-fields external-secret-fields">
										<label><span>Secret store</span><input value={provider.externalSecretRef?.store ?? ""} onChange={(event) => updateProvider(index, (item) => ({ ...item, externalSecretRef: { store: event.target.value, path: item.externalSecretRef?.path ?? "", key: item.externalSecretRef?.key ?? "api-key" } }))} /></label>
										<label><span>Remote path</span><input value={provider.externalSecretRef?.path ?? ""} onChange={(event) => updateProvider(index, (item) => ({ ...item, externalSecretRef: { store: item.externalSecretRef?.store ?? "default", path: event.target.value, key: item.externalSecretRef?.key ?? "api-key" } }))} /></label>
										<label><span>Remote key</span><input value={provider.externalSecretRef?.key ?? ""} onChange={(event) => updateProvider(index, (item) => ({ ...item, externalSecretRef: { store: item.externalSecretRef?.store ?? "default", path: item.externalSecretRef?.path ?? "", key: event.target.value } }))} /></label>
									</div>
								)}
								<div className="provider-editor-actions"><button className="secondary-button danger-button" type="button" disabled={busy} onClick={() => setDraft((current) => ({ providers: current.providers.filter((_, providerIndex) => providerIndex !== index) }))}>Remove</button></div>
							</article>
						);
					})}
					{draft.providers.length === 0 && <p className="summary-text">No model provider is configured. Add one to create a Kubernetes Secret reference or save an external secret reference.</p>}
				</div>
				<div className="provider-footer">
					<button className="primary-button" type="button" disabled={busy} onClick={() => void onSave(draft).then(setDraft).catch(() => undefined)}><ShieldCheck size={17} aria-hidden="true" />{busy ? "Saving…" : "Save provider references"}</button>
					{message && <p className="workflow-message" aria-live="polite">{message}</p>}
				</div>
				<p className="summary-text">AI decision support can explain findings and typed plans. It cannot add executable actions or bypass dry-run, approval, verification, or rollback controls.</p>
			</div>
		</section>
	);
}

function SettingsTemplateView({ providers, busy, message, onSave, onStoreSecret }: {
  providers: ModelProviderSettings | null;
  busy: boolean;
  message: string;
  onSave: (settings: ModelProviderSettings) => Promise<ModelProviderSettings>;
  onStoreSecret: (settings: ModelProviderSettings, providerIndex: number, value: string) => Promise<ModelProviderSettings>;
}) {
  const emptyForm = { type: "openai-compatible", model: "", apiKey: "", source: "kubernetes", store: "default", path: "", key: "api-key" };
  const [draft, setDraft] = useState<ModelProviderSettings>({ providers: [] });
  const [form, setForm] = useState(emptyForm);
  const [editingIndex, setEditingIndex] = useState<number | null>(null);

  useEffect(() => { setDraft({ providers: providers?.providers.map((provider) => ({ ...provider })) ?? [] }); }, [providers]);

  function beginProviderEdit(index: number) {
    const provider = draft.providers[index];
    setEditingIndex(index);
    setForm({ type: provider.type, model: provider.model, apiKey: "", source: provider.externalSecretRef ? "external" : "kubernetes", store: provider.externalSecretRef?.store ?? "default", path: provider.externalSecretRef?.path ?? "", key: provider.externalSecretRef?.key ?? provider.apiKeySecretRef?.key ?? "api-key" });
  }

  async function saveProvider() {
    const index = editingIndex ?? draft.providers.length;
    const existing = editingIndex === null ? undefined : draft.providers[editingIndex];
    const name = existing?.name || `${safeSecretName(form.type)}-${draft.providers.length + 1}`;
    const provider: ModelProvider = form.source === "external"
      ? { name, type: form.type, model: form.model, externalSecretRef: { store: form.store, path: form.path, key: form.key || "api-key" } }
      : { name, type: form.type, model: form.model, apiKeySecretRef: existing?.apiKeySecretRef ?? { name: `kubeathrix-${safeSecretName(name)}`, key: form.key || "api-key" } };
    const next: ModelProviderSettings = { providers: editingIndex === null ? [...draft.providers, provider] : draft.providers.map((item, providerIndex) => providerIndex === editingIndex ? provider : item) };
    const updated = form.source === "kubernetes" ? await onStoreSecret(next, index, form.apiKey) : await onSave(next);
    setDraft(updated);
    setEditingIndex(null);
    setForm(emptyForm);
  }

  async function removeProvider(index: number) {
    const next = { providers: draft.providers.filter((_, providerIndex) => providerIndex !== index) };
    const updated = await onSave(next);
    setDraft(updated);
    if (editingIndex === index) { setEditingIndex(null); setForm(emptyForm); }
  }

  if (providers === null) return <section className="template-stack"><article className="panel"><div className="panel-heading"><div><h2>Provider management</h2><p>Administrator only</p></div><LockKeyhole size={20} aria-hidden="true" /></div><p className="summary-text">Your identity cannot read or change model-provider settings.</p></article></section>;

  const formReady = form.type.trim() !== "" && form.model.trim() !== "" && (form.source === "kubernetes" ? form.apiKey.trim() !== "" : form.store.trim() !== "" && form.path.trim() !== "" && form.key.trim() !== "");
  return (
    <section className="template-stack settings-layout">
      <article className="panel provider-list-panel">
        <div className="panel-heading"><div><h2>Model providers</h2><p>Optional AI assist · keys stay in cluster secrets</p></div></div>
        <div className="provider-rows">
          {draft.providers.map((provider, index) => <div className="provider-row" key={`${provider.name}-${index}`}>
            <div><strong>{provider.name}</strong><span>{provider.type} · {provider.model || "model not set"}</span></div>
            <span className="status-pill signal">configured</span>
            <code>{provider.externalSecretRef ? `${provider.externalSecretRef.store}:${provider.externalSecretRef.path}#${provider.externalSecretRef.key}` : `${provider.apiKeySecretRef?.name ?? "secret"}:${provider.apiKeySecretRef?.key ?? "api-key"}`}</code>
            <div className="provider-row-actions"><button className="secondary-button compact-button" type="button" onClick={() => beginProviderEdit(index)}>Rotate</button><button className="secondary-button compact-button danger-button" type="button" disabled={busy} onClick={() => void removeProvider(index)}>Remove</button></div>
          </div>)}
          {draft.providers.length === 0 && <p className="summary-text">No model provider is configured.</p>}
        </div>
        <p className="panel-note">When enabled, AI decision support explains findings and typed plans with structured output. It cannot add executable actions or bypass dry-run, approval, verification, or rollback controls.</p>
      </article>

      <article className="panel add-provider-panel">
        <div className="panel-heading"><div><h2>{editingIndex === null ? "Add provider" : `Rotate provider · ${draft.providers[editingIndex]?.name}`}</h2><p>Keys are written to a cluster Secret or an external reference — never returned by the console</p></div>{editingIndex !== null && <button className="secondary-button compact-button" type="button" onClick={() => { setEditingIndex(null); setForm(emptyForm); }}>Cancel</button>}</div>
        <div className="provider-add-grid">
          <label><span>Provider</span><select value={form.type} onChange={(event) => setForm((current) => ({ ...current, type: event.target.value }))}><option value="openai-compatible">OpenAI-compatible endpoint</option><option value="openai">OpenAI</option><option value="anthropic">Anthropic</option><option value="google">Google</option><option value="mistral">Mistral</option><option value="azure-openai">Azure OpenAI</option><option value="aws-bedrock">AWS Bedrock</option><option value="ollama">Ollama (in-cluster)</option></select></label>
          <label><span>Model</span><input value={form.model} placeholder="e.g. gpt-5" onChange={(event) => setForm((current) => ({ ...current, model: event.target.value }))} /></label>
          <label><span>API key (never returned)</span><input type="password" autoComplete="new-password" disabled={form.source === "external"} value={form.apiKey} placeholder={editingIndex === null ? "Enter provider API key" : "Enter a new value to rotate"} onChange={(event) => setForm((current) => ({ ...current, apiKey: event.target.value }))} /></label>
          <label><span>Store as</span><select value={form.source} onChange={(event) => setForm((current) => ({ ...current, source: event.target.value }))}><option value="kubernetes">Cluster Secret (ns/kubeathrix)</option><option value="external">External Secret reference</option></select></label>
        </div>
        {form.source === "external" && <div className="external-reference-grid"><label><span>Secret store</span><input value={form.store} onChange={(event) => setForm((current) => ({ ...current, store: event.target.value }))} /></label><label><span>Remote path</span><input value={form.path} onChange={(event) => setForm((current) => ({ ...current, path: event.target.value }))} /></label><label><span>Remote key</span><input value={form.key} onChange={(event) => setForm((current) => ({ ...current, key: event.target.value }))} /></label></div>}
        <div className="provider-save-row"><button className="primary-button" type="button" disabled={busy || !formReady} onClick={() => void saveProvider().catch(() => undefined)}><KeyRound size={17} aria-hidden="true" />{busy ? "Saving…" : editingIndex === null ? form.source === "kubernetes" ? "Store key & save" : "Save provider" : form.source === "kubernetes" ? "Rotate key" : "Save reference"}</button><span>{form.source === "kubernetes" ? "The key is written directly to the configured namespace-scoped Secret." : "Only the external secret reference is stored."}</span></div>
        {message && <p className="workflow-message" aria-live="polite">{message}</p>}
      </article>
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

function auditStage(action: string): string {
  const normalized = action.toLowerCase();
  if (normalized.includes("approv") || normalized.includes("reject")) return "APPROVE";
  if (normalized.includes("execut") || normalized.includes("applied")) return "EXECUTE";
  if (normalized.includes("verif") || normalized.includes("evidence")) return "VERIFY";
  if (normalized.includes("plan") || normalized.includes("preview")) return "PLAN";
  if (normalized.includes("block") || normalized.includes("denied")) return "BLOCK";
  return "DETECT";
}

function findingResourceLabel(finding: Finding): string {
  const resource = finding.resources[0];
  if (!resource) return finding.correlationGroup || finding.source;
  return `${resource.kind.toLowerCase()}/${resource.namespace ? `${resource.namespace}/` : ""}${resource.name}`;
}

function formatEventTime(value: string): string {
  if (!value) return "just now";
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return value;
  const elapsedMinutes = Math.max(0, Math.floor((Date.now() - timestamp) / 60_000));
  if (elapsedMinutes < 1) return "just now";
  if (elapsedMinutes < 60) return `${elapsedMinutes}m ago`;
  const elapsedHours = Math.floor(elapsedMinutes / 60);
  if (elapsedHours < 24) return `${elapsedHours}h ago`;
  return `${Math.floor(elapsedHours / 24)}d ago`;
}

function formatUptime(seconds: number): string {
	const safeSeconds = Math.max(0, Math.floor(seconds));
	const days = Math.floor(safeSeconds / 86_400);
	const hours = Math.floor((safeSeconds % 86_400) / 3_600);
	const minutes = Math.floor((safeSeconds % 3_600) / 60);
	if (days > 0) return `${days}d ${hours}h`;
	if (hours > 0) return `${hours}h ${minutes}m`;
	return `${minutes}m`;
}

function humanize(value: string) {
  return value.replaceAll("_", " ");
}

function formatAgentMode(value: string): string {
	const normalized = value.replaceAll("_", " ").replaceAll("-", " ");
	return normalized ? normalized[0].toUpperCase() + normalized.slice(1) : normalized;
}

function safeFilename(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 96) || "bundle";
}

function safeSecretName(value: string): string {
	return value.toLowerCase().replace(/[^a-z0-9.-]+/g, "-").replace(/^[^a-z0-9]+|[^a-z0-9]+$/g, "").slice(0, 48) || "provider";
}

export default App;
