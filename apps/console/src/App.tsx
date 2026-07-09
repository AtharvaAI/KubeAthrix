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
  approveRemediationPlan,
  createRemediationPlan,
  loadAuditEvents,
  loadDashboard,
  loadExperiments,
  loadFindings,
  loadIntegrations,
  loadModelProviders,
  rejectRemediationPlan,
  startChaosExperiment
} from "./api";
import type { AuditEvent, ChaosExperiment, ChaosExperimentRun, ClusterInventory, Dashboard, Finding, Integration, ModelProviderSettings, RemediationPlan, ScanSummary, Severity } from "./types";

type View = "dashboard" | "findings" | "fix-center" | "runtime" | "policy" | "experiments" | "audit" | "integrations" | "settings";

const viewItems: Array<{ id: View; label: string; icon: typeof ShieldCheck }> = [
  { id: "dashboard", label: "Dashboard", icon: Gauge },
  { id: "findings", label: "Findings", icon: ShieldCheck },
  { id: "fix-center", label: "Fix Center", icon: Wrench },
  { id: "runtime", label: "Runtime", icon: Activity },
  { id: "policy", label: "Policy", icon: LockKeyhole },
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
  const [activeView, setActiveView] = useState<View>("dashboard");
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState("");
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [experiments, setExperiments] = useState<ChaosExperiment[]>([]);
  const [experimentRun, setExperimentRun] = useState<ChaosExperimentRun | null>(null);
  const [modelProviders, setModelProviders] = useState<ModelProviderSettings | null>(null);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [plan, setPlan] = useState<RemediationPlan | null>(null);
  const [workflowMessage, setWorkflowMessage] = useState("No remediation has been submitted in this console session.");
  const [approvalBusy, setApprovalBusy] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    void refreshData();
  }, []);

  async function refreshData() {
    try {
      const [dashboardData, findingData, auditData, integrationData, providerData, experimentData] = await Promise.all([
        loadDashboard(),
        loadFindings(),
        loadAuditEvents(),
        loadIntegrations(),
        loadModelProviders(),
        loadExperiments()
      ]);
      setDashboard(dashboardData);
      setFindings(findingData);
      setAuditEvents(auditData);
      setIntegrations(integrationData);
      setModelProviders(providerData);
      setExperiments(dashboardData.experiments?.length ? dashboardData.experiments : experimentData);
      setLoadError(null);
      if (findingData.length > 0 && !findingData.some((finding) => finding.id === selectedFindingId)) {
        setSelectedFindingId(findingData[0].id);
      }
      if (findingData.length === 0) {
        setSelectedFindingId("");
      }
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "API unavailable");
    }
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
      setPlan(nextPlan);
      setWorkflowMessage(
        nextPlan.approvalPolicy.required
          ? "Plan created and waiting for explicit approval."
          : "Plan created as deterministic; controller validation is next."
      );
      setLoadError(null);
      setActiveView("fix-center");
    } catch (error) {
      setWorkflowMessage(error instanceof Error ? error.message : "Unable to create remediation plan.");
    }
  }

  async function handleApproval(decision: "approved" | "rejected") {
    if (!plan) {
      return;
    }
    setApprovalBusy(true);
    try {
      const approval = decision === "approved" ? await approveRemediationPlan(plan.id) : await rejectRemediationPlan(plan.id);
      const nextStatus = approval.status === "approved" ? "dry_run_verified" : "rejected";
      setPlan((current) =>
        current
          ? {
              ...current,
              status: nextStatus,
              approvalPolicy: { ...current.approvalPolicy, required: false },
              dryRunResult: {
                passed: approval.status === "approved",
                message:
                  approval.status === "approved"
                    ? "Approval recorded; typed remediation dry-run verified and queued behind controller safety gates."
                    : "Approval rejected; no cluster change will be attempted."
              }
            }
          : current
      );
      setWorkflowMessage(
        decision === "approved"
          ? `Approved ${plan.id}; typed dry-run is verified and the controller gate has the next action.`
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
      const auditData = await loadAuditEvents();
      setAuditEvents(auditData);
      setLoadError(null);
    } catch (error) {
      setExperimentRun({
        id: "",
        experimentId,
        status: "blocked",
        message: error instanceof Error ? error.message : "Unable to start experiment.",
        manifest,
        createdAt: new Date().toISOString()
      });
    }
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
            <span>AI Kubernetes Defender</span>
          </div>
        </div>
        <nav className="nav-list">
          {viewItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                className={activeView === item.id ? "nav-item active" : "nav-item"}
                key={item.id}
                onClick={() => setActiveView(item.id)}
                type="button"
              >
                <Icon size={18} aria-hidden="true" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <div className="guardrail-note">
          <Bot size={18} aria-hidden="true" />
          <span>Models propose structured plans. Controllers execute typed actions only.</span>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">Cluster cockpit</p>
            <h1>{viewItems.find((item) => item.id === activeView)?.label}</h1>
          </div>
          <div className="topbar-actions">
            <span className="status-pill">
              <CheckCircle2 size={16} aria-hidden="true" />
              {dashboard?.bundledEnginesOnline ?? 0} engines configured
            </span>
            <button className="icon-button" type="button" title="Refresh data" aria-label="Refresh data" onClick={() => void refreshData()}>
              <RotateCcw size={18} aria-hidden="true" />
            </button>
          </div>
        </header>

        {loadError && <ErrorPanel message={loadError} onRetry={() => void refreshData()} />}
        {!loadError && activeView === "dashboard" && dashboard && (
          <DashboardView dashboard={dashboard} findings={findings} onOpenFinding={(id) => {
            setSelectedFindingId(id);
            setActiveView("findings");
          }} />
        )}
        {!loadError && activeView === "findings" && (
          <FindingsView
            findings={filteredFindings}
            selectedFinding={selectedFinding}
            query={query}
            severityFilter={severityFilter}
            onQueryChange={setQuery}
            onSeverityChange={setSeverityFilter}
            onSelect={setSelectedFindingId}
            onCreatePlan={handleCreatePlan}
          />
        )}
        {!loadError && activeView === "fix-center" && (
          <FixCenterView plan={plan} finding={selectedFinding} workflowMessage={workflowMessage} approvalBusy={approvalBusy} onCreatePlan={handleCreatePlan} onApproval={handleApproval} />
        )}
        {!loadError && activeView === "runtime" && <RuntimeView findings={findings.filter((finding) => finding.source === "falco" || finding.source === "tetragon")} />}
        {!loadError && activeView === "policy" && dashboard && <PolicyView findings={findings} dashboard={dashboard} />}
        {!loadError && activeView === "experiments" && <ExperimentsView experiments={experiments} run={experimentRun} onStart={handleStartExperiment} />}
        {!loadError && activeView === "audit" && <AuditView events={auditEvents} />}
        {!loadError && activeView === "integrations" && <IntegrationsView integrations={integrations} />}
        {!loadError && activeView === "settings" && <SettingsView providers={modelProviders} />}
      </main>
    </div>
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
      <Metric label="Total findings" value={dashboard.totalFindings} tone="neutral" icon={ShieldCheck} />
      <Metric label="Open critical" value={dashboard.openCritical} tone="danger" icon={AlertTriangle} />
      <Metric label="Pending approvals" value={dashboard.pendingApprovals} tone="warning" icon={UserCheck} />
      <Metric label="Mean risk score" value={Math.round(dashboard.meanRiskScore)} tone="signal" icon={Gauge} />
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
          <Fact label="NetworkPolicies" value={cluster.networkPolicies ?? 0} />
          <Fact label="ResourceQuotas" value={cluster.resourceQuotas ?? 0} />
          <Fact label="LimitRanges" value={cluster.limitRanges ?? 0} />
          <Fact label="PDBs / HPAs" value={`${cluster.podDisruptionBudgets ?? 0} / ${cluster.horizontalPodAutoscalers ?? 0}`} />
        </div>
      </div>

      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">RBAC and sensitive metadata</p>
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
          <Fact label="Secrets metadata" value={cluster.secrets ?? 0} />
          <Fact label="ConfigMaps" value={cluster.configMaps ?? 0} />
          <Fact label="Recent events" value={cluster.events ?? 0} />
        </div>
      </div>

      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Issue graph</p>
            <h2>Correlated cluster risk</h2>
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
  query: string;
  severityFilter: string;
  onQueryChange: (value: string) => void;
  onSeverityChange: (value: string) => void;
  onSelect: (id: string) => void;
  onCreatePlan: (id: string) => void;
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
        <FindingDetail finding={props.selectedFinding} onCreatePlan={() => props.onCreatePlan(props.selectedFinding!.id)} />
      )}
    </section>
  );
}

function FindingDetail({ finding, onCreatePlan }: { finding: Finding; onCreatePlan: () => void }) {
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
      <h3>Affected resources</h3>
      <div className="resource-list">
        {finding.resources.map((resource) => (
          <code key={`${resource.kind}-${resource.namespace}-${resource.name}`}>
            {resource.kind}/{resource.namespace ? `${resource.namespace}/` : ""}
            {resource.name}
          </code>
        ))}
      </div>
      <button className="primary-button" type="button" onClick={onCreatePlan}>
        <Sparkles size={18} aria-hidden="true" />
        Generate typed plan
      </button>
    </article>
  );
}

function FixCenterView({
  plan,
  finding,
  workflowMessage,
  approvalBusy,
  onCreatePlan,
  onApproval
}: {
  plan: RemediationPlan | null;
  finding?: Finding;
  workflowMessage: string;
  approvalBusy: boolean;
  onCreatePlan: (id: string) => void;
  onApproval: (decision: "approved" | "rejected") => void | Promise<void>;
}) {
  const planBadge = plan ? remediationBadge(plan) : null;
  const decisionLocked = plan?.status === "dry_run_verified" || plan?.status === "rejected";
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
          {["Normalize", "Plan", "Dry-run", "Approve", "Verify"].map((step, index) => (
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
            <Fact label="Plan status" value={humanize(plan.status)} />
            <Fact label="Approval gate" value={plan.approvalPolicy.required ? "required" : "cleared"} />
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
            <button className="primary-button" type="button" disabled={approvalBusy || decisionLocked} onClick={() => void onApproval("approved")}>
              <PlayCircle size={18} aria-hidden="true" />
              {approvalBusy ? "Working" : "Approve"}
            </button>
            <button className="secondary-button" type="button" disabled={approvalBusy || decisionLocked} onClick={() => void onApproval("rejected")}>
              <RotateCcw size={18} aria-hidden="true" />
              Reject
            </button>
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

function ExperimentsView({
  experiments,
  run,
  onStart
}: {
  experiments: ChaosExperiment[];
  run: ChaosExperimentRun | null;
  onStart: (experimentId: string, manifest: string) => void | Promise<void>;
}) {
  const [customManifest, setCustomManifest] = useState(
    "apiVersion: chaos-mesh.org/v1alpha1\nkind: NetworkChaos\nmetadata:\n  name: kubeathrix-custom\n  namespace: default\nspec:\n  action: delay\n  mode: one\n  selector:\n    namespaces:\n      - default\n  delay:\n    latency: \"100ms\"\n  duration: \"60s\""
  );
  const [targetNamespace, setTargetNamespace] = useState("default");
  const [targetLabelKey, setTargetLabelKey] = useState("app.kubernetes.io/name");
  const [targetLabelValue, setTargetLabelValue] = useState("");
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
            <h2>Pre-ready chaos experiments</h2>
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
                  Start preflight
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
            Start custom preflight
          </button>
        </div>
      </div>

      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Run state</p>
            <h2>Experiment execution gate</h2>
          </div>
          <span className="status-pill warning">approval guarded</span>
        </div>
        {run ? (
          <div className="timeline">
            <div className="timeline-item pass">
              <strong>{humanize(run.status)}</strong>
              <span>{run.message}</span>
              <small>{run.id}</small>
            </div>
          </div>
        ) : (
          <p className="summary-text">Start a predefined or custom manifest to create a preflight-ready chaos run.</p>
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

function IntegrationsView({ integrations }: { integrations: Integration[] }) {
  return (
    <section className="integration-grid">
      {integrations.map((integration) => (
        <div className="panel integration-panel" key={integration.name}>
          <div className="panel-heading">
            <div>
              <p className="eyebrow">{integration.type}</p>
              <h2>{integration.name}</h2>
            </div>
            <span className={integration.enabled ? "status-dot online" : "status-dot"} />
          </div>
          <p className="summary-text">{integration.enabled ? "Enabled by Helm values and available to the normalizer." : "Not installed or disabled in Helm values."}</p>
          <span className="status-pill muted">{integration.status}</span>
        </div>
      ))}
    </section>
  );
}

function SettingsView({ providers }: { providers: ModelProviderSettings | null }) {
  return (
    <section className="view-grid">
      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Model gateway</p>
            <h2>Provider references</h2>
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
        <p className="summary-text">Raw API keys are intentionally excluded from the UI schema. Use a Kubernetes Secret or external secret reference.</p>
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
  if (plan.status === "dry_run_verified") {
    return { label: "Dry-run verified", tone: "signal" };
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

export default App;
