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
import { createRemediationPlan, loadAuditEvents, loadDashboard, loadFindings, loadIntegrations, loadModelProviders } from "./api";
import type { AuditEvent, Dashboard, Finding, Integration, ModelProviderSettings, RemediationPlan, Severity } from "./types";

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

function App() {
  const [activeView, setActiveView] = useState<View>("dashboard");
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState("finding-public-rbac-image");
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [modelProviders, setModelProviders] = useState<ModelProviderSettings | null>(null);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [plan, setPlan] = useState<RemediationPlan | null>(null);
  const [workflowMessage, setWorkflowMessage] = useState("No remediation has been submitted in this console session.");

  useEffect(() => {
    void Promise.all([loadDashboard(), loadFindings(), loadAuditEvents(), loadIntegrations(), loadModelProviders()]).then(
      ([dashboardData, findingData, auditData, integrationData, providerData]) => {
        setDashboard(dashboardData);
        setFindings(findingData);
        setAuditEvents(auditData);
        setIntegrations(integrationData);
        setModelProviders(providerData);
        if (findingData.length > 0) {
          setSelectedFindingId(findingData[0].id);
        }
      }
    );
  }, []);

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
    const nextPlan = await createRemediationPlan(findingId);
    setPlan(nextPlan);
    setWorkflowMessage(
      nextPlan.approvalPolicy.required
        ? "Plan created and waiting for explicit approval."
        : "Plan created as deterministic; controller validation is next."
    );
    setActiveView("fix-center");
  }

  function handleApproval(decision: "approved" | "rejected") {
    if (!plan) {
      return;
    }
    setWorkflowMessage(
      decision === "approved"
        ? `Approved ${plan.id}; remediator will run server-side dry-run before writing.`
        : `Rejected ${plan.id}; no cluster change will be attempted.`
    );
    setAuditEvents((events) => [
      {
        id: `audit-local-${Date.now()}`,
        actor: "console-dev",
        action: decision === "approved" ? "approval.approved" : "approval.rejected",
        subject: plan.id,
        message: decision === "approved" ? "Approved from the console workflow." : "Rejected from the console workflow.",
        createdAt: new Date().toISOString()
      },
      ...events
    ]);
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
              {dashboard?.bundledEnginesOnline ?? 3} engines online
            </span>
            <button className="icon-button" type="button" title="Refresh data" aria-label="Refresh data">
              <RotateCcw size={18} aria-hidden="true" />
            </button>
          </div>
        </header>

        {activeView === "dashboard" && dashboard && (
          <DashboardView dashboard={dashboard} findings={findings} onOpenFinding={(id) => {
            setSelectedFindingId(id);
            setActiveView("findings");
          }} />
        )}
        {activeView === "findings" && (
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
        {activeView === "fix-center" && (
          <FixCenterView plan={plan} finding={selectedFinding} workflowMessage={workflowMessage} onCreatePlan={handleCreatePlan} onApproval={handleApproval} />
        )}
        {activeView === "runtime" && <RuntimeView findings={findings.filter((finding) => finding.source === "falco" || finding.source === "tetragon")} />}
        {activeView === "policy" && <PolicyView findings={findings} />}
        {activeView === "experiments" && <ExperimentsView />}
        {activeView === "audit" && <AuditView events={auditEvents} />}
        {activeView === "integrations" && <IntegrationsView integrations={integrations} />}
        {activeView === "settings" && <SettingsView providers={modelProviders} />}
      </main>
    </div>
  );
}

function DashboardView({ dashboard, findings, onOpenFinding }: { dashboard: Dashboard; findings: Finding[]; onOpenFinding: (id: string) => void }) {
  const topFindings = [...findings].sort((a, b) => b.riskScore - a.riskScore).slice(0, 3);
  return (
    <section className="view-grid dashboard-grid">
      <Metric label="Total findings" value={dashboard.totalFindings} tone="neutral" icon={ShieldCheck} />
      <Metric label="Open critical" value={dashboard.openCritical} tone="danger" icon={AlertTriangle} />
      <Metric label="Pending approvals" value={dashboard.pendingApprovals} tone="warning" icon={UserCheck} />
      <Metric label="Mean risk score" value={Math.round(dashboard.meanRiskScore)} tone="signal" icon={Gauge} />

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
                <div className={`bar-fill ${severity}`} style={{ width: `${((dashboard.findingsBySeverity[severity] ?? 0) / dashboard.totalFindings) * 100}%` }} />
              </div>
              <strong>{dashboard.findingsBySeverity[severity] ?? 0}</strong>
            </div>
          ))}
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
  onCreatePlan,
  onApproval
}: {
  plan: RemediationPlan | null;
  finding?: Finding;
  workflowMessage: string;
  onCreatePlan: (id: string) => void;
  onApproval: (decision: "approved" | "rejected") => void;
}) {
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
            <span className={plan.approvalPolicy.required ? "status-pill warning" : "status-pill signal"}>
              {plan.approvalPolicy.required ? "Approval required" : "Deterministic"}
            </span>
          </div>
          <p className="summary-text">{plan.rootCause}</p>
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
          <div className="button-row">
            <button className="primary-button" type="button" onClick={() => onApproval("approved")}>
              <PlayCircle size={18} aria-hidden="true" />
              Approve
            </button>
            <button className="secondary-button" type="button" onClick={() => onApproval("rejected")}>
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
          {findings.length === 0 && <p className="summary-text">Runtime adapters are stubbed until enabled in Helm values.</p>}
        </div>
      </div>
    </section>
  );
}

function PolicyView({ findings }: { findings: Finding[] }) {
  const policyFindings = findings.filter((finding) => ["kyverno", "kubescape", "correlator"].includes(finding.source));
  return (
    <section className="view-grid">
      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Exceptions and guardrails</p>
            <h2>Policy posture</h2>
          </div>
          <LockKeyhole size={20} aria-hidden="true" />
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

function ExperimentsView() {
  return (
    <section className="view-grid">
      <div className="panel wide-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Verification</p>
            <h2>Chaos guardrails</h2>
          </div>
          <FlaskConical size={20} aria-hidden="true" />
        </div>
        <div className="experiment-grid">
          <Fact label="Chaos Mesh" value="disabled adapter" />
          <Fact label="LitmusChaos" value="disabled adapter" />
          <Fact label="Pre-fix checks" value="required" />
          <Fact label="Rollback checks" value="required" />
        </div>
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
          <p className="summary-text">{integration.enabled ? "Enabled by Helm values and available to the normalizer." : "Adapter stub is present for a later release."}</p>
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

function humanize(value: string) {
  return value.replaceAll("_", " ");
}

export default App;
