package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
)

func TestAgentCreatesAIPlanAndRequestsSafeTierAExecution(t *testing.T) {
	now := time.Date(2026, 7, 14, 8, 0, 0, 0, time.UTC)
	finding := core.Finding{
		ID:                "finding-namespace-quota",
		Source:            "kubeathrix",
		Title:             "Developer namespace has no ResourceQuota or LimitRange",
		Severity:          core.SeverityMedium,
		Resources:         []core.ResourceRef{{APIVersion: "v1", Kind: "Namespace", Name: "team-labs"}},
		Fixability:        core.FixabilityDeterministic,
		Status:            core.FindingOpen,
		RiskScore:         61,
		RemediationState:  "autofix_available",
		RecommendedAction: "Apply namespace-scoped quota and default request limits.",
		CreatedAt:         now.Add(-time.Hour),
		UpdatedAt:         now,
	}
	repository := store.NewMemoryStore(store.WithClock(func() time.Time { return now }), store.WithFindings([]core.Finding{finding}))
	workflow := &recordingWorkflow{}
	notifier := &recordingNotifier{}
	agent, err := New(Config{
		Enabled:             true,
		Interval:            time.Minute,
		AutoPlan:            true,
		AutoExecuteTierA:    true,
		MinRiskScore:        50,
		MaxFindingsPerCycle: 5,
	}, Dependencies{Repository: repository, Advisor: staticAdvisor{now: now}, WorkflowClient: workflow, Notifier: notifier})
	if err != nil {
		t.Fatal(err)
	}

	report := agent.RunOnce(context.Background())
	if report.PlansCreated != 1 || report.Executions != 1 {
		t.Fatalf("expected plan and execution request, got %#v", report)
	}
	if len(workflow.created) != 1 || len(workflow.requested) != 1 {
		t.Fatalf("workflow did not receive create and execute requests: %#v", workflow)
	}
	plan, err := repository.GetRemediationPlan(context.Background(), workflow.created[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.AI == nil || plan.AI.Summary != "AI agent summary" {
		t.Fatalf("expected persisted AI analysis, got %#v", plan.AI)
	}
	if plan.Status != string(core.RunExecutionRequested) {
		t.Fatalf("expected execution requested after safe auto-execute, got %q", plan.Status)
	}
	if !notifier.hasEvent("remediation.execution_requested") {
		t.Fatalf("expected execution notification, got %#v", notifier.events)
	}
}

func TestAgentKeepsRiskyPlanApprovalGated(t *testing.T) {
	now := time.Date(2026, 7, 14, 8, 0, 0, 0, time.UTC)
	finding := core.Finding{
		ID:                "finding-public-rbac",
		Source:            "trivy",
		Title:             "ClusterRoleBinding grants cluster-admin",
		Severity:          core.SeverityCritical,
		Resources:         []core.ResourceRef{{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Name: "public-admin"}},
		Fixability:        core.FixabilityHumanOnly,
		Status:            core.FindingOpen,
		RiskScore:         96,
		RemediationState:  "approval_required",
		RecommendedAction: "Remove broad cluster-admin access after review.",
		CreatedAt:         now.Add(-time.Hour),
		UpdatedAt:         now,
	}
	repository := store.NewMemoryStore(store.WithClock(func() time.Time { return now }), store.WithFindings([]core.Finding{finding}))
	workflow := &recordingWorkflow{}
	notifier := &recordingNotifier{}
	agent, err := New(Config{
		Enabled:             true,
		Interval:            time.Minute,
		AutoPlan:            true,
		AutoExecuteTierA:    true,
		MinRiskScore:        50,
		MaxFindingsPerCycle: 5,
	}, Dependencies{Repository: repository, Advisor: staticAdvisor{now: now}, WorkflowClient: workflow, Notifier: notifier})
	if err != nil {
		t.Fatal(err)
	}

	report := agent.RunOnce(context.Background())
	if report.PlansCreated != 1 || report.Executions != 0 {
		t.Fatalf("expected approval-gated plan without execution, got %#v", report)
	}
	if len(workflow.requested) != 0 {
		t.Fatalf("risky plan was auto-executed: %#v", workflow.requested)
	}
	plan, err := repository.GetRemediationPlan(context.Background(), workflow.created[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApprovalPolicy.Required || plan.ApprovalPolicy.Decision != core.ApprovalPending {
		t.Fatalf("expected pending approval policy, got %#v", plan.ApprovalPolicy)
	}
	if !notifier.hasEvent("approval.required") {
		t.Fatalf("expected approval notification, got %#v", notifier.events)
	}
}

func TestFindingFingerprintIgnoresObservationClockButChangesWithEvidence(t *testing.T) {
	finding := core.Finding{
		ID: "managed-resource-not-ready", Source: "managed-resource", Title: "Not ready",
		Evidence:  []core.Evidence{{Summary: "Not ready", Details: "Ready=False", SourceID: "managed-resource"}},
		Resources: []core.ResourceRef{{APIVersion: "example.io/v1", Kind: "Role", Namespace: "payments", Name: "reader"}},
		Status:    core.FindingOpen, RemediationState: "approval_required", RiskScore: 80,
		UpdatedAt: time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
	}
	first := findingFingerprint(finding)
	finding.UpdatedAt = finding.UpdatedAt.Add(time.Minute)
	finding.Evidence[0].ObservedAt = finding.UpdatedAt
	if second := findingFingerprint(finding); second != first {
		t.Fatalf("observation-only timestamp change altered fingerprint: %s != %s", second, first)
	}
	finding.Evidence[0].Details = "Ready=False reason=DependencyFailed"
	if changed := findingFingerprint(finding); changed == first {
		t.Fatal("material evidence change did not alter fingerprint")
	}
}

func TestAgentReusesPersistedAIAnalysisForIdempotentPlan(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	finding := core.Finding{
		ID: "managed-resource-not-ready", Source: "managed-resource", Title: "Not ready",
		Evidence:   []core.Evidence{{Summary: "Not ready", Details: "Ready=False", SourceID: "managed-resource"}},
		Resources:  []core.ResourceRef{{APIVersion: "example.io/v1", Kind: "Role", Namespace: "payments", Name: "reader"}},
		Fixability: core.FixabilityHumanOnly, Status: core.FindingOpen, RiskScore: 80,
		RemediationState: "approval_required", UpdatedAt: now,
	}
	repository := store.NewMemoryStore(store.WithClock(func() time.Time { return now }), store.WithFindings([]core.Finding{finding}))
	plan, err := repository.CreateRemediationPlanFromFinding(context.Background(), finding, DefaultActor, idempotencyKey(finding))
	if err != nil {
		t.Fatal(err)
	}
	plan.AI = &core.AIAnalysis{Provider: "approved-provider", Model: "approved-model", Mode: "assistive", Summary: "persisted", GeneratedAt: now}
	if err := repository.SyncRemediationPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}

	advisor := &countingAdvisor{}
	workflow := &recordingWorkflow{}
	aiAgent, err := New(Config{Enabled: true, AutoPlan: true, MinRiskScore: 50, MaxFindingsPerCycle: 5}, Dependencies{
		Repository: repository, Advisor: advisor, WorkflowClient: workflow,
	})
	if err != nil {
		t.Fatal(err)
	}
	report := aiAgent.RunOnce(context.Background())
	if len(report.Errors) != 0 || report.PlansCreated != 1 {
		t.Fatalf("unexpected idempotent cycle report: %#v", report)
	}
	if advisor.calls != 0 {
		t.Fatalf("persisted AI analysis triggered %d duplicate provider call(s)", advisor.calls)
	}
	if len(workflow.created) != 1 || workflow.created[0].AI == nil || workflow.created[0].AI.Summary != "persisted" {
		t.Fatalf("persisted AI analysis was not reused in the workflow: %#v", workflow.created)
	}
}

type staticAdvisor struct {
	now time.Time
}

func (a staticAdvisor) Analyze(context.Context, core.Finding, core.RemediationPlan) (core.AIAnalysis, error) {
	return core.AIAnalysis{
		Provider:          "openai",
		Model:             "test-model",
		Mode:              "agent",
		Summary:           "AI agent summary",
		RootCause:         "AI root cause",
		Impact:            "AI impact",
		RecommendedAction: "Use the typed plan",
		Confidence:        "high",
		AutonomousPolicy:  "typed actions only",
		GeneratedAt:       a.now,
	}, nil
}

type countingAdvisor struct{ calls int }

func (a *countingAdvisor) Analyze(context.Context, core.Finding, core.RemediationPlan) (core.AIAnalysis, error) {
	a.calls++
	return core.AIAnalysis{}, errors.New("unexpected duplicate AI provider call")
}

type recordingWorkflow struct {
	created   []core.RemediationPlan
	requested []string
}

func (w *recordingWorkflow) CreatePlan(_ context.Context, _ core.Finding, plan core.RemediationPlan, _ string) error {
	w.created = append(w.created, plan)
	return nil
}

func (w *recordingWorkflow) RequestExecution(_ context.Context, planID, _ string) (core.RemediationRun, error) {
	w.requested = append(w.requested, planID)
	return core.RemediationRun{ID: "run-" + planID, PlanID: planID, State: core.RunExecutionRequested}, nil
}

type recordingNotifier struct {
	events []Event
}

func (n *recordingNotifier) Notify(_ context.Context, event Event) error {
	n.events = append(n.events, event)
	return nil
}

func (n *recordingNotifier) hasEvent(eventType string) bool {
	for _, event := range n.events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}
