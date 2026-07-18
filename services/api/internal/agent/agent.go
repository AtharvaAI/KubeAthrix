package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/adapters"
	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
)

const DefaultActor = "kubeathrix-ai-agent"

type Repository interface {
	ListFindings(ctx context.Context, filter store.FindingFilter) ([]core.Finding, error)
	SyncFinding(ctx context.Context, finding core.Finding) error
	CreateRemediationPlanFromFinding(ctx context.Context, finding core.Finding, requester string, idempotencyKey ...string) (core.RemediationPlan, error)
	SyncRemediationPlan(ctx context.Context, plan core.RemediationPlan) error
	ExecuteRemediationPlan(ctx context.Context, id, actor string) (core.RemediationRun, error)
}

type Advisor interface {
	Analyze(ctx context.Context, finding core.Finding, plan core.RemediationPlan) (core.AIAnalysis, error)
}

type WorkflowClient interface {
	CreatePlan(ctx context.Context, finding core.Finding, plan core.RemediationPlan, actor string) error
	RequestExecution(ctx context.Context, planID, actor string) (core.RemediationRun, error)
}

type SnapshotSource interface {
	Snapshot(ctx context.Context) (core.ClusterSnapshot, error)
}

type AdapterManager interface {
	Collect(ctx context.Context) adapters.Collection
}

type Notifier interface {
	Notify(ctx context.Context, event Event) error
}

type Config struct {
	Enabled             bool
	Actor               string
	Interval            time.Duration
	MinRiskScore        int
	MaxFindingsPerCycle int
	AutoPlan            bool
	AutoExecuteTierA    bool
	NotificationTimeout time.Duration
	NotificationWebhook string
}

type Dependencies struct {
	Repository     Repository
	Advisor        Advisor
	WorkflowClient WorkflowClient
	SnapshotSource SnapshotSource
	AdapterManager AdapterManager
	Notifier       Notifier
	Logger         *slog.Logger
}

type Agent struct {
	config         Config
	repository     Repository
	advisor        Advisor
	workflow       WorkflowClient
	snapshotSource SnapshotSource
	adapterManager AdapterManager
	notifier       Notifier
	logger         *slog.Logger

	mu        sync.Mutex
	processed map[string]struct{}
}

type CycleReport struct {
	ObservedFindings int
	Processed        int
	PlansCreated     int
	Executions       int
	Notifications    int
	Errors           []string
}

type Event struct {
	Type        string                `json:"type"`
	Message     string                `json:"message"`
	Finding     *core.Finding         `json:"finding,omitempty"`
	Plan        *core.RemediationPlan `json:"plan,omitempty"`
	Run         *core.RemediationRun  `json:"run,omitempty"`
	GeneratedAt time.Time             `json:"generatedAt"`
}

func New(config Config, deps Dependencies) (*Agent, error) {
	if !config.Enabled {
		return nil, errors.New("agent is disabled")
	}
	if deps.Repository == nil {
		return nil, errors.New("agent repository is required")
	}
	if deps.Advisor == nil {
		return nil, errors.New("agent requires an enabled AI advisor")
	}
	if strings.TrimSpace(config.Actor) == "" {
		config.Actor = DefaultActor
	}
	if config.Interval <= 0 {
		config.Interval = time.Minute
	}
	if config.MaxFindingsPerCycle <= 0 {
		config.MaxFindingsPerCycle = 10
	}
	if !config.AutoPlan {
		config.AutoExecuteTierA = false
	}
	if config.NotificationTimeout <= 0 {
		config.NotificationTimeout = 5 * time.Second
	}
	notifier := deps.Notifier
	if notifier == nil && strings.TrimSpace(config.NotificationWebhook) != "" {
		notifier = NewWebhookNotifier(config.NotificationWebhook, config.NotificationTimeout, nil)
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Agent{
		config:         config,
		repository:     deps.Repository,
		advisor:        deps.Advisor,
		workflow:       deps.WorkflowClient,
		snapshotSource: deps.SnapshotSource,
		adapterManager: deps.AdapterManager,
		notifier:       notifier,
		logger:         logger,
		processed:      map[string]struct{}{},
	}, nil
}

func (a *Agent) Start(ctx context.Context) {
	go a.run(ctx)
}

func (a *Agent) run(ctx context.Context) {
	a.logger.Info("starting kubeathrix ai agent", "interval", a.config.Interval.String(), "auto_plan", a.config.AutoPlan, "auto_execute_tier_a", a.config.AutoExecuteTierA)
	a.runCycle(ctx)
	ticker := time.NewTicker(a.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.logger.Info("stopping kubeathrix ai agent")
			return
		case <-ticker.C:
			a.runCycle(ctx)
		}
	}
}

func (a *Agent) RunOnce(ctx context.Context) CycleReport {
	return a.runCycle(ctx)
}

func (a *Agent) runCycle(ctx context.Context) CycleReport {
	start := time.Now()
	report := CycleReport{}
	defer func() {
		logArgs := []any{
			"observed_findings", report.ObservedFindings,
			"processed", report.Processed,
			"plans_created", report.PlansCreated,
			"executions_requested", report.Executions,
			"notifications_sent", report.Notifications,
			"duration_ms", time.Since(start).Milliseconds(),
		}
		if len(report.Errors) > 0 {
			logArgs = append(logArgs, "errors", strings.Join(report.Errors, "; "))
			a.logger.Warn("kubeathrix ai agent cycle completed with errors", logArgs...)
			return
		}
		a.logger.Info("kubeathrix ai agent cycle completed", logArgs...)
	}()
	if err := a.syncObservedFindings(ctx); err != nil {
		report.Errors = append(report.Errors, err.Error())
		a.logger.Warn("ai agent could not sync observed findings", "error", err)
	}
	findings, err := a.repository.ListFindings(ctx, store.FindingFilter{MinRisk: a.config.MinRiskScore})
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}
	findings = activeFindings(findings, a.config.MinRiskScore)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RiskScore == findings[j].RiskScore {
			return findings[i].UpdatedAt.After(findings[j].UpdatedAt)
		}
		return findings[i].RiskScore > findings[j].RiskScore
	})
	report.ObservedFindings = len(findings)
	if len(findings) > a.config.MaxFindingsPerCycle {
		findings = findings[:a.config.MaxFindingsPerCycle]
	}
	for _, finding := range findings {
		key := findingEventKey(finding)
		if a.alreadyProcessed(key) {
			continue
		}
		result := a.processFinding(ctx, finding)
		report.Processed++
		report.PlansCreated += result.PlansCreated
		report.Executions += result.Executions
		report.Notifications += result.Notifications
		report.Errors = append(report.Errors, result.Errors...)
		if len(result.Errors) == 0 {
			a.markProcessed(key)
		}
	}
	return report
}

func (a *Agent) syncObservedFindings(ctx context.Context) error {
	var errs []error
	if a.snapshotSource != nil {
		snapshot, err := a.snapshotSource.Snapshot(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("snapshot: %w", err))
		} else {
			for _, finding := range snapshot.Findings {
				if err := a.repository.SyncFinding(ctx, finding); err != nil {
					errs = append(errs, fmt.Errorf("sync native finding %s: %w", finding.ID, err))
				}
			}
		}
	}
	if a.adapterManager != nil {
		collection := a.adapterManager.Collect(ctx)
		for _, finding := range collection.Findings {
			if err := a.repository.SyncFinding(ctx, finding); err != nil {
				errs = append(errs, fmt.Errorf("sync adapter finding %s: %w", finding.ID, err))
			}
		}
	}
	return errors.Join(errs...)
}

func (a *Agent) processFinding(ctx context.Context, finding core.Finding) CycleReport {
	report := CycleReport{}
	a.logger.Info("ai agent processing finding", "finding_id", finding.ID, "risk_score", finding.RiskScore, "source", finding.Source)
	a.notify(ctx, Event{Type: "finding.detected", Message: "AI agent detected an actionable finding", Finding: &finding}, &report)
	if !a.config.AutoPlan {
		return report
	}

	plan, err := a.repository.CreateRemediationPlanFromFinding(ctx, finding, a.config.Actor, idempotencyKey(finding))
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("create plan for %s: %v", finding.ID, err))
		a.notify(ctx, Event{Type: "agent.error", Message: "AI agent could not create a typed plan", Finding: &finding}, &report)
		return report
	}
	report.PlansCreated++
	a.logger.Info("ai agent created deterministic plan", "finding_id", finding.ID, "plan_id", plan.ID, "risk_tier", plan.RiskTier, "approval_required", plan.ApprovalPolicy.Required)

	if plan.AI == nil {
		analysis, err := a.advisor.Analyze(ctx, finding, plan)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("analyze finding %s: %v", finding.ID, err))
			a.notify(ctx, Event{Type: "ai.analysis_failed", Message: "OpenAI analysis failed; deterministic plan remains available", Finding: &finding, Plan: &plan}, &report)
			return report
		}
		plan.AI = &analysis
		if err := a.repository.SyncRemediationPlan(ctx, plan); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("persist AI plan %s: %v", plan.ID, err))
			return report
		}
		a.logger.Info("ai agent attached AI analysis", "finding_id", finding.ID, "plan_id", plan.ID, "provider", analysis.Provider, "model", analysis.Model, "confidence", analysis.Confidence)
	}
	if a.workflow != nil {
		if err := a.workflow.CreatePlan(ctx, finding, plan, a.config.Actor); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("persist workflow plan %s: %v", plan.ID, err))
			a.notify(ctx, Event{Type: "agent.error", Message: "AI agent could not persist the workflow plan", Finding: &finding, Plan: &plan}, &report)
			return report
		}
	}
	a.notify(ctx, Event{Type: "remediation.plan.created", Message: "AI agent created a typed remediation plan", Finding: &finding, Plan: &plan}, &report)

	if a.shouldAutoExecute(plan) {
		run, err := a.requestExecution(ctx, plan.ID)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("request execution %s: %v", plan.ID, err))
			a.notify(ctx, Event{Type: "agent.error", Message: "AI agent could not request safe Tier A execution", Finding: &finding, Plan: &plan}, &report)
			return report
		}
		report.Executions++
		a.notify(ctx, Event{Type: "remediation.execution_requested", Message: "AI agent requested safe Tier A execution", Finding: &finding, Plan: &plan, Run: &run}, &report)
		return report
	}
	if plan.ApprovalPolicy.Required {
		a.notify(ctx, Event{Type: "approval.required", Message: "AI agent prepared a plan that requires human approval", Finding: &finding, Plan: &plan}, &report)
	}
	return report
}

func (a *Agent) requestExecution(ctx context.Context, planID string) (core.RemediationRun, error) {
	if a.workflow != nil {
		if _, err := a.workflow.RequestExecution(ctx, planID, a.config.Actor); err != nil {
			return core.RemediationRun{}, err
		}
	}
	return a.repository.ExecuteRemediationPlan(ctx, planID, a.config.Actor)
}

func (a *Agent) shouldAutoExecute(plan core.RemediationPlan) bool {
	return a.config.AutoExecuteTierA && plan.RiskTier == core.RiskTierA && !plan.ApprovalPolicy.Required
}

func (a *Agent) notify(ctx context.Context, event Event, report *CycleReport) {
	if a.notifier == nil {
		return
	}
	event.GeneratedAt = time.Now().UTC()
	notifyCtx, cancel := context.WithTimeout(ctx, a.config.NotificationTimeout)
	defer cancel()
	if err := a.notifier.Notify(notifyCtx, event); err != nil {
		a.logger.Warn("ai agent notification failed", "type", event.Type, "error", err)
		return
	}
	report.Notifications++
}

func (a *Agent) alreadyProcessed(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.processed[key]
	return ok
}

func (a *Agent) markProcessed(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.processed[key] = struct{}{}
}

type WebhookNotifier struct {
	url    string
	client *http.Client
}

func NewWebhookNotifier(url string, timeout time.Duration, client *http.Client) *WebhookNotifier {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &WebhookNotifier{url: strings.TrimSpace(url), client: client}
}

func (n *WebhookNotifier) Notify(ctx context.Context, event Event) error {
	if n == nil || n.url == "" {
		return nil
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := n.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("webhook returned %d", response.StatusCode)
	}
	return nil
}

func activeFindings(findings []core.Finding, minRisk int) []core.Finding {
	result := make([]core.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.RiskScore < minRisk || finding.Fixability == core.FixabilityInformational {
			continue
		}
		if finding.Status != core.FindingOpen && finding.Status != core.FindingInReview {
			continue
		}
		result = append(result, finding)
	}
	return result
}

func idempotencyKey(finding core.Finding) string {
	return "ai-agent-" + safeKey(finding.ID+"-"+findingFingerprint(finding))
}

func findingEventKey(finding core.Finding) string {
	return finding.ID + "|" + findingFingerprint(finding)
}

func findingFingerprint(finding core.Finding) string {
	type stableEvidence struct {
		Summary  string `json:"summary"`
		Details  string `json:"details"`
		SourceID string `json:"sourceId"`
	}
	evidence := make([]stableEvidence, 0, len(finding.Evidence))
	for _, item := range finding.Evidence {
		evidence = append(evidence, stableEvidence{Summary: item.Summary, Details: item.Details, SourceID: item.SourceID})
	}
	payload := struct {
		ID                string               `json:"id"`
		Source            string               `json:"source"`
		Title             string               `json:"title"`
		Severity          core.Severity        `json:"severity"`
		Evidence          []stableEvidence     `json:"evidence"`
		Resources         []core.ResourceRef   `json:"resources"`
		BlastRadius       string               `json:"blastRadius"`
		Fixability        core.Fixability      `json:"fixability"`
		CorrelationGroup  string               `json:"correlationGroup"`
		CorrelationKeys   core.CorrelationKeys `json:"correlationKeys"`
		RiskScore         int                  `json:"riskScore"`
		RecommendedAction string               `json:"recommendedAction"`
	}{
		ID: finding.ID, Source: finding.Source, Title: finding.Title, Severity: finding.Severity,
		Evidence: evidence, Resources: finding.Resources, BlastRadius: finding.BlastRadius,
		Fixability: finding.Fixability, CorrelationGroup: finding.CorrelationGroup,
		CorrelationKeys: finding.CorrelationKeys, RiskScore: finding.RiskScore,
		RecommendedAction: finding.RecommendedAction,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "unavailable"
	}
	digest := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", digest[:12])
}

func safeKey(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			builder.WriteRune(r)
		} else {
			builder.WriteByte('-')
		}
		if builder.Len() >= 96 {
			break
		}
	}
	key := strings.Trim(builder.String(), "-_.")
	if len(key) < 8 {
		return "ai-agent-event"
	}
	return key
}
