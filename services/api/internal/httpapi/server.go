package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/atharvaai/kubeathrix/pkg/actioncatalog"
	"github.com/atharvaai/kubeathrix/services/api/internal/adapters"
	"github.com/atharvaai/kubeathrix/services/api/internal/auth"
	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	findinglogic "github.com/atharvaai/kubeathrix/services/api/internal/findings"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
)

type ClusterInspector interface {
	Snapshot(ctx context.Context) (core.ClusterSnapshot, error)
}

type ChaosManager interface {
	Health(ctx context.Context) error
	TargetNamespace(manifest string) (string, error)
	Request(ctx context.Context, experimentID, manifest, actor string) (core.ChaosExperimentRun, error)
	Approve(ctx context.Context, id, actor, reason string) (core.ChaosExperimentRun, error)
	Reject(ctx context.Context, id, actor, reason string) (core.ChaosExperimentRun, error)
	Execute(ctx context.Context, id, actor string) (core.ChaosExperimentRun, error)
	Abort(ctx context.Context, id, actor, reason string) (core.ChaosExperimentRun, error)
	Get(ctx context.Context, id string) (core.ChaosExperimentRun, error)
	List(ctx context.Context) ([]core.ChaosExperimentRun, error)
}

type WorkflowClient interface {
	Health(ctx context.Context) error
	ListFindings(ctx context.Context) ([]core.Finding, error)
	GetFinding(ctx context.Context, findingID string) (core.Finding, error)
	ListRuns(ctx context.Context) ([]core.RemediationRun, error)
	CreatePlan(ctx context.Context, finding core.Finding, plan core.RemediationPlan, actor string) error
	DecideApproval(ctx context.Context, approvalID string, decision core.ApprovalStatus, actor, reason string) (core.ApprovalRequest, error)
	RequestExecution(ctx context.Context, planID, actor string) (core.RemediationRun, error)
	RequestRollback(ctx context.Context, runID, actor string) (core.RemediationRun, error)
	GetRun(ctx context.Context, runID string) (core.RemediationRun, error)
	RenderDiff(ctx context.Context, plan core.RemediationPlan) (core.RemediationDiff, error)
}

type exceptionWorkflowClient interface {
	CreateException(ctx context.Context, exception core.Exception) error
	DeleteException(ctx context.Context, id string) error
}

type findingLifecycleWorkflowClient interface {
	SetFindingStatus(ctx context.Context, finding core.Finding, status core.FindingStatus, actor, reason string) error
}

type AdapterManager interface {
	Collect(ctx context.Context) adapters.Collection
}

type Config struct {
	InsecureDevAuth      bool
	OIDCIssuerURL        string
	OIDCClientID         string
	Authenticator        auth.Verifier
	ClusterID            string
	MaxRequestBytes      int64
	RateLimitPerMinute   int
	Logger               *slog.Logger
	ClusterInspector     ClusterInspector
	ChaosManager         ChaosManager
	WorkflowClient       WorkflowClient
	AllowMemoryWorkflows bool
	AdapterManager       AdapterManager
	RiskConfig           findinglogic.Config
	FindingExpiry        time.Duration
}

type Server struct {
	repository       store.Repository
	config           Config
	clusterInspector ClusterInspector
	chaosManager     ChaosManager
	workflowClient   WorkflowClient
	adapterManager   AdapterManager
	limiter          *requestLimiter
	logger           *slog.Logger
	metrics          *apiMetrics
}

func NewServer(repository store.Repository, config Config) *Server {
	if config.ClusterID == "" {
		config.ClusterID = "default"
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{repository: repository, config: config, clusterInspector: config.ClusterInspector, chaosManager: config.ChaosManager, workflowClient: config.WorkflowClient, adapterManager: config.AdapterManager, limiter: newRequestLimiter(config.RateLimitPerMinute), logger: logger, metrics: newAPIMetrics()}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.liveness)
	mux.HandleFunc("GET /health/ready", s.readiness)
	mux.HandleFunc("GET /auth/config", s.authConfig)
	mux.HandleFunc("GET /api/health", requireRole(auth.RoleViewer, s.health))
	mux.HandleFunc("GET /api/metrics", requireRole(auth.RoleViewer, s.prometheusMetrics))
	mux.HandleFunc("GET /api/action-catalog", requireRole(auth.RoleViewer, s.actionCatalog))
	mux.HandleFunc("GET /api/dashboard", requireRole(auth.RoleViewer, s.dashboard))
	mux.HandleFunc("GET /api/findings", requireRole(auth.RoleViewer, s.listFindings))
	mux.HandleFunc("GET /api/findings/{id}", requireRole(auth.RoleViewer, s.getFinding))
	mux.HandleFunc("PATCH /api/findings/{id}/status", requireRole(auth.RoleOperator, s.updateFindingStatus))
	mux.HandleFunc("GET /api/exceptions", requireRole(auth.RoleViewer, s.listExceptions))
	mux.HandleFunc("POST /api/exceptions", requireRole(auth.RoleOperator, s.createException))
	mux.HandleFunc("DELETE /api/exceptions/{id}", requireRole(auth.RoleOperator, s.deleteException))
	mux.HandleFunc("POST /api/remediation-plans/preview", requireRole(auth.RoleOperator, s.previewRemediationPlan))
	mux.HandleFunc("POST /api/remediation-plans", requireRole(auth.RoleOperator, s.createRemediationPlan))
	mux.HandleFunc("GET /api/remediation-plans/{id}/diff", requireRole(auth.RoleViewer, s.getRemediationPlanDiff))
	mux.HandleFunc("POST /api/remediation-plans/{id}/execute", requireRole(auth.RoleOperator, s.executeRemediationPlan))
	mux.HandleFunc("GET /api/remediation-runs/{id}", requireRole(auth.RoleViewer, s.getRemediationRun))
	mux.HandleFunc("POST /api/remediation-runs/{id}/rollback", requireRole(auth.RoleOperator, s.rollbackRemediationRun))
	mux.HandleFunc("POST /api/approvals/{id}/approve", requireRole(auth.RoleApprover, s.approve))
	mux.HandleFunc("POST /api/approvals/{id}/reject", requireRole(auth.RoleApprover, s.reject))
	mux.HandleFunc("GET /api/audit-events", requireRole(auth.RoleViewer, s.auditEvents))
	mux.HandleFunc("GET /api/evidence-bundles/{scope}", requireRole(auth.RoleViewer, s.evidenceBundle))
	mux.HandleFunc("GET /api/integrations", requireRole(auth.RoleViewer, s.integrations))
	mux.HandleFunc("GET /api/integrations/{name}/health", requireRole(auth.RoleViewer, s.integrationHealth))
	mux.HandleFunc("GET /api/experiments", requireRole(auth.RoleViewer, s.experiments))
	mux.HandleFunc("POST /api/experiments/{id}/runs", requireRole(auth.RoleOperator, s.startExperiment))
	mux.HandleFunc("GET /api/experiment-runs", requireRole(auth.RoleViewer, s.listExperimentRuns))
	mux.HandleFunc("GET /api/experiment-runs/{id}", requireRole(auth.RoleViewer, s.getExperimentRun))
	mux.HandleFunc("POST /api/experiment-runs/{id}/approve", requireRole(auth.RoleApprover, s.approveExperimentRun))
	mux.HandleFunc("POST /api/experiment-runs/{id}/reject", requireRole(auth.RoleApprover, s.rejectExperimentRun))
	mux.HandleFunc("POST /api/experiment-runs/{id}/execute", requireRole(auth.RoleOperator, s.executeExperimentRun))
	mux.HandleFunc("POST /api/experiment-runs/{id}/abort", requireRole(auth.RoleOperator, s.abortExperimentRun))
	mux.HandleFunc("GET /api/settings/model-providers", requireRole(auth.RoleAdministrator, s.getModelProviders))
	mux.HandleFunc("PUT /api/settings/model-providers", requireRole(auth.RoleAdministrator, s.putModelProviders))
	handler := withJSON(mux)
	handler = s.withRateLimit(handler)
	handler = s.withAuthentication(handler)
	handler = withRequestBodyLimit(s.config.MaxRequestBytes, handler)
	handler = s.withRequestLogging(handler)
	handler = withRecovery(s.logger, handler)
	handler = withSecurityHeaders(handler)
	handler = withRequestID(handler)
	return handler
}

func (s *Server) liveness(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
}

func (s *Server) authConfig(w http.ResponseWriter, _ *http.Request) {
	mode := "oidc"
	if s.config.InsecureDevAuth {
		mode = "development"
	}
	writeJSON(w, http.StatusOK, map[string]string{"mode": mode, "issuerURL": s.config.OIDCIssuerURL, "clientID": s.config.OIDCClientID})
}

func (s *Server) readiness(w http.ResponseWriter, r *http.Request) {
	if err := s.repository.Health(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("repository is not ready"))
		return
	}
	if !s.config.InsecureDevAuth && s.config.Authenticator == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("authentication is not configured"))
		return
	}
	if s.workflowClient == nil && !s.config.AllowMemoryWorkflows {
		writeError(w, http.StatusServiceUnavailable, errors.New("Kubernetes workflow client is not configured"))
		return
	}
	if s.chaosManager != nil {
		if err := s.chaosManager.Health(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("chaos execution dependency is not ready"))
			return
		}
	}
	if s.workflowClient != nil {
		if err := s.workflowClient.Health(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("Kubernetes workflow API is not ready"))
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.repository.Health(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "ok",
		"insecureDevAuth": s.config.InsecureDevAuth,
		"oidcConfigured":  s.config.OIDCIssuerURL != "" && s.config.OIDCClientID != "",
		"clusterId":       s.config.ClusterID,
	})
}

func (s *Server) actionCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": actioncatalog.Version, "actions": actioncatalog.All()})
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	if !s.requireClusterAccess(w, r) {
		return
	}
	s.syncWorkflowState(r.Context())
	s.expireStaleFindings(r.Context())
	dashboard, err := s.repository.Dashboard(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	dashboard = s.enrichDashboard(r.Context(), dashboard)
	writeJSON(w, http.StatusOK, dashboard)
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	s.expireStaleFindings(r.Context())
	minRisk, err := queryInt(r, "minRisk", 0, 0, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	filter := store.FindingFilter{
		Severity:   r.URL.Query().Get("severity"),
		Status:     r.URL.Query().Get("status"),
		Source:     r.URL.Query().Get("source"),
		Query:      r.URL.Query().Get("q"),
		Namespace:  r.URL.Query().Get("namespace"),
		Kind:       r.URL.Query().Get("kind"),
		Fixability: r.URL.Query().Get("fixability"),
		MinRisk:    minRisk,
	}
	findings, err := s.repository.ListFindings(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	findings = s.mergeLiveFindings(r.Context(), findings, filter)
	findings = s.mergeAdapterFindings(r.Context(), findings, filter)
	findings = s.mergeWorkflowFindings(r.Context(), findings, filter)
	findings = s.filterAuthorizedFindings(r, findings)
	riskConfig := s.config.RiskConfig
	if riskConfig.CriticalBase == 0 {
		riskConfig = findinglogic.DefaultConfig()
	}
	findings = findinglogic.CorrelateWithConfig(findings, riskConfig)
	for _, finding := range findings {
		if err := s.repository.SyncFinding(r.Context(), finding); err != nil {
			s.logger.Error("failed to persist correlated finding", "finding_id", finding.ID, "error", err)
		}
	}
	if err := sortFindings(findings, r.URL.Query().Get("sort"), r.URL.Query().Get("order")); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	response := core.FindingListResponse{Total: len(findings)}
	if groupBy := r.URL.Query().Get("groupBy"); groupBy != "" {
		groups, err := groupFindings(findings, groupBy)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		response.Groups = groups
	}
	limit, err := queryInt(r, "limit", 50, 1, 200)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	start, err := cursorStart(findings, r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	end := min(start+limit, len(findings))
	response.Items = findings[start:end]
	if response.Items == nil {
		response.Items = []core.Finding{}
	}
	if end < len(findings) {
		response.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(findings[end-1].ID))
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) expireStaleFindings(ctx context.Context) {
	if s.config.FindingExpiry <= 0 {
		return
	}
	if err := s.repository.ExpireFindings(ctx, time.Now().UTC().Add(-s.config.FindingExpiry)); err != nil {
		s.logger.Error("failed to expire stale findings", "error", err)
	}
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	finding, err := s.getFindingByID(r.Context(), r.PathValue("id"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	if !s.requireFindingAccess(w, r, finding) {
		return
	}
	writeJSON(w, http.StatusOK, finding)
}

func (s *Server) updateFindingStatus(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Status core.FindingStatus `json:"status"`
		Reason string             `json:"reason"`
	}
	if !decodeStrict(w, r, &request) {
		return
	}
	finding, err := s.getFindingByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	if !s.requireFindingAccess(w, r, finding) {
		return
	}
	actor, reason := actorFromRequest(r), strings.TrimSpace(request.Reason)
	if workflow, ok := s.workflowClient.(findingLifecycleWorkflowClient); ok {
		if err := workflow.SetFindingStatus(r.Context(), finding, request.Status, actor, reason); err != nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("finding lifecycle state could not be persisted to Kubernetes"))
			return
		}
	}
	updated, err := s.repository.UpdateFindingStatus(r.Context(), finding.ID, request.Status, actor, reason)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrInvalid) {
			status = http.StatusBadRequest
		} else if errors.Is(err, store.ErrConflict) {
			status = http.StatusConflict
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) listExceptions(w http.ResponseWriter, r *http.Request) {
	items, err := s.repository.ListExceptions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	if !principal.CanAccessCluster(s.config.ClusterID) {
		filtered := make([]core.Exception, 0, len(items))
		for _, exception := range items {
			finding, findErr := s.getFindingByID(r.Context(), exception.Scope)
			if findErr == nil && findingAllowed(principal, s.config.ClusterID, finding) {
				filtered = append(filtered, exception)
			}
		}
		items = filtered
	}
	if items == nil {
		items = []core.Exception{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createException(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Scope     string    `json:"scope"`
		Reason    string    `json:"reason"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if !decodeStrict(w, r, &request) {
		return
	}
	request.Scope, request.Reason = strings.TrimSpace(request.Scope), strings.TrimSpace(request.Reason)
	if finding, err := s.getFindingByID(r.Context(), request.Scope); err == nil {
		if !s.requireFindingAccess(w, r, finding) {
			return
		}
	} else if !s.requireClusterAccess(w, r) {
		return
	}
	exception, err := s.repository.CreateException(r.Context(), core.Exception{Scope: request.Scope, Reason: request.Reason, ExpiresAt: request.ExpiresAt}, actorFromRequest(r))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrInvalid) {
			status = http.StatusBadRequest
		}
		writeError(w, status, err)
		return
	}
	if workflow, ok := s.workflowClient.(exceptionWorkflowClient); ok {
		if err := workflow.CreateException(r.Context(), exception); err != nil {
			_ = s.repository.DeleteException(r.Context(), exception.ID, actorFromRequest(r))
			writeError(w, http.StatusServiceUnavailable, errors.New("exception could not be persisted to Kubernetes workflow state"))
			return
		}
	}
	writeJSON(w, http.StatusCreated, exception)
}

func (s *Server) deleteException(w http.ResponseWriter, r *http.Request) {
	items, err := s.repository.ListExceptions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	var target *core.Exception
	for index := range items {
		if items[index].ID == r.PathValue("id") {
			target = &items[index]
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	if finding, findErr := s.getFindingByID(r.Context(), target.Scope); findErr == nil {
		if !s.requireFindingAccess(w, r, finding) {
			return
		}
	} else if !s.requireClusterAccess(w, r) {
		return
	}
	if workflow, ok := s.workflowClient.(exceptionWorkflowClient); ok {
		if err := workflow.DeleteException(r.Context(), target.ID); err != nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("exception could not be deleted from Kubernetes workflow state"))
			return
		}
	}
	if err := s.repository.DeleteException(r.Context(), target.ID, actorFromRequest(r)); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) previewRemediationPlan(w http.ResponseWriter, r *http.Request) {
	var request struct {
		FindingID string `json:"findingId"`
	}
	if !decodeStrict(w, r, &request) {
		return
	}
	if request.FindingID == "" {
		writeError(w, http.StatusBadRequest, errors.New("findingId is required"))
		return
	}
	finding, err := s.getFindingByID(r.Context(), request.FindingID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	if !s.requireFindingAccess(w, r, finding) {
		return
	}
	requester := actorFromRequest(r)
	preview, err := s.repository.PreviewRemediationPlan(r.Context(), request.FindingID, requester)
	if errors.Is(err, store.ErrNotFound) {
		now := time.Now().UTC()
		plan := store.BuildRemediationPlan(finding, requester, now, 0)
		plan.ID = "preview-" + finding.ID
		preview = store.BuildRemediationPreview(finding, plan, now)
		err = nil
	}
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (s *Server) createRemediationPlan(w http.ResponseWriter, r *http.Request) {
	var request struct {
		FindingID string `json:"findingId"`
	}
	if !decodeStrict(w, r, &request) {
		return
	}
	if request.FindingID == "" {
		writeError(w, http.StatusBadRequest, errors.New("findingId is required"))
		return
	}
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if !validRequestID(idempotencyKey) {
		writeError(w, http.StatusBadRequest, errors.New("Idempotency-Key is required and must contain 8 to 128 URL-safe characters"))
		return
	}
	w.Header().Set("Idempotency-Key", idempotencyKey)
	finding, err := s.getFindingByID(r.Context(), request.FindingID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	if !s.requireFindingAccess(w, r, finding) {
		return
	}
	plan, err := s.repository.CreateRemediationPlanFromFinding(r.Context(), finding, actorFromRequest(r), idempotencyKey)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		} else if errors.Is(err, store.ErrConflict) {
			status = http.StatusConflict
		}
		writeError(w, status, err)
		return
	}
	if s.workflowClient == nil && !s.config.AllowMemoryWorkflows {
		writeError(w, http.StatusServiceUnavailable, errors.New("Kubernetes workflow persistence is required"))
		return
	}
	if s.workflowClient != nil {
		if err := s.workflowClient.CreatePlan(r.Context(), finding, plan, actorFromRequest(r)); err != nil {
			s.logger.Error("failed to persist remediation workflow CRDs", "request_id", w.Header().Get("X-Request-ID"), "plan_id", plan.ID, "error", err)
			writeError(w, http.StatusServiceUnavailable, errors.New("Kubernetes workflow persistence failed"))
			return
		}
	}
	writeJSON(w, http.StatusCreated, plan)
}

func (s *Server) getRemediationPlanDiff(w http.ResponseWriter, r *http.Request) {
	if !s.requirePlanAccess(w, r, r.PathValue("id")) {
		return
	}
	plan, err := s.repository.GetRemediationPlan(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	var diff core.RemediationDiff
	if s.workflowClient != nil {
		diff, err = s.workflowClient.RenderDiff(r.Context(), plan)
	} else {
		diff, err = s.repository.GetRemediationPlanDiff(r.Context(), r.PathValue("id"))
	}
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, diff)
}

func (s *Server) executeRemediationPlan(w http.ResponseWriter, r *http.Request) {
	var request struct{}
	if !decodeStrict(w, r, &request) {
		return
	}
	if !s.requirePlanAccess(w, r, r.PathValue("id")) {
		return
	}
	var clusterRun core.RemediationRun
	if s.workflowClient == nil && !s.config.AllowMemoryWorkflows {
		writeError(w, http.StatusServiceUnavailable, errors.New("Kubernetes workflow persistence is required"))
		return
	}
	if s.workflowClient != nil {
		var workflowErr error
		clusterRun, workflowErr = s.workflowClient.RequestExecution(r.Context(), r.PathValue("id"), actorFromRequest(r))
		if workflowErr != nil {
			writeError(w, http.StatusConflict, errors.New("execution request was rejected by Kubernetes workflow state"))
			return
		}
	}
	run, err := s.repository.ExecuteRemediationPlan(r.Context(), r.PathValue("id"), actorFromRequest(r))
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, store.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, store.ErrInvalid):
			status = http.StatusBadRequest
		}
		writeError(w, status, err)
		return
	}
	if s.workflowClient != nil {
		run = clusterRun
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) getRemediationRun(w http.ResponseWriter, r *http.Request) {
	if s.workflowClient != nil {
		run, err := s.workflowClient.GetRun(r.Context(), r.PathValue("id"))
		if err == nil {
			if !s.requirePlanAccess(w, r, run.PlanID) {
				return
			}
			if syncErr := s.repository.SyncRemediationRun(r.Context(), run); syncErr != nil {
				s.logger.Error("failed to mirror remediation run state", "run_id", run.ID, "error", syncErr)
			}
			writeJSON(w, http.StatusOK, run)
			return
		}
	}
	run, err := s.repository.GetRemediationRun(r.Context(), r.PathValue("id"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	if !s.requirePlanAccess(w, r, run.PlanID) {
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) rollbackRemediationRun(w http.ResponseWriter, r *http.Request) {
	var request struct{}
	if !decodeStrict(w, r, &request) {
		return
	}
	if s.workflowClient == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("rollback requires Kubernetes workflow state"))
		return
	}
	current, err := s.workflowClient.GetRun(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	if !s.requirePlanAccess(w, r, current.PlanID) {
		return
	}
	run, err := s.workflowClient.RequestRollback(r.Context(), r.PathValue("id"), actorFromRequest(r))
	if err != nil {
		writeError(w, http.StatusConflict, errors.New("run is not eligible for rollback or has no controller snapshot"))
		return
	}
	if _, err := s.repository.RequestRollback(r.Context(), r.PathValue("id"), actorFromRequest(r)); err != nil {
		s.logger.Error("failed to mirror rollback request", "request_id", w.Header().Get("X-Request-ID"), "run_id", r.PathValue("id"), "error", err)
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	s.decideApproval(w, r, true)
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request) {
	s.decideApproval(w, r, false)
}

func (s *Server) decideApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	var request struct {
		Reason string `json:"reason"`
	}
	if !decodeStrict(w, r, &request) {
		return
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Reason == "" || len(request.Reason) > 2048 {
		writeError(w, http.StatusBadRequest, errors.New("a decision reason between 1 and 2048 characters is required"))
		return
	}
	var (
		approval core.ApprovalRequest
		err      error
	)
	planID := strings.TrimPrefix(r.PathValue("id"), "approval-")
	if planID == r.PathValue("id") || !s.requirePlanAccess(w, r, planID) {
		if planID == r.PathValue("id") {
			writeError(w, http.StatusBadRequest, errors.New("invalid approval id"))
		}
		return
	}
	actor := actorFromRequest(r)
	decision := core.ApprovalRejected
	if approve {
		decision = core.ApprovalApproved
	}
	if s.workflowClient == nil && !s.config.AllowMemoryWorkflows {
		writeError(w, http.StatusServiceUnavailable, errors.New("Kubernetes workflow persistence is required"))
		return
	}
	if s.workflowClient != nil {
		if _, workflowErr := s.workflowClient.DecideApproval(r.Context(), r.PathValue("id"), decision, actor, request.Reason); workflowErr != nil {
			writeError(w, http.StatusConflict, errors.New("approval decision was rejected by Kubernetes workflow state"))
			return
		}
	}
	if approve {
		approval, err = s.repository.Approve(r.Context(), r.PathValue("id"), actor, request.Reason)
	} else {
		approval, err = s.repository.Reject(r.Context(), r.PathValue("id"), actor, request.Reason)
	}
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, store.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, store.ErrInvalid):
			status = http.StatusBadRequest
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, approval)
}

func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	if !s.requireClusterAccess(w, r) {
		return
	}
	events, err := s.repository.ListAuditEvents(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if events == nil {
		events = []core.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": events})
}

func (s *Server) evidenceBundle(w http.ResponseWriter, r *http.Request) {
	if !s.requireClusterAccess(w, r) {
		return
	}
	bundle, err := s.repository.EvidenceBundle(r.Context(), pathValue(r, "scope"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) integrations(w http.ResponseWriter, r *http.Request) {
	if !s.requireClusterAccess(w, r) {
		return
	}
	if s.adapterManager != nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": s.adapterManager.Collect(r.Context()).Integrations})
		return
	}
	integrations, err := s.repository.ListIntegrations(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if integrations == nil {
		integrations = []core.Integration{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": integrations})
}

func (s *Server) integrationHealth(w http.ResponseWriter, r *http.Request) {
	if !s.requireClusterAccess(w, r) {
		return
	}
	if s.adapterManager != nil {
		requested := normalizeName(pathValue(r, "name"))
		for _, health := range s.adapterManager.Collect(r.Context()).Health {
			if normalizeName(health.Name) == requested {
				writeJSON(w, http.StatusOK, health)
				return
			}
		}
		writeError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	health, err := s.repository.IntegrationHealth(r.Context(), pathValue(r, "name"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, health)
}

func (s *Server) experiments(w http.ResponseWriter, r *http.Request) {
	if !s.requireClusterAccess(w, r) {
		return
	}
	experiments := core.DefaultChaosExperiments()
	if snapshot, ok := s.snapshot(r.Context()); ok && len(snapshot.Experiments) > 0 {
		experiments = snapshot.Experiments
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": experiments})
}

func (s *Server) startExperiment(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Manifest string `json:"manifest"`
	}
	if !decodeStrict(w, r, &request) {
		return
	}
	experimentID := r.PathValue("id")
	experiment, ok := findExperiment(core.DefaultChaosExperiments(), experimentID)
	if !ok && experimentID != "custom" {
		writeError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	manifest := request.Manifest
	if manifest == "" && ok {
		manifest = experiment.Manifest
	}
	if manifest == "" {
		writeError(w, http.StatusBadRequest, errors.New("manifest is required"))
		return
	}
	if s.chaosManager == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("chaos manager is not configured"))
		return
	}
	namespace, err := s.chaosManager.TargetNamespace(manifest)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	if !principal.CanAccessNamespace(s.config.ClusterID, namespace) {
		writeError(w, http.StatusForbidden, auth.ErrUnauthorized)
		return
	}
	run, err := s.chaosManager.Request(r.Context(), experimentID, manifest, actorFromRequest(r))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, run)
}

func (s *Server) listExperimentRuns(w http.ResponseWriter, r *http.Request) {
	if s.chaosManager == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("chaos manager is not configured"))
		return
	}
	runs, err := s.chaosManager.List(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	filtered := make([]core.ChaosExperimentRun, 0, len(runs))
	for _, run := range runs {
		if principal.CanAccessNamespace(s.config.ClusterID, run.Resource.Namespace) {
			filtered = append(filtered, run)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": filtered})
}

func (s *Server) getExperimentRun(w http.ResponseWriter, r *http.Request) {
	run, ok := s.authorizedExperimentRun(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) approveExperimentRun(w http.ResponseWriter, r *http.Request) {
	s.decideExperimentRun(w, r, true)
}

func (s *Server) rejectExperimentRun(w http.ResponseWriter, r *http.Request) {
	s.decideExperimentRun(w, r, false)
}

func (s *Server) decideExperimentRun(w http.ResponseWriter, r *http.Request, approve bool) {
	if _, ok := s.authorizedExperimentRun(w, r); !ok {
		return
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if !decodeStrict(w, r, &request) {
		return
	}
	var run core.ChaosExperimentRun
	var err error
	if approve {
		run, err = s.chaosManager.Approve(r.Context(), r.PathValue("id"), actorFromRequest(r), request.Reason)
	} else {
		run, err = s.chaosManager.Reject(r.Context(), r.PathValue("id"), actorFromRequest(r), request.Reason)
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) executeExperimentRun(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizedExperimentRun(w, r); !ok {
		return
	}
	run, err := s.chaosManager.Execute(r.Context(), r.PathValue("id"), actorFromRequest(r))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) abortExperimentRun(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizedExperimentRun(w, r); !ok {
		return
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if !decodeStrict(w, r, &request) {
		return
	}
	run, err := s.chaosManager.Abort(r.Context(), r.PathValue("id"), actorFromRequest(r), request.Reason)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) authorizedExperimentRun(w http.ResponseWriter, r *http.Request) (core.ChaosExperimentRun, bool) {
	if s.chaosManager == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("chaos manager is not configured"))
		return core.ChaosExperimentRun{}, false
	}
	run, err := s.chaosManager.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return core.ChaosExperimentRun{}, false
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	if !principal.CanAccessNamespace(s.config.ClusterID, run.Resource.Namespace) {
		writeError(w, http.StatusForbidden, auth.ErrUnauthorized)
		return core.ChaosExperimentRun{}, false
	}
	return run, true
}

func (s *Server) getModelProviders(w http.ResponseWriter, r *http.Request) {
	settings, err := s.repository.GetModelProviders(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) putModelProviders(w http.ResponseWriter, r *http.Request) {
	var settings core.ModelProviderSettings
	if !decodeStrict(w, r, &settings) {
		return
	}
	updated, err := s.repository.SaveModelProviders(r.Context(), settings)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrInvalid) {
			status = http.StatusBadRequest
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func decodeStrict(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
		if contentType != "application/json" {
			writeError(w, http.StatusUnsupportedMediaType, errors.New("Content-Type must be application/json"))
			return false
		}
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, errors.New("request body is too large"))
		} else {
			writeError(w, http.StatusBadRequest, errors.New("request body must be valid JSON matching the documented schema"))
		}
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, errors.New("request body must contain exactly one JSON document"))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	message := err.Error()
	if status >= http.StatusInternalServerError && status != http.StatusServiceUnavailable {
		message = "internal server error"
	}
	writeJSON(w, status, map[string]any{"error": map[string]string{
		"code":      errorCode(status),
		"message":   message,
		"requestId": w.Header().Get("X-Request-ID"),
	}})
}

func writeStoreError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, store.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, store.ErrInvalid):
		status = http.StatusBadRequest
	case errors.Is(err, store.ErrConflict):
		status = http.StatusConflict
	}
	writeError(w, status, err)
}

func errorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthenticated"
	case http.StatusForbidden:
		return "permission_denied"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusUnsupportedMediaType:
		return "unsupported_media_type"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusServiceUnavailable:
		return "unavailable"
	default:
		return "internal_error"
	}
}

func (s *Server) enrichDashboard(ctx context.Context, dashboard core.Dashboard) core.Dashboard {
	ensureDashboardMaps(&dashboard)
	dashboard.Experiments = core.DefaultChaosExperiments()
	persisted, err := s.repository.ListFindings(ctx, store.FindingFilter{})
	seen := map[string]bool{}
	if err == nil {
		for _, finding := range persisted {
			seen[finding.ID] = true
		}
	}
	snapshot, ok := s.snapshot(ctx)
	if ok {
		dashboard.Cluster = snapshot.Inventory
		dashboard.Scan = snapshot.Scan
		dashboard.Compliance = snapshot.Compliance
		if len(snapshot.Experiments) > 0 {
			dashboard.Experiments = snapshot.Experiments
		}
		if snapshot.Inventory.Namespaces > dashboard.ProtectedNamespaces {
			dashboard.ProtectedNamespaces = snapshot.Inventory.Namespaces
		}
		dashboard.EvidenceFreshness = freshnessLabel(snapshot.Scan.LastRunAt, time.Now().UTC())
		for _, finding := range snapshot.Findings {
			if seen[finding.ID] {
				continue
			}
			seen[finding.ID] = true
			addFindingToDashboard(&dashboard, finding)
		}
	}
	if s.adapterManager != nil {
		collection := s.adapterManager.Collect(ctx)
		dashboard.BundledEnginesOnline = 0
		for _, health := range collection.Health {
			if health.Health == "healthy" {
				dashboard.BundledEnginesOnline++
			}
		}
		for _, finding := range collection.Findings {
			if seen[finding.ID] {
				continue
			}
			seen[finding.ID] = true
			addFindingToDashboard(&dashboard, finding)
		}
	}
	return dashboard
}

func (s *Server) mergeLiveFindings(ctx context.Context, findings []core.Finding, filter store.FindingFilter) []core.Finding {
	snapshot, ok := s.snapshot(ctx)
	if !ok {
		return findings
	}
	for _, finding := range snapshot.Findings {
		if syncErr := s.repository.SyncFinding(ctx, finding); syncErr != nil {
			s.logger.Error("failed to persist native finding", "finding_id", finding.ID, "error", syncErr)
		}
		findings = mergeObservedFinding(findings, finding, filter)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RiskScore == findings[j].RiskScore {
			return findings[i].UpdatedAt.After(findings[j].UpdatedAt)
		}
		return findings[i].RiskScore > findings[j].RiskScore
	})
	return findings
}

func (s *Server) mergeAdapterFindings(ctx context.Context, findings []core.Finding, filter store.FindingFilter) []core.Finding {
	if s.adapterManager == nil {
		return findings
	}
	for _, finding := range s.adapterManager.Collect(ctx).Findings {
		if syncErr := s.repository.SyncFinding(ctx, finding); syncErr != nil {
			s.logger.Error("failed to persist adapter finding", "finding_id", finding.ID, "error", syncErr)
		}
		findings = mergeObservedFinding(findings, finding, filter)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RiskScore == findings[j].RiskScore {
			return findings[i].UpdatedAt.After(findings[j].UpdatedAt)
		}
		return findings[i].RiskScore > findings[j].RiskScore
	})
	return findings
}

func mergeObservedFinding(existing []core.Finding, observed core.Finding, filter store.FindingFilter) []core.Finding {
	for index := range existing {
		if existing[index].ID != observed.ID {
			continue
		}
		if matchesFilter(observed, filter) {
			existing[index] = observed
			return existing
		}
		return append(existing[:index], existing[index+1:]...)
	}
	if matchesFilter(observed, filter) {
		return append(existing, observed)
	}
	return existing
}

func (s *Server) findLiveFinding(ctx context.Context, id string) (core.Finding, bool) {
	snapshot, ok := s.snapshot(ctx)
	if !ok {
		return core.Finding{}, false
	}
	for _, finding := range snapshot.Findings {
		if finding.ID == id {
			return finding, true
		}
	}
	return core.Finding{}, false
}

func (s *Server) snapshot(ctx context.Context) (core.ClusterSnapshot, bool) {
	if s.clusterInspector == nil {
		return core.ClusterSnapshot{}, false
	}
	snapshot, err := s.clusterInspector.Snapshot(ctx)
	return snapshot, err == nil
}

func addFindingToDashboard(dashboard *core.Dashboard, finding core.Finding) {
	ensureDashboardMaps(dashboard)
	dashboard.TotalFindings++
	dashboard.FindingsBySeverity[string(finding.Severity)]++
	dashboard.FindingsBySource[finding.Source]++
	dashboard.RemediationByState[finding.RemediationState]++
	if finding.Severity == core.SeverityCritical && finding.Status != core.FindingResolved && finding.Status != core.FindingSuppressed {
		dashboard.OpenCritical++
	}
	if finding.RemediationState == "approval_required" {
		dashboard.PendingApprovals++
	}
	if finding.Status == core.FindingRemediating {
		dashboard.ActiveRemediations++
	}
	if finding.Fixability == core.FixabilityDeterministic || finding.Fixability == core.FixabilityGated {
		dashboard.FindingsWithSafeFix++
	}
	if finding.Status == core.FindingResolved {
		dashboard.RiskReduced += finding.RiskScore
	}
	if dashboard.TotalFindings > 0 {
		scoreTotal := int(dashboard.MeanRiskScore * float64(dashboard.TotalFindings-1))
		dashboard.MeanRiskScore = float64(scoreTotal+finding.RiskScore) / float64(dashboard.TotalFindings)
	}
}

func ensureDashboardMaps(dashboard *core.Dashboard) {
	if dashboard.FindingsBySeverity == nil {
		dashboard.FindingsBySeverity = map[string]int{}
	}
	if dashboard.FindingsBySource == nil {
		dashboard.FindingsBySource = map[string]int{}
	}
	if dashboard.RemediationByState == nil {
		dashboard.RemediationByState = map[string]int{}
	}
}

func matchesFilter(finding core.Finding, filter store.FindingFilter) bool {
	if filter.Severity != "" && string(finding.Severity) != filter.Severity {
		return false
	}
	if filter.Status != "" && string(finding.Status) != filter.Status {
		return false
	}
	if filter.Source != "" && finding.Source != filter.Source {
		return false
	}
	if filter.Fixability != "" && string(finding.Fixability) != filter.Fixability {
		return false
	}
	if filter.MinRisk > 0 && finding.RiskScore < filter.MinRisk {
		return false
	}
	if filter.Namespace != "" || filter.Kind != "" {
		matched := false
		for _, resource := range finding.Resources {
			namespace := resource.Namespace
			if resource.Kind == "Namespace" {
				namespace = resource.Name
			}
			if (filter.Namespace == "" || namespace == filter.Namespace) && (filter.Kind == "" || resource.Kind == filter.Kind) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if filter.Query != "" {
		haystack := strings.ToLower(finding.Title + " " + finding.BlastRadius + " " + finding.CorrelationGroup)
		if !strings.Contains(haystack, strings.ToLower(filter.Query)) {
			return false
		}
	}
	return true
}

func queryInt(r *http.Request, name string, fallback, minimum, maximum int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, minimum, maximum)
	}
	return value, nil
}

func cursorStart(findings []core.Finding, encoded string) (int, error) {
	if encoded == "" {
		return 0, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 {
		return 0, errors.New("cursor is invalid")
	}
	for index := range findings {
		if findings[index].ID == string(decoded) {
			return index + 1, nil
		}
	}
	return 0, errors.New("cursor no longer identifies a finding in this result set")
}

func sortFindings(findings []core.Finding, field, order string) error {
	if field == "" {
		field = "risk"
	}
	if order == "" {
		order = "desc"
	}
	if order != "asc" && order != "desc" {
		return errors.New("order must be asc or desc")
	}
	severityRank := map[core.Severity]int{core.SeverityCritical: 5, core.SeverityHigh: 4, core.SeverityMedium: 3, core.SeverityLow: 2, core.SeverityInfo: 1}
	compare := func(left, right core.Finding) int {
		switch field {
		case "risk":
			return left.RiskScore - right.RiskScore
		case "updated":
			if left.UpdatedAt.Before(right.UpdatedAt) {
				return -1
			}
			if left.UpdatedAt.After(right.UpdatedAt) {
				return 1
			}
		case "severity":
			return severityRank[left.Severity] - severityRank[right.Severity]
		case "title":
			return strings.Compare(strings.ToLower(left.Title), strings.ToLower(right.Title))
		case "source":
			return strings.Compare(strings.ToLower(left.Source), strings.ToLower(right.Source))
		default:
			return 0
		}
		return 0
	}
	if field != "risk" && field != "updated" && field != "severity" && field != "title" && field != "source" {
		return errors.New("sort must be risk, updated, severity, title, or source")
	}
	sort.SliceStable(findings, func(i, j int) bool {
		result := compare(findings[i], findings[j])
		if result == 0 {
			return findings[i].ID < findings[j].ID
		}
		if order == "asc" {
			return result < 0
		}
		return result > 0
	})
	return nil
}

func findExperiment(experiments []core.ChaosExperiment, id string) (core.ChaosExperiment, bool) {
	for _, experiment := range experiments {
		if experiment.ID == id {
			return experiment, true
		}
	}
	return core.ChaosExperiment{}, false
}

func groupFindings(findings []core.Finding, groupBy string) ([]core.FindingGroup, error) {
	if groupBy != "workload" && groupBy != "namespace" && groupBy != "owner" {
		return nil, fmt.Errorf("unsupported groupBy %q", groupBy)
	}
	groupsByKey := map[string]*core.FindingGroup{}
	for _, finding := range findings {
		key := groupKey(finding, groupBy)
		group := groupsByKey[key]
		if group == nil {
			group = &core.FindingGroup{GroupBy: groupBy, Key: key, HighestSeverity: finding.Severity}
			groupsByKey[key] = group
		}
		group.Count++
		group.MeanRiskScore += float64(finding.RiskScore)
		group.Findings = append(group.Findings, finding)
		if severityRank(finding.Severity) > severityRank(group.HighestSeverity) {
			group.HighestSeverity = finding.Severity
		}
	}
	groups := make([]core.FindingGroup, 0, len(groupsByKey))
	for _, group := range groupsByKey {
		if group.Count > 0 {
			group.MeanRiskScore = group.MeanRiskScore / float64(group.Count)
		}
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].MeanRiskScore == groups[j].MeanRiskScore {
			return groups[i].Key < groups[j].Key
		}
		return groups[i].MeanRiskScore > groups[j].MeanRiskScore
	})
	return groups, nil
}

func groupKey(finding core.Finding, groupBy string) string {
	if len(finding.Resources) == 0 {
		return "unscoped"
	}
	resource := finding.Resources[0]
	switch groupBy {
	case "namespace":
		if resource.Namespace != "" {
			return resource.Namespace
		}
		if resource.Kind == "Namespace" {
			return resource.Name
		}
	case "owner":
		parts := strings.Split(finding.CorrelationGroup, "-")
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	case "workload":
		if resource.Namespace != "" {
			return resource.Namespace + "/" + resource.Name
		}
		return resource.Name
	}
	return "cluster"
}

func severityRank(severity core.Severity) int {
	switch severity {
	case core.SeverityCritical:
		return 5
	case core.SeverityHigh:
		return 4
	case core.SeverityMedium:
		return 3
	case core.SeverityLow:
		return 2
	default:
		return 1
	}
}

func freshnessLabel(observedAt time.Time, now time.Time) string {
	if observedAt.IsZero() {
		return "no-evidence"
	}
	age := now.Sub(observedAt)
	switch {
	case age <= 15*time.Minute:
		return "fresh"
	case age <= 2*time.Hour:
		return "recent"
	case age <= 24*time.Hour:
		return "stale"
	default:
		return "expired"
	}
}

func pathValue(r *http.Request, name string) string {
	value := r.PathValue(name)
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func normalizeName(value string) string {
	return strings.Trim(strings.NewReplacer(" ", "-", "_", "-", "/", "-").Replace(strings.ToLower(value)), "-")
}

func withJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func actorFromRequest(r *http.Request) string {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		return "unknown"
	}
	return principal.Actor()
}

func (s *Server) requireClusterAccess(w http.ResponseWriter, r *http.Request) bool {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, auth.ErrUnauthenticated)
		return false
	}
	if !principal.CanAccessCluster(s.config.ClusterID) {
		writeError(w, http.StatusForbidden, auth.ErrUnauthorized)
		return false
	}
	return true
}

func (s *Server) requireFindingAccess(w http.ResponseWriter, r *http.Request, finding core.Finding) bool {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, auth.ErrUnauthenticated)
		return false
	}
	if principal.CanAccessCluster(s.config.ClusterID) {
		return true
	}
	if len(finding.Resources) == 0 {
		writeError(w, http.StatusForbidden, auth.ErrUnauthorized)
		return false
	}
	for _, resource := range finding.Resources {
		namespace := resource.Namespace
		if resource.Kind == "Namespace" {
			namespace = resource.Name
		}
		if namespace == "" || !principal.CanAccessNamespace(s.config.ClusterID, namespace) {
			writeError(w, http.StatusForbidden, auth.ErrUnauthorized)
			return false
		}
	}
	return true
}

func (s *Server) filterAuthorizedFindings(r *http.Request, findings []core.Finding) []core.Finding {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		return nil
	}
	if principal.CanAccessCluster(s.config.ClusterID) {
		return findings
	}
	filtered := make([]core.Finding, 0, len(findings))
	for _, finding := range findings {
		if findingAllowed(principal, s.config.ClusterID, finding) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func findingAllowed(principal auth.Principal, clusterID string, finding core.Finding) bool {
	if principal.CanAccessCluster(clusterID) {
		return true
	}
	if len(finding.Resources) == 0 {
		return false
	}
	for _, resource := range finding.Resources {
		namespace := resource.Namespace
		if resource.Kind == "Namespace" {
			namespace = resource.Name
		}
		if namespace == "" || !principal.CanAccessNamespace(clusterID, namespace) {
			return false
		}
	}
	return true
}

func (s *Server) requirePlanAccess(w http.ResponseWriter, r *http.Request, planID string) bool {
	plan, err := s.repository.GetRemediationPlan(r.Context(), planID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return false
	}
	finding, err := s.getFindingByID(r.Context(), plan.FindingID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return false
	}
	return s.requireFindingAccess(w, r, finding)
}

func (s *Server) getFindingByID(ctx context.Context, id string) (core.Finding, error) {
	if s.workflowClient != nil {
		if finding, err := s.workflowClient.GetFinding(ctx, id); err == nil {
			return finding, nil
		}
	}
	finding, err := s.repository.GetFinding(ctx, id)
	if err == nil || !errors.Is(err, store.ErrNotFound) {
		return finding, err
	}
	if liveFinding, ok := s.findLiveFinding(ctx, id); ok {
		return liveFinding, nil
	}
	return core.Finding{}, store.ErrNotFound
}

func (s *Server) mergeWorkflowFindings(ctx context.Context, findings []core.Finding, filter store.FindingFilter) []core.Finding {
	if s.workflowClient == nil {
		return findings
	}
	workflowFindings, err := s.workflowClient.ListFindings(ctx)
	if err != nil {
		return findings
	}
	byID := make(map[string]core.Finding, len(findings)+len(workflowFindings))
	for _, finding := range findings {
		byID[finding.ID] = finding
	}
	for _, finding := range workflowFindings {
		if syncErr := s.repository.SyncFinding(ctx, finding); syncErr != nil {
			s.logger.Error("failed to mirror Finding CRD state", "finding_id", finding.ID, "error", syncErr)
		}
		if matchesFilter(finding, filter) {
			byID[finding.ID] = finding
		} else {
			delete(byID, finding.ID)
		}
	}
	merged := make([]core.Finding, 0, len(byID))
	for _, finding := range byID {
		merged = append(merged, finding)
	}
	sort.Slice(merged, func(i, j int) bool {
		if merged[i].RiskScore == merged[j].RiskScore {
			return merged[i].UpdatedAt.After(merged[j].UpdatedAt)
		}
		return merged[i].RiskScore > merged[j].RiskScore
	})
	return merged
}

func (s *Server) syncWorkflowState(ctx context.Context) {
	if s.workflowClient == nil {
		return
	}
	if findings, err := s.workflowClient.ListFindings(ctx); err == nil {
		for _, finding := range findings {
			if syncErr := s.repository.SyncFinding(ctx, finding); syncErr != nil {
				s.logger.Error("failed to mirror Finding CRD state", "finding_id", finding.ID, "error", syncErr)
			}
		}
	}
	if runs, err := s.workflowClient.ListRuns(ctx); err == nil {
		for _, run := range runs {
			if syncErr := s.repository.SyncRemediationRun(ctx, run); syncErr != nil {
				s.logger.Error("failed to mirror RemediationRun CRD state", "run_id", run.ID, "error", syncErr)
			}
		}
	}
}
