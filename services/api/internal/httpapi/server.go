package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
)

type ClusterInspector interface {
	Snapshot(ctx context.Context) (core.ClusterSnapshot, error)
}

type ChaosRunner interface {
	Run(ctx context.Context, experimentID, manifest string) (core.ChaosExperimentRun, error)
}

type Config struct {
	DevAuthEnabled   bool
	OIDCIssuerURL    string
	OIDCClientID     string
	ClusterInspector ClusterInspector
	ChaosRunner      ChaosRunner
}

type Server struct {
	repository       store.Repository
	config           Config
	clusterInspector ClusterInspector
	chaosRunner      ChaosRunner
}

func NewServer(repository store.Repository, config Config) *Server {
	return &Server{repository: repository, config: config, clusterInspector: config.ClusterInspector, chaosRunner: config.ChaosRunner}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/dashboard", s.dashboard)
	mux.HandleFunc("GET /api/findings", s.listFindings)
	mux.HandleFunc("GET /api/findings/{id}", s.getFinding)
	mux.HandleFunc("POST /api/remediation-plans", s.createRemediationPlan)
	mux.HandleFunc("GET /api/remediation-runs/{id}", s.getRemediationRun)
	mux.HandleFunc("POST /api/approvals/{id}/approve", s.approve)
	mux.HandleFunc("POST /api/approvals/{id}/reject", s.reject)
	mux.HandleFunc("GET /api/audit-events", s.auditEvents)
	mux.HandleFunc("GET /api/integrations", s.integrations)
	mux.HandleFunc("GET /api/experiments", s.experiments)
	mux.HandleFunc("POST /api/experiments/{id}/runs", s.startExperiment)
	mux.HandleFunc("GET /api/settings/model-providers", s.getModelProviders)
	mux.HandleFunc("PUT /api/settings/model-providers", s.putModelProviders)
	return withJSON(withSecurityHeaders(mux))
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.repository.Health(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"devAuthEnabled": s.config.DevAuthEnabled,
		"oidcConfigured": s.config.OIDCIssuerURL != "" && s.config.OIDCClientID != "",
	})
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	dashboard, err := s.repository.Dashboard(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	dashboard = s.enrichDashboard(r.Context(), dashboard)
	writeJSON(w, http.StatusOK, dashboard)
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	filter := store.FindingFilter{
		Severity: r.URL.Query().Get("severity"),
		Status:   r.URL.Query().Get("status"),
		Source:   r.URL.Query().Get("source"),
		Query:    r.URL.Query().Get("q"),
	}
	findings, err := s.repository.ListFindings(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	findings = s.mergeLiveFindings(r.Context(), findings, filter)
	writeJSON(w, http.StatusOK, map[string]any{"items": findings})
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	finding, err := s.repository.GetFinding(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if liveFinding, ok := s.findLiveFinding(r.Context(), r.PathValue("id")); ok {
				writeJSON(w, http.StatusOK, liveFinding)
				return
			}
		}
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, finding)
}

func (s *Server) createRemediationPlan(w http.ResponseWriter, r *http.Request) {
	var request struct {
		FindingID   string `json:"findingId"`
		RequestedBy string `json:"requestedBy"`
	}
	if !decodeStrict(w, r, &request) {
		return
	}
	if request.FindingID == "" {
		writeError(w, http.StatusBadRequest, errors.New("findingId is required"))
		return
	}
	plan, err := s.repository.CreateRemediationPlan(r.Context(), request.FindingID, request.RequestedBy)
	if errors.Is(err, store.ErrNotFound) {
		if liveFinding, ok := s.findLiveFinding(r.Context(), request.FindingID); ok {
			plan, err = s.repository.CreateRemediationPlanFromFinding(r.Context(), liveFinding, request.RequestedBy)
		}
	}
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusCreated, plan)
}

func (s *Server) getRemediationRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.repository.GetRemediationRun(r.Context(), r.PathValue("id"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	s.decideApproval(w, r, true)
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request) {
	s.decideApproval(w, r, false)
}

func (s *Server) decideApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	var request struct {
		Actor  string `json:"actor"`
		Reason string `json:"reason"`
	}
	if !decodeStrict(w, r, &request) {
		return
	}
	var (
		approval core.ApprovalRequest
		err      error
	)
	if approve {
		approval, err = s.repository.Approve(r.Context(), r.PathValue("id"), request.Actor, request.Reason)
	} else {
		approval, err = s.repository.Reject(r.Context(), r.PathValue("id"), request.Actor, request.Reason)
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
	events, err := s.repository.ListAuditEvents(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": events})
}

func (s *Server) integrations(w http.ResponseWriter, r *http.Request) {
	integrations, err := s.repository.ListIntegrations(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": integrations})
}

func (s *Server) experiments(w http.ResponseWriter, r *http.Request) {
	experiments := core.DefaultChaosExperiments()
	if snapshot, ok := s.snapshot(r.Context()); ok && len(snapshot.Experiments) > 0 {
		experiments = snapshot.Experiments
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": experiments})
}

func (s *Server) startExperiment(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Manifest        string `json:"manifest"`
		RequestedBy     string `json:"requestedBy"`
		TargetNamespace string `json:"targetNamespace"`
		TargetName      string `json:"targetName"`
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
	if s.chaosRunner != nil {
		run, err := s.chaosRunner.Run(r.Context(), experimentID, manifest)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusAccepted, run)
		return
	}
	writeJSON(w, http.StatusAccepted, core.ChaosExperimentRun{
		ID:           fmt.Sprintf("chaos-run-%d", time.Now().UTC().UnixNano()),
		ExperimentID: experimentID,
		Status:       "preflight_ready",
		Message:      "experiment manifest accepted; enable the matching chaos engine and execution gate before applying it to the cluster",
		Manifest:     manifest,
		CreatedAt:    time.Now().UTC(),
	})
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
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) enrichDashboard(ctx context.Context, dashboard core.Dashboard) core.Dashboard {
	ensureDashboardMaps(&dashboard)
	dashboard.Experiments = core.DefaultChaosExperiments()
	snapshot, ok := s.snapshot(ctx)
	if !ok {
		return dashboard
	}

	dashboard.Cluster = snapshot.Inventory
	dashboard.Scan = snapshot.Scan
	dashboard.Compliance = snapshot.Compliance
	if len(snapshot.Experiments) > 0 {
		dashboard.Experiments = snapshot.Experiments
	}
	if snapshot.Inventory.Namespaces > dashboard.ProtectedNamespaces {
		dashboard.ProtectedNamespaces = snapshot.Inventory.Namespaces
	}

	persisted, err := s.repository.ListFindings(ctx, store.FindingFilter{})
	seen := map[string]bool{}
	if err == nil {
		for _, finding := range persisted {
			seen[finding.ID] = true
		}
	}
	for _, finding := range snapshot.Findings {
		if seen[finding.ID] {
			continue
		}
		addFindingToDashboard(&dashboard, finding)
	}
	return dashboard
}

func (s *Server) mergeLiveFindings(ctx context.Context, findings []core.Finding, filter store.FindingFilter) []core.Finding {
	snapshot, ok := s.snapshot(ctx)
	if !ok {
		return findings
	}
	seen := map[string]bool{}
	for _, finding := range findings {
		seen[finding.ID] = true
	}
	for _, finding := range snapshot.Findings {
		if seen[finding.ID] || !matchesFilter(finding, filter) {
			continue
		}
		findings = append(findings, finding)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RiskScore == findings[j].RiskScore {
			return findings[i].UpdatedAt.After(findings[j].UpdatedAt)
		}
		return findings[i].RiskScore > findings[j].RiskScore
	})
	return findings
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
	if filter.Query != "" {
		haystack := strings.ToLower(finding.Title + " " + finding.BlastRadius + " " + finding.CorrelationGroup)
		if !strings.Contains(haystack, strings.ToLower(filter.Query)) {
			return false
		}
	}
	return true
}

func findExperiment(experiments []core.ChaosExperiment, id string) (core.ChaosExperiment, bool) {
	for _, experiment := range experiments {
		if experiment.ID == id {
			return experiment, true
		}
	}
	return core.ChaosExperiment{}, false
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
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}
