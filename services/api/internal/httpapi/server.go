package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
)

type Config struct {
	DevAuthEnabled bool
	OIDCIssuerURL  string
	OIDCClientID   string
}

type Server struct {
	repository store.Repository
	config     Config
}

func NewServer(repository store.Repository, config Config) *Server {
	return &Server{repository: repository, config: config}
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
	writeJSON(w, http.StatusOK, dashboard)
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	findings, err := s.repository.ListFindings(r.Context(), store.FindingFilter{
		Severity: r.URL.Query().Get("severity"),
		Status:   r.URL.Query().Get("status"),
		Source:   r.URL.Query().Get("source"),
		Query:    r.URL.Query().Get("q"),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": findings})
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	finding, err := s.repository.GetFinding(r.Context(), r.PathValue("id"))
	if err != nil {
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
