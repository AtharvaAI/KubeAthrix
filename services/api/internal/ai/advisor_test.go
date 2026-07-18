package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
)

func TestOpenAICompatibleAdvisorParsesBoundedStructuredOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("authorization header was not set")
		}
		writeCompletion(t, w, aiProviderOutput{
			Summary:           "Scoped recommendation",
			RootCause:         "The namespace lacks guardrails.",
			Impact:            "Workloads can consume unbounded resources.",
			RecommendedAction: "apply_resource_governance",
			Confidence:        "high",
			SafetyNotes:       []string{"No direct mutation is performed by AI."},
			EvidenceSourceIDs: []string{"policy-scan-1"},
		})
	}))
	defer server.Close()

	advisor := newTestAdvisor(t, server, Config{})
	analysis, err := advisor.Analyze(context.Background(), core.Finding{
		ID:       "finding-1",
		Title:    "Namespace lacks ResourceQuota",
		Evidence: []core.Evidence{{SourceID: "policy-scan-1", Summary: "No ResourceQuota exists"}},
	}, core.RemediationPlan{
		ID:      "plan-1",
		Actions: []core.TypedAction{{Type: "apply_resource_governance"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Summary != "Scoped recommendation" || analysis.Confidence != "high" {
		t.Fatalf("unexpected analysis: %#v", analysis)
	}
	if analysis.RecommendedAction != "apply_resource_governance" {
		t.Fatalf("unexpected recommended action: %q", analysis.RecommendedAction)
	}
	if !contains(analysis.SafetyNotes, "Evidence sources: policy-scan-1") {
		t.Fatalf("expected validated evidence citation in safety notes: %#v", analysis.SafetyNotes)
	}
	if analysis.AutonomousPolicy == "" {
		t.Fatal("analysis must include the autonomous safety policy")
	}
}

func TestNewOpenAICompatibleAdvisorValidatesEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{name: "http rejected by default", config: Config{Endpoint: "http://example.com/v1/chat/completions"}},
		{name: "userinfo rejected", config: Config{Endpoint: "https://user:password@example.com/v1/chat/completions"}},
		{name: "unsupported scheme rejected", config: Config{Endpoint: "ftp://example.com/model"}},
		{name: "host not allowlisted", config: Config{Endpoint: "https://api.example.com/model", EndpointHostAllowlist: []string{"models.example.net"}}},
		{name: "wildcard allowlist rejected", config: Config{Endpoint: "https://api.example.com/model", EndpointHostAllowlist: []string{"*.example.com"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.Enabled = true
			tt.config.Model = "test-model"
			tt.config.APIKey = "test-key"
			if _, err := NewOpenAICompatibleAdvisor(tt.config, nil); err == nil {
				t.Fatal("expected endpoint validation error")
			}
		})
	}

	if _, err := NewOpenAICompatibleAdvisor(Config{
		Enabled:               true,
		Endpoint:              "https://api.example.com/model",
		EndpointHostAllowlist: []string{"API.EXAMPLE.COM"},
		Model:                 "test-model",
		APIKey:                "test-key",
	}, nil); err != nil {
		t.Fatalf("expected exact case-insensitive hostname allowlist match: %v", err)
	}

	advisor, err := NewOpenAICompatibleAdvisor(Config{
		Enabled: true, Endpoint: "https://api.example.com/model", Model: "test-model", APIKey: "test-key",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	redirectURL, _ := url.Parse("https://internal.example.net/model")
	if err := advisor.client.CheckRedirect(&http.Request{URL: redirectURL}, nil); err == nil {
		t.Fatal("empty host configuration did not pin redirects to the configured endpoint hostname")
	}
}

func TestOpenAICompatibleAdvisorExclusionsPreventRequests(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()
	advisor := newTestAdvisor(t, server, Config{
		ExcludedSources:    []string{"private-scanner"},
		ExcludedNamespaces: []string{"secrets-system"},
	})

	tests := []struct {
		name    string
		finding core.Finding
		plan    core.RemediationPlan
	}{
		{name: "source", finding: core.Finding{Source: "PRIVATE-SCANNER"}},
		{name: "finding resource namespace", finding: core.Finding{Resources: []core.ResourceRef{{Namespace: "secrets-system"}}}},
		{name: "correlation namespace", finding: core.Finding{CorrelationKeys: core.CorrelationKeys{Namespace: "secrets-system"}}},
		{name: "action namespace", plan: core.RemediationPlan{Actions: []core.TypedAction{{Target: core.ResourceRef{Namespace: "secrets-system"}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := advisor.Analyze(context.Background(), tt.finding, tt.plan); err == nil {
				t.Fatal("expected exclusion error")
			}
		})
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("excluded input made %d provider requests", got)
	}
}

func TestOpenAICompatibleAdvisorProjectsRedactsAndBoundsRequest(t *testing.T) {
	const (
		jwt       = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234"
		awsKey    = "AKIAIOSFODNN7EXAMPLE"
		bearer    = "secret-bearer-token"
		password  = "password-value"
		paramKey  = "PARAM-API-KEY-MUST-NOT-LEAK"
		pemSecret = "private-material"
	)
	var captured chatCompletionRequest
	var capturedRaw string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		capturedRaw = string(body)
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		writeCompletion(t, w, aiProviderOutput{
			Summary:           "Use the selected action.",
			RootCause:         "The policy finding is supported by evidence.",
			Impact:            "The affected workload remains in scope.",
			RecommendedAction: "apply_fix",
			Confidence:        "medium",
			EvidenceSourceIDs: []string{"scan-1"},
		})
	}))
	defer server.Close()

	advisor := newTestAdvisor(t, server, Config{MaxOutputTokens: 321})
	_, err := advisor.Analyze(context.Background(), core.Finding{
		ID:                "finding-1",
		Source:            "scanner",
		Title:             "JWT " + jwt,
		BlastRadius:       "access_key=" + awsKey + " password=" + password,
		RecommendedAction: "Bearer " + bearer,
		Evidence: []core.Evidence{{
			SourceID: "scan-1",
			Summary:  "https://alice:supersecret@example.com/private",
			Details:  "-----BEGIN PRIVATE KEY-----\n" + pemSecret + "\n-----END PRIVATE KEY-----",
		}},
	}, core.RemediationPlan{
		ID:        "plan-1",
		RootCause: "api_key=another-secret",
		Actions: []core.TypedAction{{
			Type:        "apply_fix",
			Description: "token=third-secret",
			Params:      map[string]string{"apiKey": paramKey},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if captured.MaxTokens != 321 {
		t.Fatalf("max_tokens = %d, want 321", captured.MaxTokens)
	}
	for _, secret := range []string{jwt, awsKey, bearer, password, paramKey, pemSecret, "alice:supersecret", "another-secret", "third-secret"} {
		if strings.Contains(capturedRaw, secret) {
			t.Fatalf("request leaked sensitive value %q: %s", secret, capturedRaw)
		}
	}
	if !strings.Contains(capturedRaw, "[REDACTED") {
		t.Fatalf("request did not contain redaction markers: %s", capturedRaw)
	}
	if strings.Contains(captured.Messages[1].Content, `"params"`) || strings.Contains(captured.Messages[1].Content, `"createdAt"`) {
		t.Fatalf("request contains non-projected fields: %s", captured.Messages[1].Content)
	}
}

func TestOpenAICompatibleAdvisorRejectsNonStrictOutput(t *testing.T) {
	validPrefix := `{"summary":"s","rootCause":"r","impact":"i","recommendedAction":"human_review","confidence":"low","safetyNotes":[],"evidenceSourceIds":[]`
	tests := []struct {
		name    string
		content string
	}{
		{name: "unknown field", content: validPrefix + `,"unexpected":true}`},
		{name: "missing field", content: `{"summary":"s","rootCause":"r","recommendedAction":"human_review","confidence":"low","safetyNotes":[],"evidenceSourceIds":[]}`},
		{name: "trailing object", content: validPrefix + `} {}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := completionServer(t, tt.content)
			defer server.Close()
			advisor := newTestAdvisor(t, server, Config{})
			if _, err := advisor.Analyze(context.Background(), core.Finding{}, core.RemediationPlan{}); err == nil {
				t.Fatal("expected strict output validation error")
			}
		})
	}
}

func TestOpenAICompatibleAdvisorRejectsInvalidRecommendedAction(t *testing.T) {
	server := completionServer(t, mustProviderOutput(t, aiProviderOutput{
		Summary:           "s",
		RootCause:         "r",
		Impact:            "i",
		RecommendedAction: "invented_action",
		Confidence:        "high",
		EvidenceSourceIDs: []string{},
	}))
	defer server.Close()
	advisor := newTestAdvisor(t, server, Config{})
	_, err := advisor.Analyze(context.Background(), core.Finding{}, core.RemediationPlan{
		Actions: []core.TypedAction{{Type: "allowed_action"}},
	})
	if err == nil || !strings.Contains(err.Error(), "not a plan action") {
		t.Fatalf("expected invalid recommended action error, got %v", err)
	}
}

func TestOpenAICompatibleAdvisorRequiresInputEvidenceCitations(t *testing.T) {
	tests := []struct {
		name      string
		citations []string
	}{
		{name: "missing citation", citations: nil},
		{name: "unknown citation", citations: []string{"invented-source"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := completionServer(t, mustProviderOutput(t, aiProviderOutput{
				Summary:           "s",
				RootCause:         "r",
				Impact:            "i",
				RecommendedAction: "human_review",
				Confidence:        "low",
				EvidenceSourceIDs: tt.citations,
			}))
			defer server.Close()
			advisor := newTestAdvisor(t, server, Config{})
			_, err := advisor.Analyze(context.Background(), core.Finding{
				Evidence: []core.Evidence{{SourceID: "real-source"}},
			}, core.RemediationPlan{})
			if err == nil {
				t.Fatal("expected citation validation error")
			}
		})
	}
}

func TestOpenAICompatibleAdvisorCircuitBreaker(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	advisor := newTestAdvisor(t, server, Config{
		CircuitBreakerThreshold: 2,
		CircuitBreakerCooldown:  time.Minute,
	})
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	advisor.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		if _, err := advisor.Analyze(context.Background(), core.Finding{}, core.RemediationPlan{}); err == nil {
			t.Fatal("expected provider error")
		}
	}
	if _, err := advisor.Analyze(context.Background(), core.Finding{}, core.RemediationPlan{}); err == nil || !strings.Contains(err.Error(), "circuit breaker is open") {
		t.Fatalf("expected open circuit error, got %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("open circuit made a request: got %d requests", got)
	}

	now = now.Add(time.Minute + time.Second)
	if _, err := advisor.Analyze(context.Background(), core.Finding{}, core.RemediationPlan{}); err == nil {
		t.Fatal("expected provider error after cooldown probe")
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("cooldown did not permit a probe request: got %d requests", got)
	}
}

func TestOpenAICompatibleAdvisorCapsTotalRequestBytes(t *testing.T) {
	const maxInputBytes = 1800
	var requestBytes atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		requestBytes.Store(int64(len(body)))
		var request chatCompletionRequest
		if err := json.Unmarshal(body, &request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		var input advisorInput
		if err := json.Unmarshal([]byte(request.Messages[1].Content), &input); err != nil {
			t.Errorf("decode projected input: %v", err)
			return
		}
		citations := make([]string, 0, 1)
		if len(input.Finding.Evidence) > 0 {
			citations = append(citations, input.Finding.Evidence[0].SourceID)
		}
		writeCompletion(t, w, aiProviderOutput{
			Summary:           "s",
			RootCause:         "r",
			Impact:            "i",
			RecommendedAction: "human_review",
			Confidence:        "low",
			EvidenceSourceIDs: citations,
		})
	}))
	defer server.Close()
	advisor := newTestAdvisor(t, server, Config{MaxInputBytes: maxInputBytes})

	finding := core.Finding{Title: strings.Repeat("large-title ", 1000)}
	for i := 0; i < 30; i++ {
		finding.Evidence = append(finding.Evidence, core.Evidence{
			SourceID: "evidence-source-" + strings.Repeat("x", 40),
			Summary:  strings.Repeat("summary ", 500),
			Details:  strings.Repeat("details ", 1000),
		})
		finding.Resources = append(finding.Resources, core.ResourceRef{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Namespace:  "default",
			Name:       strings.Repeat("resource", 30),
		})
	}
	if _, err := advisor.Analyze(context.Background(), finding, core.RemediationPlan{}); err != nil {
		t.Fatal(err)
	}
	if got := requestBytes.Load(); got == 0 || got > maxInputBytes {
		t.Fatalf("request size = %d, want 1..%d", got, maxInputBytes)
	}
}

func newTestAdvisor(t *testing.T, server *httptest.Server, overrides Config) *OpenAICompatibleAdvisor {
	t.Helper()
	overrides.Enabled = true
	overrides.Endpoint = server.URL
	overrides.Model = "test-model"
	overrides.APIKey = "test-key"
	overrides.Timeout = time.Second
	overrides.AllowInsecureHTTP = true
	advisor, err := NewOpenAICompatibleAdvisor(overrides, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return advisor
}

func completionServer(t *testing.T, content string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": content}}},
		}); err != nil {
			t.Errorf("encode completion: %v", err)
		}
	}))
}

func writeCompletion(t *testing.T, w http.ResponseWriter, output aiProviderOutput) {
	t.Helper()
	content := mustProviderOutput(t, output)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": content}}},
	}); err != nil {
		t.Errorf("encode completion: %v", err)
	}
}

func mustProviderOutput(t *testing.T, output aiProviderOutput) string {
	t.Helper()
	encoded, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
