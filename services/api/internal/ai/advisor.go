package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
)

const (
	autonomousPolicy = "AI output is decision support only. KubeAthrix executes only catalog-validated typed actions through dry-run, approval gates, controller reconciliation, verification, and rollback metadata."
	systemPrompt     = "You are KubeAthrix AI decision support. Return exactly one compact JSON object with only these fields: summary, rootCause, impact, recommendedAction, confidence, safetyNotes, and evidenceSourceIds. recommendedAction must exactly equal one input plan action type or human_review. confidence must be low, medium, or high. When finding evidence is present, cite one or more of its sourceId values in evidenceSourceIds. Do not invent cluster objects, executable actions, commands, or evidence, and do not bypass approvals."

	defaultMaxInputBytes           = 64 << 10
	defaultMaxOutputTokens         = 700
	defaultCircuitBreakerThreshold = 3
	defaultCircuitBreakerCooldown  = 30 * time.Second
	maxProviderResponseBytes       = 1 << 20

	maxProjectedEvidence  = 10
	maxProjectedResources = 20
	maxProjectedActions   = 12
	maxProjectedSteps     = 10
)

var redactionRules = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?s)-----BEGIN[ \t]+[A-Z0-9 _-]+-----.*?-----END[ \t]+[A-Z0-9 _-]+-----`), "[REDACTED-PEM]"},
	{regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@`), `${1}[REDACTED]@`},
	{regexp.MustCompile(`(?i)\bbearer[ \t]+[A-Za-z0-9._~+/=-]+`), "Bearer [REDACTED]"},
	{regexp.MustCompile(`(?i)\b(password|passwd|api[-_]?key|token|secret|client[-_]?secret|access[-_]?key|private[-_]?key|credential)\b([ \t]*[:=][ \t]*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}\]]+)`), `$1$2[REDACTED]`},
	{regexp.MustCompile(`\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), "[REDACTED-JWT]"},
	{regexp.MustCompile(`\b(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b`), "[REDACTED-AWS-KEY]"},
}

type Advisor interface {
	Analyze(ctx context.Context, finding core.Finding, plan core.RemediationPlan) (core.AIAnalysis, error)
}

type Config struct {
	Enabled                 bool
	Provider                string
	Endpoint                string
	Model                   string
	APIKey                  string
	Timeout                 time.Duration
	AllowInsecureHTTP       bool
	EndpointHostAllowlist   []string
	ExcludedSources         []string
	ExcludedNamespaces      []string
	MaxInputBytes           int
	MaxOutputTokens         int
	CircuitBreakerThreshold int
	CircuitBreakerCooldown  time.Duration
}

type OpenAICompatibleAdvisor struct {
	provider           string
	endpoint           string
	model              string
	apiKey             string
	timeout            time.Duration
	client             *http.Client
	now                func() time.Time
	allowInsecureHTTP  bool
	endpointAllowlist  map[string]struct{}
	excludedSources    map[string]struct{}
	excludedNamespaces map[string]struct{}
	maxInputBytes      int
	maxOutputTokens    int
	circuitThreshold   int
	circuitCooldown    time.Duration

	circuitMu           sync.Mutex
	consecutiveFailures int
	circuitOpenUntil    time.Time
}

func NewOpenAICompatibleAdvisor(config Config, client *http.Client) (*OpenAICompatibleAdvisor, error) {
	if !config.Enabled {
		return nil, errors.New("ai advisor is disabled")
	}
	provider := strings.TrimSpace(config.Provider)
	if provider == "" {
		provider = "openai-compatible"
	}
	endpoint := strings.TrimSpace(config.Endpoint)
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1/chat/completions"
	}
	model := strings.TrimSpace(config.Model)
	if model == "" {
		return nil, errors.New("ai model is required")
	}
	apiKey := strings.TrimSpace(config.APIKey)
	if apiKey == "" {
		return nil, errors.New("ai api key is required")
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	maxInputBytes := config.MaxInputBytes
	if maxInputBytes <= 0 {
		maxInputBytes = defaultMaxInputBytes
	}
	maxOutputTokens := config.MaxOutputTokens
	if maxOutputTokens <= 0 {
		maxOutputTokens = defaultMaxOutputTokens
	}
	circuitThreshold := config.CircuitBreakerThreshold
	if circuitThreshold <= 0 {
		circuitThreshold = defaultCircuitBreakerThreshold
	}
	circuitCooldown := config.CircuitBreakerCooldown
	if circuitCooldown <= 0 {
		circuitCooldown = defaultCircuitBreakerCooldown
	}

	endpointAllowlist, err := exactMatchSet(config.EndpointHostAllowlist, true)
	if err != nil {
		return nil, fmt.Errorf("invalid ai endpoint host allowlist: %w", err)
	}
	if len(endpointAllowlist) == 0 {
		parsedEndpoint, parseErr := url.Parse(endpoint)
		if parseErr != nil || parsedEndpoint.Hostname() == "" {
			return nil, errors.New("ai endpoint must be an absolute URL with a host")
		}
		endpointAllowlist[normalizeExactMatch(parsedEndpoint.Hostname())] = struct{}{}
	}
	validatedEndpoint, err := validateEndpoint(endpoint, config.AllowInsecureHTTP, endpointAllowlist)
	if err != nil {
		return nil, err
	}
	excludedSources, err := exactMatchSet(config.ExcludedSources, false)
	if err != nil {
		return nil, fmt.Errorf("invalid excluded AI source: %w", err)
	}
	excludedNamespaces, err := exactMatchSet(config.ExcludedNamespaces, false)
	if err != nil {
		return nil, fmt.Errorf("invalid excluded AI namespace: %w", err)
	}

	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	clientCopy := *client
	originalRedirectPolicy := clientCopy.CheckRedirect
	clientCopy.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if _, err := validateEndpoint(request.URL.String(), config.AllowInsecureHTTP, endpointAllowlist); err != nil {
			return fmt.Errorf("ai provider redirect rejected: %w", err)
		}
		if originalRedirectPolicy != nil {
			return originalRedirectPolicy(request, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}

	return &OpenAICompatibleAdvisor{
		provider:           provider,
		endpoint:           validatedEndpoint,
		model:              model,
		apiKey:             apiKey,
		timeout:            timeout,
		client:             &clientCopy,
		now:                time.Now,
		allowInsecureHTTP:  config.AllowInsecureHTTP,
		endpointAllowlist:  endpointAllowlist,
		excludedSources:    excludedSources,
		excludedNamespaces: excludedNamespaces,
		maxInputBytes:      maxInputBytes,
		maxOutputTokens:    maxOutputTokens,
		circuitThreshold:   circuitThreshold,
		circuitCooldown:    circuitCooldown,
	}, nil
}

func (a *OpenAICompatibleAdvisor) Analyze(ctx context.Context, finding core.Finding, plan core.RemediationPlan) (analysis core.AIAnalysis, err error) {
	if err := a.checkExclusions(finding, plan); err != nil {
		return core.AIAnalysis{}, err
	}

	requestBody, evidenceSourceIDs, allowedActions, err := a.buildRequestBody(finding, plan)
	if err != nil {
		return core.AIAnalysis{}, err
	}
	if err := a.checkCircuit(); err != nil {
		return core.AIAnalysis{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return core.AIAnalysis{}, err
	}
	request.Header.Set("Authorization", "Bearer "+a.apiKey)
	request.Header.Set("Content-Type", "application/json")

	trackCircuitOutcome := true
	defer func() {
		if !trackCircuitOutcome {
			return
		}
		if err != nil {
			a.recordFailure()
			return
		}
		a.recordSuccess()
	}()

	response, err := a.client.Do(request)
	if err != nil {
		return core.AIAnalysis{}, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxProviderResponseBytes+1))
	if err != nil {
		return core.AIAnalysis{}, err
	}
	if len(body) > maxProviderResponseBytes {
		return core.AIAnalysis{}, errors.New("ai provider response exceeded size limit")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return core.AIAnalysis{}, fmt.Errorf("ai provider returned %d", response.StatusCode)
	}

	var completion chatCompletionResponse
	if err := decodeSingleJSON(body, &completion, false); err != nil {
		return core.AIAnalysis{}, fmt.Errorf("ai provider returned invalid completion envelope: %w", err)
	}
	if len(completion.Choices) == 0 {
		return core.AIAnalysis{}, errors.New("ai provider returned no choices")
	}

	var decoded aiProviderOutput
	content := strings.TrimSpace(stripJSONFence(completion.Choices[0].Message.Content))
	if err := decodeSingleJSON([]byte(content), &decoded, true); err != nil {
		return core.AIAnalysis{}, fmt.Errorf("ai provider returned invalid structured output: %w", err)
	}
	confidence, citations, err := validateProviderOutput(decoded, allowedActions, evidenceSourceIDs)
	if err != nil {
		return core.AIAnalysis{}, fmt.Errorf("ai provider returned invalid structured output: %w", err)
	}

	safetyNoteLimit := 5
	if len(citations) > 0 {
		safetyNoteLimit--
	}
	safetyNotes := boundedSanitizedStrings(decoded.SafetyNotes, safetyNoteLimit, 300)
	if len(citations) > 0 {
		safetyNotes = append(safetyNotes, boundedString("Evidence sources: "+strings.Join(citations, ", "), 300))
	}
	return core.AIAnalysis{
		Provider:          a.provider,
		Model:             a.model,
		Mode:              "assistive",
		Summary:           sanitize(decoded.Summary, 700),
		RootCause:         sanitize(decoded.RootCause, 900),
		Impact:            sanitize(decoded.Impact, 900),
		RecommendedAction: strings.TrimSpace(decoded.RecommendedAction),
		Confidence:        confidence,
		SafetyNotes:       safetyNotes,
		AutonomousPolicy:  autonomousPolicy,
		GeneratedAt:       a.now().UTC(),
	}, nil
}

func (a *OpenAICompatibleAdvisor) buildRequestBody(finding core.Finding, plan core.RemediationPlan) ([]byte, map[string]struct{}, map[string]struct{}, error) {
	projected := projectAdvisorInput(finding, plan)
	allowedActions := make(map[string]struct{}, len(plan.Actions))
	for _, action := range plan.Actions {
		if actionType := strings.TrimSpace(action.Type); actionType != "" {
			allowedActions[actionType] = struct{}{}
		}
	}

	for attempts := 0; attempts < 256; attempts++ {
		prompt, err := json.Marshal(projected)
		if err != nil {
			return nil, nil, nil, err
		}
		requestBody, err := json.Marshal(chatCompletionRequest{
			Model: a.model,
			Messages: []chatMessage{
				{Role: "system", Content: systemPrompt},
				{Role: "user", Content: string(prompt)},
			},
			Temperature:    0.1,
			MaxTokens:      a.maxOutputTokens,
			ResponseFormat: map[string]string{"type": "json_object"},
		})
		if err != nil {
			return nil, nil, nil, err
		}
		if len(requestBody) <= a.maxInputBytes {
			return requestBody, projectedEvidenceSourceIDs(projected), allowedActions, nil
		}
		if !shrinkProjectedInput(&projected) {
			break
		}
	}
	return nil, nil, nil, fmt.Errorf("projected AI input cannot fit within %d bytes", a.maxInputBytes)
}

func (a *OpenAICompatibleAdvisor) checkExclusions(finding core.Finding, plan core.RemediationPlan) error {
	if _, excluded := a.excludedSources[normalizeExactMatch(finding.Source)]; excluded {
		return fmt.Errorf("finding source %q is excluded from AI processing", finding.Source)
	}
	checkNamespace := func(namespace string) error {
		if namespace = strings.TrimSpace(namespace); namespace == "" {
			return nil
		}
		if _, excluded := a.excludedNamespaces[normalizeExactMatch(namespace)]; excluded {
			return fmt.Errorf("namespace %q is excluded from AI processing", namespace)
		}
		return nil
	}
	if err := checkNamespace(finding.CorrelationKeys.Namespace); err != nil {
		return err
	}
	for _, resource := range finding.Resources {
		if err := checkNamespace(resource.Namespace); err != nil {
			return err
		}
	}
	for _, action := range plan.Actions {
		if err := checkNamespace(action.Target.Namespace); err != nil {
			return err
		}
	}
	return nil
}

func (a *OpenAICompatibleAdvisor) checkCircuit() error {
	now := a.now()
	a.circuitMu.Lock()
	defer a.circuitMu.Unlock()
	if a.circuitOpenUntil.IsZero() {
		return nil
	}
	if now.Before(a.circuitOpenUntil) {
		return fmt.Errorf("ai provider circuit breaker is open until %s", a.circuitOpenUntil.UTC().Format(time.RFC3339))
	}
	a.circuitOpenUntil = time.Time{}
	a.consecutiveFailures = 0
	return nil
}

func (a *OpenAICompatibleAdvisor) recordFailure() {
	a.circuitMu.Lock()
	defer a.circuitMu.Unlock()
	a.consecutiveFailures++
	if a.consecutiveFailures >= a.circuitThreshold {
		a.circuitOpenUntil = a.now().Add(a.circuitCooldown)
	}
}

func (a *OpenAICompatibleAdvisor) recordSuccess() {
	a.circuitMu.Lock()
	defer a.circuitMu.Unlock()
	a.consecutiveFailures = 0
	a.circuitOpenUntil = time.Time{}
}

type chatCompletionRequest struct {
	Model          string            `json:"model"`
	Messages       []chatMessage     `json:"messages"`
	Temperature    float64           `json:"temperature"`
	MaxTokens      int               `json:"max_tokens"`
	ResponseFormat map[string]string `json:"response_format,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

type aiProviderOutput struct {
	Summary           string   `json:"summary"`
	RootCause         string   `json:"rootCause"`
	Impact            string   `json:"impact"`
	RecommendedAction string   `json:"recommendedAction"`
	Confidence        string   `json:"confidence"`
	SafetyNotes       []string `json:"safetyNotes"`
	EvidenceSourceIDs []string `json:"evidenceSourceIds"`
}

type advisorInput struct {
	Finding projectedFinding `json:"finding"`
	Plan    projectedPlan    `json:"plan"`
}

type projectedFinding struct {
	ID                string              `json:"id,omitempty"`
	Source            string              `json:"source,omitempty"`
	Title             string              `json:"title,omitempty"`
	Severity          string              `json:"severity,omitempty"`
	Evidence          []projectedEvidence `json:"evidence,omitempty"`
	Resources         []projectedResource `json:"resources,omitempty"`
	BlastRadius       string              `json:"blastRadius,omitempty"`
	Fixability        string              `json:"fixability,omitempty"`
	RiskScore         int                 `json:"riskScore,omitempty"`
	RecommendedAction string              `json:"recommendedAction,omitempty"`
}

type projectedEvidence struct {
	Summary    string `json:"summary,omitempty"`
	Details    string `json:"details,omitempty"`
	SourceID   string `json:"sourceId"`
	ObservedAt string `json:"observedAt,omitempty"`
}

type projectedResource struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name,omitempty"`
}

type projectedAction struct {
	Type        string             `json:"type"`
	Target      *projectedResource `json:"target,omitempty"`
	Description string             `json:"description,omitempty"`
}

type projectedApprovalPolicy struct {
	Required   bool     `json:"required"`
	Categories []string `json:"categories,omitempty"`
}

type projectedPlan struct {
	ID                string                  `json:"id,omitempty"`
	FindingID         string                  `json:"findingId,omitempty"`
	RootCause         string                  `json:"rootCause,omitempty"`
	Actions           []projectedAction       `json:"actions,omitempty"`
	RiskTier          string                  `json:"riskTier,omitempty"`
	ApprovalPolicy    projectedApprovalPolicy `json:"approvalPolicy"`
	VerificationSteps []string                `json:"verificationSteps,omitempty"`
	RollbackSteps     []string                `json:"rollbackSteps,omitempty"`
}

func projectAdvisorInput(finding core.Finding, plan core.RemediationPlan) advisorInput {
	projected := advisorInput{
		Finding: projectedFinding{
			ID:                sanitize(finding.ID, 200),
			Source:            sanitize(finding.Source, 120),
			Title:             sanitize(finding.Title, 500),
			Severity:          sanitize(string(finding.Severity), 30),
			BlastRadius:       sanitize(finding.BlastRadius, 700),
			Fixability:        sanitize(string(finding.Fixability), 60),
			RiskScore:         finding.RiskScore,
			RecommendedAction: sanitize(finding.RecommendedAction, 700),
		},
		Plan: projectedPlan{
			ID:             sanitize(plan.ID, 200),
			FindingID:      sanitize(plan.FindingID, 200),
			RootCause:      sanitize(plan.RootCause, 900),
			RiskTier:       sanitize(string(plan.RiskTier), 20),
			ApprovalPolicy: projectedApprovalPolicy{Required: plan.ApprovalPolicy.Required},
		},
	}
	for _, evidence := range finding.Evidence {
		if len(projected.Finding.Evidence) >= maxProjectedEvidence {
			break
		}
		sourceID := sanitize(evidence.SourceID, 200)
		if sourceID == "" {
			continue
		}
		projected.Finding.Evidence = append(projected.Finding.Evidence, projectedEvidence{
			Summary:    sanitize(evidence.Summary, 500),
			Details:    sanitize(evidence.Details, 1200),
			SourceID:   sourceID,
			ObservedAt: evidence.ObservedAt.UTC().Format(time.RFC3339),
		})
	}
	for _, resource := range finding.Resources {
		if len(projected.Finding.Resources) >= maxProjectedResources {
			break
		}
		projected.Finding.Resources = append(projected.Finding.Resources, projectResource(resource))
	}
	for _, action := range plan.Actions {
		if len(projected.Plan.Actions) >= maxProjectedActions {
			break
		}
		target := projectResource(action.Target)
		projected.Plan.Actions = append(projected.Plan.Actions, projectedAction{
			Type:        sanitize(action.Type, 160),
			Target:      &target,
			Description: sanitize(action.Description, 700),
		})
	}
	projected.Plan.ApprovalPolicy.Categories = boundedSanitizedStrings(plan.ApprovalPolicy.Categories, maxProjectedSteps, 200)
	projected.Plan.VerificationSteps = boundedSanitizedStrings(plan.VerificationSteps, maxProjectedSteps, 500)
	projected.Plan.RollbackSteps = boundedSanitizedStrings(plan.RollbackSteps, maxProjectedSteps, 500)
	return projected
}

func projectResource(resource core.ResourceRef) projectedResource {
	return projectedResource{
		APIVersion: sanitize(resource.APIVersion, 120),
		Kind:       sanitize(resource.Kind, 120),
		Namespace:  sanitize(resource.Namespace, 253),
		Name:       sanitize(resource.Name, 253),
	}
}

func shrinkProjectedInput(input *advisorInput) bool {
	if n := len(input.Plan.RollbackSteps); n > 0 {
		input.Plan.RollbackSteps = input.Plan.RollbackSteps[:n-1]
		return true
	}
	if n := len(input.Plan.VerificationSteps); n > 0 {
		input.Plan.VerificationSteps = input.Plan.VerificationSteps[:n-1]
		return true
	}
	if n := len(input.Plan.ApprovalPolicy.Categories); n > 0 {
		input.Plan.ApprovalPolicy.Categories = input.Plan.ApprovalPolicy.Categories[:n-1]
		return true
	}
	for i := range input.Finding.Evidence {
		if input.Finding.Evidence[i].Details != "" {
			input.Finding.Evidence[i].Details = ""
			return true
		}
	}
	for i := range input.Plan.Actions {
		if input.Plan.Actions[i].Description != "" {
			input.Plan.Actions[i].Description = ""
			return true
		}
	}
	if len(input.Finding.Resources) > 8 {
		input.Finding.Resources = input.Finding.Resources[:len(input.Finding.Resources)-1]
		return true
	}
	if len(input.Finding.Evidence) > 4 {
		input.Finding.Evidence = input.Finding.Evidence[:len(input.Finding.Evidence)-1]
		return true
	}
	if len(input.Plan.Actions) > 8 {
		input.Plan.Actions = input.Plan.Actions[:len(input.Plan.Actions)-1]
		return true
	}
	for _, value := range []*string{&input.Finding.Title, &input.Finding.BlastRadius, &input.Finding.RecommendedAction, &input.Plan.RootCause} {
		if utf8.RuneCountInString(*value) > 160 {
			*value = boundedString(*value, utf8.RuneCountInString(*value)/2)
			return true
		}
	}
	if input.Finding.RecommendedAction != "" {
		input.Finding.RecommendedAction = ""
		return true
	}
	if input.Finding.BlastRadius != "" {
		input.Finding.BlastRadius = ""
		return true
	}
	if input.Plan.RootCause != "" {
		input.Plan.RootCause = ""
		return true
	}
	for i := range input.Finding.Evidence {
		if input.Finding.Evidence[i].Summary != "" {
			input.Finding.Evidence[i].Summary = ""
			return true
		}
	}
	for i := range input.Finding.Resources {
		if input.Finding.Resources[i].APIVersion != "" {
			input.Finding.Resources[i].APIVersion = ""
			return true
		}
	}
	for i := range input.Plan.Actions {
		if input.Plan.Actions[i].Target != nil && input.Plan.Actions[i].Target.APIVersion != "" {
			input.Plan.Actions[i].Target.APIVersion = ""
			return true
		}
	}
	if n := len(input.Finding.Resources); n > 0 {
		input.Finding.Resources = input.Finding.Resources[:n-1]
		return true
	}
	if n := len(input.Finding.Evidence); n > 0 {
		input.Finding.Evidence = input.Finding.Evidence[:n-1]
		return true
	}
	for i := range input.Plan.Actions {
		if input.Plan.Actions[i].Target != nil {
			input.Plan.Actions[i].Target = nil
			return true
		}
	}
	if len(input.Plan.Actions) > 1 {
		input.Plan.Actions = input.Plan.Actions[:len(input.Plan.Actions)-1]
		return true
	}
	for _, value := range []*string{&input.Finding.ID, &input.Finding.Source, &input.Finding.Title, &input.Plan.ID, &input.Plan.FindingID} {
		if utf8.RuneCountInString(*value) > 32 {
			*value = boundedString(*value, utf8.RuneCountInString(*value)/2)
			return true
		}
	}
	for _, value := range []*string{&input.Finding.Title, &input.Finding.Source, &input.Finding.ID, &input.Plan.FindingID, &input.Plan.ID, &input.Finding.Severity, &input.Finding.Fixability, &input.Plan.RiskTier} {
		if *value != "" {
			*value = ""
			return true
		}
	}
	if len(input.Plan.Actions) > 0 {
		input.Plan.Actions = nil
		return true
	}
	return false
}

func projectedEvidenceSourceIDs(input advisorInput) map[string]struct{} {
	result := make(map[string]struct{}, len(input.Finding.Evidence))
	for _, evidence := range input.Finding.Evidence {
		if sourceID := strings.TrimSpace(evidence.SourceID); sourceID != "" {
			result[sourceID] = struct{}{}
		}
	}
	return result
}

func validateProviderOutput(output aiProviderOutput, allowedActions, evidenceSourceIDs map[string]struct{}) (string, []string, error) {
	required := map[string]string{
		"summary":           output.Summary,
		"rootCause":         output.RootCause,
		"impact":            output.Impact,
		"recommendedAction": output.RecommendedAction,
		"confidence":        output.Confidence,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return "", nil, fmt.Errorf("%s is required", name)
		}
	}

	recommendedAction := strings.TrimSpace(output.RecommendedAction)
	if recommendedAction != "human_review" {
		if _, ok := allowedActions[recommendedAction]; !ok {
			return "", nil, fmt.Errorf("recommendedAction %q is not a plan action", recommendedAction)
		}
	}
	confidence := strings.ToLower(strings.TrimSpace(output.Confidence))
	if confidence != "low" && confidence != "medium" && confidence != "high" {
		return "", nil, fmt.Errorf("confidence %q is not low, medium, or high", output.Confidence)
	}

	citationSet := make(map[string]struct{}, len(output.EvidenceSourceIDs))
	citations := make([]string, 0, len(output.EvidenceSourceIDs))
	for _, sourceID := range output.EvidenceSourceIDs {
		sourceID = strings.TrimSpace(sourceID)
		if sourceID == "" {
			return "", nil, errors.New("evidenceSourceIds cannot contain an empty value")
		}
		if _, ok := evidenceSourceIDs[sourceID]; !ok {
			return "", nil, fmt.Errorf("evidence source %q was not present in the input", sourceID)
		}
		if _, duplicate := citationSet[sourceID]; duplicate {
			continue
		}
		citationSet[sourceID] = struct{}{}
		citations = append(citations, sourceID)
	}
	if len(evidenceSourceIDs) > 0 && len(citations) == 0 {
		return "", nil, errors.New("evidenceSourceIds must cite at least one input evidence source")
	}
	if len(evidenceSourceIDs) == 0 && len(output.EvidenceSourceIDs) > 0 {
		return "", nil, errors.New("evidenceSourceIds were returned without input evidence")
	}
	sort.Strings(citations)
	return confidence, citations, nil
}

func decodeSingleJSON(data []byte, target any, disallowUnknown bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if disallowUnknown {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value is not allowed")
		}
		return fmt.Errorf("trailing data is not allowed: %w", err)
	}
	return nil
}

func exactMatchSet(values []string, rejectWildcard bool) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, errors.New("empty values are not allowed")
		}
		if rejectWildcard && strings.Contains(value, "*") {
			return nil, fmt.Errorf("wildcard value %q is not allowed", value)
		}
		result[normalizeExactMatch(strings.Trim(value, "[]"))] = struct{}{}
	}
	return result, nil
}

func normalizeExactMatch(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validateEndpoint(rawEndpoint string, allowInsecureHTTP bool, allowlist map[string]struct{}) (string, error) {
	parsed, err := url.Parse(rawEndpoint)
	if err != nil {
		return "", fmt.Errorf("invalid ai endpoint: %w", err)
	}
	if !parsed.IsAbs() || parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("ai endpoint must be an absolute URL with a host")
	}
	if parsed.User != nil {
		return "", errors.New("ai endpoint must not contain userinfo")
	}
	if parsed.Fragment != "" {
		return "", errors.New("ai endpoint must not contain a fragment")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !allowInsecureHTTP {
			return "", errors.New("ai endpoint must use HTTPS")
		}
	default:
		return "", errors.New("ai endpoint must use HTTPS")
	}
	if len(allowlist) > 0 {
		if _, ok := allowlist[normalizeExactMatch(parsed.Hostname())]; !ok {
			return "", fmt.Errorf("ai endpoint hostname %q is not allowlisted", parsed.Hostname())
		}
	}
	return parsed.String(), nil
}

func redactSensitive(value string) string {
	for _, rule := range redactionRules {
		value = rule.pattern.ReplaceAllString(value, rule.replacement)
	}
	return value
}

func sanitize(value string, maxRunes int) string {
	return boundedString(redactSensitive(value), maxRunes)
}

func stripJSONFence(value string) string {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "```") {
		return trimmed
	}
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	return strings.TrimSpace(trimmed)
}

func boundedSanitizedStrings(values []string, limit, maxRunes int) []string {
	if len(values) > limit {
		values = values[:limit]
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := sanitize(value, maxRunes); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func boundedString(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	if maxRunes <= 0 || utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	return strings.TrimSpace(string(runes[:maxRunes]))
}
