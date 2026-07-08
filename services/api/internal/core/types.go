package core

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type FindingStatus string

const (
	FindingOpen        FindingStatus = "open"
	FindingInReview    FindingStatus = "in_review"
	FindingRemediating FindingStatus = "remediating"
	FindingResolved    FindingStatus = "resolved"
	FindingSuppressed  FindingStatus = "suppressed"
)

type Fixability string

const (
	FixabilityDeterministic Fixability = "safe_deterministic"
	FixabilityGated         Fixability = "dry_run_then_gated"
	FixabilityHumanOnly     Fixability = "human_approved_only"
	FixabilityInformational Fixability = "informational_no_fix"
)

type RiskTier string

const (
	RiskTierA RiskTier = "A"
	RiskTierB RiskTier = "B"
	RiskTierC RiskTier = "C"
	RiskTierD RiskTier = "D"
)

type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
	ApprovalExpired  ApprovalStatus = "expired"
)

type RunState string

const (
	RunPendingApproval RunState = "pending_approval"
	RunDryRunPassed    RunState = "dry_run_passed"
	RunRunning         RunState = "running"
	RunSucceeded       RunState = "succeeded"
	RunFailed          RunState = "failed"
	RunRolledBack      RunState = "rolled_back"
)

type ResourceRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

func (r ResourceRef) String() string {
	if r.Namespace == "" {
		return r.Kind + "/" + r.Name
	}
	return r.Kind + "/" + r.Namespace + "/" + r.Name
}

type Evidence struct {
	Summary    string    `json:"summary"`
	Details    string    `json:"details"`
	SourceID   string    `json:"sourceId"`
	ObservedAt time.Time `json:"observedAt"`
}

type Finding struct {
	ID                string        `json:"id"`
	Source            string        `json:"source"`
	Title             string        `json:"title"`
	Severity          Severity      `json:"severity"`
	Evidence          []Evidence    `json:"evidence"`
	Resources         []ResourceRef `json:"resources"`
	BlastRadius       string        `json:"blastRadius"`
	Fixability        Fixability    `json:"fixability"`
	Status            FindingStatus `json:"status"`
	CorrelationGroup  string        `json:"correlationGroup"`
	RiskScore         int           `json:"riskScore"`
	RemediationState  string        `json:"remediationState"`
	RecommendedAction string        `json:"recommendedAction"`
	CreatedAt         time.Time     `json:"createdAt"`
	UpdatedAt         time.Time     `json:"updatedAt"`
}

type Dashboard struct {
	TotalFindings        int            `json:"totalFindings"`
	OpenCritical         int            `json:"openCritical"`
	PendingApprovals     int            `json:"pendingApprovals"`
	ActiveRemediations   int            `json:"activeRemediations"`
	MeanRiskScore        float64        `json:"meanRiskScore"`
	FindingsBySeverity   map[string]int `json:"findingsBySeverity"`
	FindingsBySource     map[string]int `json:"findingsBySource"`
	RemediationByState   map[string]int `json:"remediationByState"`
	ProtectedNamespaces  int            `json:"protectedNamespaces"`
	BundledEnginesOnline int            `json:"bundledEnginesOnline"`
}

type TypedAction struct {
	Type        string            `json:"type"`
	Target      ResourceRef       `json:"target"`
	Description string            `json:"description"`
	Params      map[string]string `json:"params,omitempty"`
}

type DryRunResult struct {
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

type ApprovalPolicy struct {
	Required   bool     `json:"required"`
	Categories []string `json:"categories,omitempty"`
}

type RemediationPlan struct {
	ID                string         `json:"id"`
	FindingID         string         `json:"findingId"`
	RootCause         string         `json:"rootCause"`
	Actions           []TypedAction  `json:"actions"`
	RiskTier          RiskTier       `json:"riskTier"`
	DryRunResult      DryRunResult   `json:"dryRunResult"`
	VerificationSteps []string       `json:"verificationSteps"`
	RollbackSteps     []string       `json:"rollbackSteps"`
	ApprovalPolicy    ApprovalPolicy `json:"approvalPolicy"`
	Status            string         `json:"status"`
	CreatedAt         time.Time      `json:"createdAt"`
}

type ApprovalRequest struct {
	ID              string         `json:"id"`
	SubjectRef      string         `json:"subjectRef"`
	RequestedAction string         `json:"requestedAction"`
	Requester       string         `json:"requester"`
	Approver        string         `json:"approver,omitempty"`
	Status          ApprovalStatus `json:"status"`
	ExpiresAt       time.Time      `json:"expiresAt"`
	CreatedAt       time.Time      `json:"createdAt"`
	UpdatedAt       time.Time      `json:"updatedAt"`
	DecisionReason  string         `json:"decisionReason,omitempty"`
}

type ActionStatus struct {
	ActionType string `json:"actionType"`
	State      string `json:"state"`
	Message    string `json:"message"`
}

type RemediationRun struct {
	ID               string         `json:"id"`
	PlanID           string         `json:"planId"`
	State            RunState       `json:"state"`
	ActionStatuses   []ActionStatus `json:"actionStatuses"`
	ValidationResult string         `json:"validationResult"`
	RollbackMetadata string         `json:"rollbackMetadata"`
	CreatedAt        time.Time      `json:"createdAt"`
	UpdatedAt        time.Time      `json:"updatedAt"`
}

type Exception struct {
	ID            string    `json:"id"`
	Scope         string    `json:"scope"`
	Owner         string    `json:"owner"`
	Reason        string    `json:"reason"`
	ExpiresAt     time.Time `json:"expiresAt"`
	AuditMetadata string    `json:"auditMetadata"`
}

type AuditEvent struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Subject   string    `json:"subject"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"createdAt"`
}

type SecretRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type ExternalSecretRef struct {
	Store string `json:"store"`
	Path  string `json:"path"`
	Key   string `json:"key"`
}

type ModelProvider struct {
	Name              string             `json:"name"`
	Type              string             `json:"type"`
	Model             string             `json:"model"`
	APIKeySecretRef   *SecretRef         `json:"apiKeySecretRef,omitempty"`
	ExternalSecretRef *ExternalSecretRef `json:"externalSecretRef,omitempty"`
}

type ModelProviderSettings struct {
	Providers []ModelProvider `json:"providers"`
}

type Integration struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
	Status  string `json:"status"`
}
