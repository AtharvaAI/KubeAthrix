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
	TotalFindings        int                 `json:"totalFindings"`
	OpenCritical         int                 `json:"openCritical"`
	PendingApprovals     int                 `json:"pendingApprovals"`
	ActiveRemediations   int                 `json:"activeRemediations"`
	VerifiedRemediations int                 `json:"verifiedRemediations"`
	FindingsWithSafeFix  int                 `json:"findingsWithSafeFix"`
	RiskReduced          int                 `json:"riskReduced"`
	EvidenceFreshness    string              `json:"evidenceFreshness"`
	MeanRiskScore        float64             `json:"meanRiskScore"`
	FindingsBySeverity   map[string]int      `json:"findingsBySeverity"`
	FindingsBySource     map[string]int      `json:"findingsBySource"`
	RemediationByState   map[string]int      `json:"remediationByState"`
	ProtectedNamespaces  int                 `json:"protectedNamespaces"`
	BundledEnginesOnline int                 `json:"bundledEnginesOnline"`
	Cluster              ClusterInventory    `json:"cluster"`
	Scan                 ScanSummary         `json:"scan"`
	Compliance           []ComplianceControl `json:"compliance"`
	Experiments          []ChaosExperiment   `json:"experiments"`
}

type ClusterInventory struct {
	Nodes                    int `json:"nodes"`
	ReadyNodes               int `json:"readyNodes"`
	Namespaces               int `json:"namespaces"`
	Pods                     int `json:"pods"`
	RunningPods              int `json:"runningPods"`
	PendingPods              int `json:"pendingPods"`
	Deployments              int `json:"deployments"`
	StatefulSets             int `json:"statefulSets"`
	DaemonSets               int `json:"daemonSets"`
	Services                 int `json:"services"`
	Ingresses                int `json:"ingresses"`
	Jobs                     int `json:"jobs"`
	ConfigMaps               int `json:"configMaps"`
	Secrets                  int `json:"secrets"`
	ServiceAccounts          int `json:"serviceAccounts"`
	Roles                    int `json:"roles"`
	RoleBindings             int `json:"roleBindings"`
	ClusterRoles             int `json:"clusterRoles"`
	ClusterRoleBindings      int `json:"clusterRoleBindings"`
	NetworkPolicies          int `json:"networkPolicies"`
	ResourceQuotas           int `json:"resourceQuotas"`
	LimitRanges              int `json:"limitRanges"`
	PersistentVolumeClaims   int `json:"persistentVolumeClaims"`
	PodDisruptionBudgets     int `json:"podDisruptionBudgets"`
	HorizontalPodAutoscalers int `json:"horizontalPodAutoscalers"`
	Events                   int `json:"events"`
}

type ScanSummary struct {
	LastRunAt           time.Time `json:"lastRunAt"`
	ResourcesScanned    int       `json:"resourcesScanned"`
	PolicyChecks        int       `json:"policyChecks"`
	PermissionChecks    int       `json:"permissionChecks"`
	ConfigurationChecks int       `json:"configurationChecks"`
	ComplianceControls  int       `json:"complianceControls"`
	PassedControls      int       `json:"passedControls"`
	FailedControls      int       `json:"failedControls"`
}

type ComplianceControl struct {
	ID        string   `json:"id"`
	Framework string   `json:"framework"`
	Title     string   `json:"title"`
	Status    string   `json:"status"`
	Severity  Severity `json:"severity"`
	Evidence  string   `json:"evidence"`
}

type ChaosExperiment struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Target      string   `json:"target"`
	Status      string   `json:"status"`
	Engine      string   `json:"engine"`
	Description string   `json:"description"`
	Preflight   []string `json:"preflight"`
	Manifest    string   `json:"manifest"`
}

type ChaosExperimentRun struct {
	ID           string    `json:"id"`
	ExperimentID string    `json:"experimentId"`
	Status       string    `json:"status"`
	Message      string    `json:"message"`
	Manifest     string    `json:"manifest"`
	CreatedAt    time.Time `json:"createdAt"`
}

type ClusterSnapshot struct {
	Inventory   ClusterInventory    `json:"inventory"`
	Findings    []Finding           `json:"findings"`
	Scan        ScanSummary         `json:"scan"`
	Compliance  []ComplianceControl `json:"compliance"`
	Experiments []ChaosExperiment   `json:"experiments"`
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

type EvidenceCitation struct {
	SourceID   string    `json:"sourceId"`
	Summary    string    `json:"summary"`
	Resource   string    `json:"resource"`
	ObservedAt time.Time `json:"observedAt"`
}

type RemediationPreview struct {
	FindingID             string             `json:"findingId"`
	Summary               string             `json:"summary"`
	Candidate             RemediationPlan    `json:"candidate"`
	EvidenceCitations     []EvidenceCitation `json:"evidenceCitations"`
	PromptEvidenceHash    string             `json:"promptEvidenceHash"`
	DeterministicFallback bool               `json:"deterministicFallback"`
	SafetyNotes           []string           `json:"safetyNotes"`
	GeneratedAt           time.Time          `json:"generatedAt"`
}

type PlannedManifest struct {
	ActionType string      `json:"actionType"`
	Target     ResourceRef `json:"target"`
	WriteMode  string      `json:"writeMode"`
	Diff       string      `json:"diff"`
	Manifest   string      `json:"manifest"`
}

type RemediationDiff struct {
	PlanID    string            `json:"planId"`
	Mode      string            `json:"mode"`
	Summary   string            `json:"summary"`
	Manifests []PlannedManifest `json:"manifests"`
}

type FindingGroup struct {
	GroupBy         string    `json:"groupBy"`
	Key             string    `json:"key"`
	Count           int       `json:"count"`
	MeanRiskScore   float64   `json:"meanRiskScore"`
	HighestSeverity Severity  `json:"highestSeverity"`
	Findings        []Finding `json:"findings"`
}

type FindingListResponse struct {
	Items  []Finding      `json:"items"`
	Groups []FindingGroup `json:"groups,omitempty"`
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

type EvidenceBundle struct {
	Scope       string            `json:"scope"`
	GeneratedAt time.Time         `json:"generatedAt"`
	Summary     map[string]int    `json:"summary"`
	Findings    []Finding         `json:"findings"`
	Plans       []RemediationPlan `json:"plans"`
	Runs        []RemediationRun  `json:"runs"`
	AuditEvents []AuditEvent      `json:"auditEvents"`
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

type IntegrationHealth struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Enabled      bool      `json:"enabled"`
	Status       string    `json:"status"`
	Health       string    `json:"health"`
	DataLastSeen string    `json:"dataLastSeen"`
	Permissions  []string  `json:"permissions"`
	SetupGaps    []string  `json:"setupGaps"`
	CheckedAt    time.Time `json:"checkedAt"`
}
