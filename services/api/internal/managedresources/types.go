package managedresources

import (
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
)

const RedactedValue = "[REDACTED]"

type Config struct {
	Enabled   bool             `json:"enabled"`
	Allowlist []AllowlistEntry `json:"allowlist"`
}

type AllowlistEntry struct {
	APIGroup   string   `json:"apiGroup"`
	Version    string   `json:"version"`
	Resources  []string `json:"resources"`
	Namespaced bool     `json:"namespaced"`
}

type ManagementSystem string

const (
	ManagementArgoCD     ManagementSystem = "argocd"
	ManagementFlux       ManagementSystem = "flux"
	ManagementHelm       ManagementSystem = "helm"
	ManagementCrossplane ManagementSystem = "crossplane"
	ManagementOperator   ManagementSystem = "operator"
	ManagementUnknown    ManagementSystem = "unknown"
)

type Provenance struct {
	System     ManagementSystem `json:"system"`
	Controller string           `json:"controller,omitempty"`
	SourceRef  string           `json:"sourceRef,omitempty"`
	GitOps     bool             `json:"gitOps"`
	Signals    []string         `json:"signals,omitempty"`
}

type ResourceReference struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
}

type RelationshipType string

const (
	RelationshipOwner     RelationshipType = "owned_by"
	RelationshipReference RelationshipType = "references"
	RelationshipClaim     RelationshipType = "claimed_by"
)

type Relationship struct {
	From ResourceReference `json:"from"`
	To   ResourceReference `json:"to"`
	Type RelationshipType  `json:"type"`
	Path string            `json:"path,omitempty"`
}

type Condition struct {
	Type               string     `json:"type"`
	Status             string     `json:"status"`
	Reason             string     `json:"reason,omitempty"`
	Message            string     `json:"-"`
	ObservedGeneration int64      `json:"observedGeneration,omitempty"`
	LastTransitionTime *time.Time `json:"lastTransitionTime,omitempty"`
}

type ResourceStatus struct {
	Ready              *bool       `json:"ready,omitempty"`
	Synced             *bool       `json:"synced,omitempty"`
	Stalled            *bool       `json:"stalled,omitempty"`
	State              string      `json:"state,omitempty"`
	ObservedGeneration int64       `json:"observedGeneration,omitempty"`
	Conditions         []Condition `json:"conditions,omitempty"`
}

// Resource is a read-only representation of an allowlisted object. Spec,
// labels, annotations, and condition messages remain internal analysis inputs
// and are deliberately omitted from serialized API/model evidence.
type Resource struct {
	ID                string            `json:"id"`
	APIGroup          string            `json:"apiGroup"`
	Version           string            `json:"version"`
	Plural            string            `json:"plural"`
	APIVersion        string            `json:"apiVersion"`
	Kind              string            `json:"kind"`
	Namespace         string            `json:"namespace,omitempty"`
	Name              string            `json:"name"`
	UID               string            `json:"uid,omitempty"`
	Generation        int64             `json:"generation,omitempty"`
	CreatedAt         time.Time         `json:"createdAt,omitempty"`
	DeletionTimestamp *time.Time        `json:"deletionTimestamp,omitempty"`
	Finalizers        []string          `json:"finalizers,omitempty"`
	Labels            map[string]string `json:"-"`
	Annotations       map[string]string `json:"-"`
	Spec              map[string]any    `json:"-"`
	ExternalID        string            `json:"externalId,omitempty"`
	Status            ResourceStatus    `json:"status"`
	Provenance        Provenance        `json:"provenance"`
}

func (r Resource) Reference() ResourceReference {
	return ResourceReference{
		APIVersion: r.APIVersion,
		Kind:       r.Kind,
		Namespace:  r.Namespace,
		Name:       r.Name,
		UID:        r.UID,
	}
}

type Warning struct {
	APIGroup string `json:"apiGroup"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type Snapshot struct {
	ObservedAt    time.Time      `json:"observedAt"`
	Resources     []Resource     `json:"resources"`
	Relationships []Relationship `json:"relationships"`
	Findings      []core.Finding `json:"findings"`
	Warnings      []Warning      `json:"warnings,omitempty"`
}
