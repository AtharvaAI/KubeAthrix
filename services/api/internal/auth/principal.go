package auth

import (
	"context"
	"errors"
	"strings"
)

type Role string

const (
	RoleViewer        Role = "viewer"
	RoleOperator      Role = "operator"
	RoleApprover      Role = "approver"
	RoleAdministrator Role = "administrator"
)

var (
	ErrUnauthenticated = errors.New("authentication required")
	ErrUnauthorized    = errors.New("insufficient permissions")
)

type Principal struct {
	Subject     string
	DisplayName string
	Roles       map[Role]struct{}
	Namespaces  map[string]struct{}
	Clusters    map[string]struct{}
}

func (p Principal) Actor() string {
	if strings.TrimSpace(p.DisplayName) != "" {
		return strings.TrimSpace(p.DisplayName) + " (" + p.Subject + ")"
	}
	return p.Subject
}

func (p Principal) HasRole(required Role) bool {
	if _, ok := p.Roles[RoleAdministrator]; ok {
		return true
	}
	if required == RoleViewer {
		return len(p.Roles) > 0
	}
	if required == RoleOperator {
		_, operator := p.Roles[RoleOperator]
		_, approver := p.Roles[RoleApprover]
		return operator || approver
	}
	_, ok := p.Roles[required]
	return ok
}

func (p Principal) CanAccessCluster(clusterID string) bool {
	if p.HasRole(RoleAdministrator) {
		return true
	}
	if _, ok := p.Clusters["*"]; ok {
		return true
	}
	_, ok := p.Clusters[clusterID]
	return ok
}

func (p Principal) CanAccessNamespace(clusterID, namespace string) bool {
	if p.CanAccessCluster(clusterID) {
		return true
	}
	if _, ok := p.Namespaces["*"]; ok {
		return true
	}
	_, ok := p.Namespaces[namespace]
	return ok
}

type contextKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(contextKey{}).(Principal)
	return principal, ok
}

type Verifier interface {
	Verify(ctx context.Context, rawToken string) (Principal, error)
}

type StaticVerifier struct {
	Principal Principal
}

func (v StaticVerifier) Verify(_ context.Context, _ string) (Principal, error) {
	if v.Principal.Subject == "" {
		return Principal{}, ErrUnauthenticated
	}
	return v.Principal, nil
}

func DevelopmentPrincipal() Principal {
	return Principal{
		Subject:     "insecure-development-user",
		DisplayName: "Insecure development administrator",
		Roles:       map[Role]struct{}{RoleAdministrator: {}},
		Namespaces:  map[string]struct{}{"*": {}},
		Clusters:    map[string]struct{}{"*": {}},
	}
}
