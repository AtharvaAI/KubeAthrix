package managedresources

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseConfigJSONAndConcise(t *testing.T) {
	config, err := ParseConfig(`{
		"enabled": true,
		"allowlist": [
			{"apiGroup":"iam.aws.upbound.io","version":"v1beta1","resources":["roles","policies"],"namespaced":true}
		]
	}`)
	if err != nil {
		t.Fatalf("ParseConfig JSON: %v", err)
	}
	if !config.Enabled || len(config.Allowlist) != 1 {
		t.Fatalf("unexpected config: %#v", config)
	}
	if got := strings.Join(config.Allowlist[0].Resources, ","); got != "policies,roles" {
		t.Fatalf("resources were not normalized: %q", got)
	}

	concise, err := ParseConfig("s3.aws.upbound.io/v1beta1/buckets:namespaced;iam.services.k8s.aws/v1alpha1/roles:cluster")
	if err != nil {
		t.Fatalf("ParseConfig concise: %v", err)
	}
	if !concise.Enabled || len(configRules(concise)) != 2 {
		t.Fatalf("unexpected concise config: %#v", concise)
	}
}

func TestNormalizeConfigRejectsOversizedAllowlist(t *testing.T) {
	resources := make([]string, 129)
	for index := range resources {
		resources[index] = fmt.Sprintf("resource-%d", index)
	}
	_, err := normalizeConfig(Config{Enabled: true, Allowlist: []AllowlistEntry{{APIGroup: "example.io", Version: "v1", Resources: resources, Namespaced: true}}})
	if err == nil || !strings.Contains(err.Error(), "128") {
		t.Fatalf("oversized allowlist was not rejected: %v", err)
	}
}

func TestParseConfigRejectsBroadAccess(t *testing.T) {
	for _, raw := range []string{
		`[{"apiGroup":"","version":"v1","resources":["secrets"],"namespaced":true}]`,
		`[{"apiGroup":"core","version":"v1","resources":["secrets"],"namespaced":true}]`,
		`[{"apiGroup":"iam.aws.upbound.io","version":"v1beta1","resources":["*"],"namespaced":true}]`,
		`[{"apiGroup":"iam.aws.upbound.io","version":"v1beta1","resources":["roles"]}]`,
		`{"enabled":true,"allowlist":[]}`,
	} {
		if _, err := ParseConfig(raw); err == nil {
			t.Fatalf("expected invalid config to be rejected: %s", raw)
		}
	}
}
