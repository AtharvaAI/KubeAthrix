package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
)

const (
	CorrelationVersion = "v1"
	RiskModelVersion   = "v1"
)

type Rule struct {
	Name       string
	Window     time.Duration
	Key        func(core.Finding) string
	RequireKey bool
}

type Config struct {
	CriticalBase           int `json:"criticalBase"`
	HighBase               int `json:"highBase"`
	MediumBase             int `json:"mediumBase"`
	LowBase                int `json:"lowBase"`
	InfoBase               int `json:"infoBase"`
	MultiSourcePoints      int `json:"multiSourcePoints"`
	CorrelatedPointsCap    int `json:"correlatedPointsCap"`
	NetworkPoints          int `json:"networkPoints"`
	IdentityPoints         int `json:"identityPoints"`
	ImagePoints            int `json:"imagePoints"`
	MultiResourcePointsCap int `json:"multiResourcePointsCap"`
	WorkloadWindowMinutes  int `json:"workloadWindowMinutes"`
	ImageWindowMinutes     int `json:"imageWindowMinutes"`
	IdentityWindowMinutes  int `json:"identityWindowMinutes"`
	NetworkWindowMinutes   int `json:"networkWindowMinutes"`
}

func DefaultConfig() Config { return Config{90, 72, 50, 28, 10, 6, 6, 5, 5, 3, 5, 120, 1440, 60, 120} }

func ParseConfig(raw string) (Config, error) {
	config := DefaultConfig()
	if raw == "" {
		return config, nil
	}
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return Config{}, fmt.Errorf("parse risk config: %w", err)
	}
	values := []int{config.CriticalBase, config.HighBase, config.MediumBase, config.LowBase, config.InfoBase}
	if !(values[0] >= values[1] && values[1] >= values[2] && values[2] >= values[3] && values[3] >= values[4] && values[4] >= 0 && values[0] <= 100) {
		return Config{}, fmt.Errorf("risk severity bases must descend from 0 through 100")
	}
	for _, value := range []int{config.MultiSourcePoints, config.CorrelatedPointsCap, config.NetworkPoints, config.IdentityPoints, config.ImagePoints, config.MultiResourcePointsCap} {
		if value < 0 || value > 20 {
			return Config{}, fmt.Errorf("risk factor points must be between 0 and 20")
		}
	}
	for _, value := range []int{config.WorkloadWindowMinutes, config.ImageWindowMinutes, config.IdentityWindowMinutes, config.NetworkWindowMinutes} {
		if value < 1 || value > 10080 {
			return Config{}, fmt.Errorf("correlation windows must be between 1 and 10080 minutes")
		}
	}
	return config, nil
}

func rules(config Config) []Rule {
	return []Rule{
		{Name: "same-workload", Window: time.Duration(config.WorkloadWindowMinutes) * time.Minute, Key: func(f core.Finding) string { return f.CorrelationKeys.Workload }, RequireKey: true},
		{Name: "same-image", Window: time.Duration(config.ImageWindowMinutes) * time.Minute, Key: func(f core.Finding) string { return f.CorrelationKeys.Image }, RequireKey: true},
		{Name: "same-identity", Window: time.Duration(config.IdentityWindowMinutes) * time.Minute, Key: func(f core.Finding) string { return f.CorrelationKeys.Identity }, RequireKey: true},
		{Name: "same-network-exposure", Window: time.Duration(config.NetworkWindowMinutes) * time.Minute, Key: func(f core.Finding) string { return f.CorrelationKeys.NetworkExposure }, RequireKey: true},
	}
}

func Correlate(input []core.Finding) []core.Finding {
	return CorrelateWithConfig(input, DefaultConfig())
}

func CorrelateWithConfig(input []core.Finding, config Config) []core.Finding {
	findings := append([]core.Finding(nil), input...)
	for index := range findings {
		ensureKeys(&findings[index])
	}
	parents := make([]int, len(findings))
	for index := range parents {
		parents[index] = index
	}
	for _, rule := range rules(config) {
		byKey := map[string][]int{}
		for index, finding := range findings {
			key := rule.Key(finding)
			if key == "" && rule.RequireKey {
				continue
			}
			byKey[key] = append(byKey[key], index)
		}
		for _, indexes := range byKey {
			sort.Slice(indexes, func(i, j int) bool { return findings[indexes[i]].UpdatedAt.Before(findings[indexes[j]].UpdatedAt) })
			for start := 0; start < len(indexes); {
				end := start + 1
				for end < len(indexes) && findings[indexes[end]].UpdatedAt.Sub(findings[indexes[start]].UpdatedAt) <= rule.Window {
					union(parents, indexes[start], indexes[end])
					end++
				}
				start = end
			}
		}
	}
	groups := map[int][]int{}
	for index := range findings {
		root := find(parents, index)
		groups[root] = append(groups[root], index)
	}
	for _, indexes := range groups {
		ids := make([]string, 0, len(indexes))
		sources := map[string]struct{}{}
		for _, index := range indexes {
			ids = append(ids, findings[index].ID)
			sources[findings[index].Source] = struct{}{}
		}
		sort.Strings(ids)
		groupID := "corr-" + stable(stringsJoin(ids, "\x00"))
		for _, index := range indexes {
			findings[index].CorrelationGroup = groupID
			findings[index].RiskExplanation = score(findings[index], len(sources), len(indexes), config)
			findings[index].RiskScore = findings[index].RiskExplanation.FinalScore
		}
	}
	return findings
}

func ensureKeys(finding *core.Finding) {
	if finding.CorrelationKeys.Namespace == "" && len(finding.Resources) > 0 {
		resource := finding.Resources[0]
		if resource.Kind == "Namespace" {
			finding.CorrelationKeys.Namespace = resource.Name
		} else {
			finding.CorrelationKeys.Namespace = resource.Namespace
		}
	}
	if finding.CorrelationKeys.Workload == "" && len(finding.Resources) > 0 {
		resource := finding.Resources[0]
		switch resource.Kind {
		case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod":
			finding.CorrelationKeys.Workload = resource.Namespace + "/" + resource.Kind + "/" + resource.Name
		}
	}
}

func score(finding core.Finding, sourceCount, groupSize int, config Config) core.RiskExplanation {
	base := map[core.Severity]int{
		core.SeverityCritical: config.CriticalBase, core.SeverityHigh: config.HighBase, core.SeverityMedium: config.MediumBase,
		core.SeverityLow: config.LowBase, core.SeverityInfo: config.InfoBase,
	}[finding.Severity]
	factors := []core.RiskFactor{}
	add := func(name string, points int, reason string) {
		factors = append(factors, core.RiskFactor{Name: name, Points: points, Reason: reason})
	}
	if sourceCount > 1 {
		add("multi-source-corroboration", config.MultiSourcePoints, "Independent evidence sources are correlated to the same entity.")
	}
	if groupSize > 1 {
		points := min(config.CorrelatedPointsCap, groupSize-1)
		add("correlated-findings", points, "Multiple findings affect the same explicit correlation key within its time window.")
	}
	if finding.CorrelationKeys.NetworkExposure != "" {
		add("network-exposure", config.NetworkPoints, "The affected resource has an explicit network exposure correlation key.")
	}
	if finding.CorrelationKeys.Identity != "" {
		add("identity-impact", config.IdentityPoints, "The evidence affects an explicit Kubernetes identity or permission path.")
	}
	if finding.CorrelationKeys.Image != "" {
		add("image-reuse", config.ImagePoints, "The affected image can be shared by multiple workload replicas or namespaces.")
	}
	if len(finding.Resources) > 1 {
		add("multi-resource-blast-radius", min(config.MultiResourcePointsCap, len(finding.Resources)), "The finding cites multiple affected Kubernetes resources.")
	}
	final := base
	for _, factor := range factors {
		final += factor.Points
	}
	if final > 100 {
		final = 100
	}
	return core.RiskExplanation{Version: RiskModelVersion, BaseScore: base, Factors: factors, FinalScore: final}
}

func find(parents []int, value int) int {
	if parents[value] != value {
		parents[value] = find(parents, parents[value])
	}
	return parents[value]
}

func union(parents []int, left, right int) {
	leftRoot, rightRoot := find(parents, left), find(parents, right)
	if leftRoot != rightRoot {
		parents[rightRoot] = leftRoot
	}
}

func stable(value string) string {
	hash := sha256.Sum256([]byte(CorrelationVersion + "\x00" + value))
	return hex.EncodeToString(hash[:])[:20]
}

func stringsJoin(values []string, separator string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += separator + value
	}
	return result
}
