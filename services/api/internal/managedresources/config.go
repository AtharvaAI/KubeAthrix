package managedresources

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

type jsonAllowlistEntry struct {
	APIGroup   string   `json:"apiGroup"`
	Version    string   `json:"version"`
	Resources  []string `json:"resources"`
	Namespaced *bool    `json:"namespaced"`
}

type jsonConfig struct {
	Enabled   *bool                `json:"enabled"`
	Allowlist []jsonAllowlistEntry `json:"allowlist"`
}

type resourceRule struct {
	gvr        schema.GroupVersionResource
	namespaced bool
}

// ParseConfig parses either the Helm JSON contract or a concise allowlist.
//
// JSON accepts an array of
// {"apiGroup":"s3.aws.upbound.io","version":"v1beta1",
// "resources":["buckets"],"namespaced":true}, or a wrapper containing
// {"enabled":true,"allowlist":[...]}. The concise form is a comma, semicolon,
// or newline separated list of group/version/resource[:namespaced|cluster].
func ParseConfig(raw string) (Config, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Config{}, nil
	}

	if strings.HasPrefix(raw, "[") || strings.HasPrefix(raw, "{") {
		return parseJSONConfig(raw)
	}
	return parseConciseConfig(raw)
}

func parseJSONConfig(raw string) (Config, error) {
	if strings.HasPrefix(strings.TrimSpace(raw), "[") {
		var entries []jsonAllowlistEntry
		if err := decodeStrictJSON(raw, &entries); err != nil {
			return Config{}, fmt.Errorf("parse managed resource allowlist: %w", err)
		}
		return configFromJSONEntries(true, entries)
	}

	var wrapper jsonConfig
	if err := decodeStrictJSON(raw, &wrapper); err != nil {
		return Config{}, fmt.Errorf("parse managed resource config: %w", err)
	}
	enabled := len(wrapper.Allowlist) > 0
	if wrapper.Enabled != nil {
		enabled = *wrapper.Enabled
	}
	return configFromJSONEntries(enabled, wrapper.Allowlist)
}

func decodeStrictJSON(raw string, target any) error {
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func configFromJSONEntries(enabled bool, rawEntries []jsonAllowlistEntry) (Config, error) {
	entries := make([]AllowlistEntry, 0, len(rawEntries))
	for index, entry := range rawEntries {
		if entry.Namespaced == nil {
			return Config{}, fmt.Errorf("allowlist entry %d: namespaced must be explicitly true or false", index)
		}
		entries = append(entries, AllowlistEntry{
			APIGroup:   entry.APIGroup,
			Version:    entry.Version,
			Resources:  entry.Resources,
			Namespaced: *entry.Namespaced,
		})
	}
	return normalizeConfig(Config{Enabled: enabled, Allowlist: entries})
}

func parseConciseConfig(raw string) (Config, error) {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})
	entries := make([]AllowlistEntry, 0, len(parts))
	for index, value := range parts {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		namespaced := true
		path := value
		if separator := strings.LastIndexAny(value, ":@"); separator >= 0 {
			path = strings.TrimSpace(value[:separator])
			scope := strings.ToLower(strings.TrimSpace(value[separator+1:]))
			switch scope {
			case "namespaced", "namespace", "ns":
				namespaced = true
			case "cluster", "cluster-scoped", "clusterscoped":
				namespaced = false
			default:
				return Config{}, fmt.Errorf("allowlist entry %d: unsupported scope %q", index, scope)
			}
		}
		segments := strings.Split(path, "/")
		if len(segments) != 3 {
			return Config{}, fmt.Errorf("allowlist entry %d: expected group/version/resource, got %q", index, value)
		}
		entries = append(entries, AllowlistEntry{
			APIGroup:   strings.TrimSpace(segments[0]),
			Version:    strings.TrimSpace(segments[1]),
			Resources:  []string{strings.TrimSpace(segments[2])},
			Namespaced: namespaced,
		})
	}
	return normalizeConfig(Config{Enabled: len(entries) > 0, Allowlist: entries})
}

func normalizeConfig(config Config) (Config, error) {
	if config.Enabled && len(config.Allowlist) == 0 {
		return Config{}, fmt.Errorf("managed resource discovery is enabled but the allowlist is empty")
	}

	type groupKey struct {
		apiGroup   string
		version    string
		namespaced bool
	}
	grouped := map[groupKey]map[string]struct{}{}
	resourceScopes := map[schema.GroupVersionResource]bool{}
	for index, entry := range config.Allowlist {
		apiGroup := strings.TrimSpace(entry.APIGroup)
		version := strings.TrimSpace(entry.Version)
		if err := validateSegment("apiGroup", apiGroup, true); err != nil {
			return Config{}, fmt.Errorf("allowlist entry %d: %w", index, err)
		}
		if err := validateSegment("version", version, false); err != nil {
			return Config{}, fmt.Errorf("allowlist entry %d: %w", index, err)
		}
		if len(entry.Resources) == 0 {
			return Config{}, fmt.Errorf("allowlist entry %d: resources must not be empty", index)
		}
		key := groupKey{apiGroup: apiGroup, version: version, namespaced: entry.Namespaced}
		if grouped[key] == nil {
			grouped[key] = map[string]struct{}{}
		}
		for resourceIndex, rawResource := range entry.Resources {
			resource := strings.TrimSpace(rawResource)
			if err := validateSegment("resource", resource, false); err != nil {
				return Config{}, fmt.Errorf("allowlist entry %d resource %d: %w", index, resourceIndex, err)
			}
			gvr := schema.GroupVersionResource{Group: apiGroup, Version: version, Resource: resource}
			if priorScope, exists := resourceScopes[gvr]; exists && priorScope != entry.Namespaced {
				return Config{}, fmt.Errorf("allowlist resource %s has conflicting namespaced values", gvr.String())
			}
			resourceScopes[gvr] = entry.Namespaced
			grouped[key][resource] = struct{}{}
		}
	}
	if len(resourceScopes) > 128 {
		return Config{}, fmt.Errorf("managed resource allowlist exceeds the safety limit of 128 resources")
	}

	keys := make([]groupKey, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].apiGroup != keys[j].apiGroup {
			return keys[i].apiGroup < keys[j].apiGroup
		}
		if keys[i].version != keys[j].version {
			return keys[i].version < keys[j].version
		}
		return !keys[i].namespaced && keys[j].namespaced
	})
	normalized := Config{Enabled: config.Enabled, Allowlist: make([]AllowlistEntry, 0, len(keys))}
	for _, key := range keys {
		resources := make([]string, 0, len(grouped[key]))
		for resource := range grouped[key] {
			resources = append(resources, resource)
		}
		sort.Strings(resources)
		normalized.Allowlist = append(normalized.Allowlist, AllowlistEntry{
			APIGroup:   key.apiGroup,
			Version:    key.version,
			Resources:  resources,
			Namespaced: key.namespaced,
		})
	}
	return normalized, nil
}

func validateSegment(name, value string, apiGroup bool) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if strings.Contains(value, "*") {
		return fmt.Errorf("%s must not contain wildcards", name)
	}
	if apiGroup && strings.EqualFold(value, "core") {
		return fmt.Errorf("core API group is not allowed")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			continue
		}
		return fmt.Errorf("%s %q contains unsupported character %q", name, value, r)
	}
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return fmt.Errorf("%s %q is malformed", name, value)
	}
	return nil
}

func configRules(config Config) []resourceRule {
	rules := make([]resourceRule, 0)
	for _, entry := range config.Allowlist {
		for _, resource := range entry.Resources {
			rules = append(rules, resourceRule{
				gvr: schema.GroupVersionResource{
					Group:    entry.APIGroup,
					Version:  entry.Version,
					Resource: resource,
				},
				namespaced: entry.Namespaced,
			})
		}
	}
	return rules
}
