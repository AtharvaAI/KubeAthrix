package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/adapters"
	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/managedresources"
)

type fixedManagedDiscoverer struct {
	snapshot managedresources.Snapshot
	calls    int
	err      error
}

func (f *fixedManagedDiscoverer) Discover(context.Context) (managedresources.Snapshot, error) {
	f.calls++
	return f.snapshot, f.err
}

type fixedAdapterManager struct{ collection adapters.Collection }

func (f fixedAdapterManager) Collect(context.Context) adapters.Collection { return f.collection }

type blockingManagedDiscoverer struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once

	mu    sync.Mutex
	calls int
}

func (b *blockingManagedDiscoverer) Discover(ctx context.Context) (managedresources.Snapshot, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	b.once.Do(func() { close(b.started) })
	select {
	case <-ctx.Done():
		return managedresources.Snapshot{}, ctx.Err()
	case <-b.release:
		return managedresources.Snapshot{ObservedAt: time.Now().UTC()}, nil
	}
}

func (b *blockingManagedDiscoverer) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func TestManagedAdapterManagerMergesFindingsForAPIAndAgent(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	managedFinding := core.Finding{ID: "managed-resource-not-ready", Source: "managed-resource", RiskScore: 82}
	source := &fixedManagedDiscoverer{snapshot: managedresources.Snapshot{
		ObservedAt: now,
		Findings:   []core.Finding{managedFinding},
	}}
	manager := &managedAdapterManager{
		base:   fixedAdapterManager{collection: adapters.Collection{Findings: []core.Finding{{ID: "native", RiskScore: 10}}}},
		source: source,
		config: managedresources.Config{Enabled: true, Allowlist: []managedresources.AllowlistEntry{{
			APIGroup: "iam.example.io", Version: "v1", Resources: []string{"roles"}, Namespaced: true,
		}}},
		now: func() time.Time { return now },
	}

	collection := manager.Collect(context.Background())
	if len(collection.Findings) != 2 || collection.Findings[0].ID != managedFinding.ID {
		t.Fatalf("managed finding was not merged into the shared adapter stream: %#v", collection.Findings)
	}
	if len(collection.Integrations) != 1 || collection.Integrations[0].Type != "managed-resource" {
		t.Fatalf("managed integration health is missing: %#v", collection.Integrations)
	}
	if len(collection.Health) != 1 || collection.Health[0].FindingsCount != 1 {
		t.Fatalf("managed integration finding count is wrong: %#v", collection.Health)
	}
}

func TestManagedResourceCacheBoundsKubernetesListFrequency(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	source := &fixedManagedDiscoverer{snapshot: managedresources.Snapshot{ObservedAt: now}}
	cache := &managedResourceCache{source: source, now: func() time.Time { return now }, ttl: 30 * time.Second}
	if _, err := cache.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if source.calls != 1 {
		t.Fatalf("expected one Kubernetes discovery call inside the TTL, got %d", source.calls)
	}
	now = now.Add(31 * time.Second)
	if _, err := cache.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if source.calls != 2 {
		t.Fatalf("expected cache refresh after the TTL, got %d calls", source.calls)
	}
}

func TestManagedResourceCacheServesExplicitStaleSnapshotOnRefreshFailure(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	source := &fixedManagedDiscoverer{snapshot: managedresources.Snapshot{
		ObservedAt: now,
		Resources:  []managedresources.Resource{{ID: "known-good", Name: "known-good"}},
	}}
	cache := &managedResourceCache{source: source, now: func() time.Time { return now }, ttl: 30 * time.Second}
	if _, err := cache.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * time.Second)
	source.err = errors.New("temporary Kubernetes API failure")
	snapshot, err := cache.Discover(context.Background())
	if err != nil {
		t.Fatalf("last-good fallback returned an error: %v", err)
	}
	if len(snapshot.Resources) != 1 || snapshot.Resources[0].ID != "known-good" {
		t.Fatalf("last-good snapshot was not retained: %#v", snapshot.Resources)
	}
	if len(snapshot.Warnings) != 1 || snapshot.Warnings[0].Code != "stale_snapshot" {
		t.Fatalf("stale fallback was not explicit: %#v", snapshot.Warnings)
	}
}

func TestManagedResourceCacheCoalescesConcurrentRefreshesWithoutHoldingLockDuringIO(t *testing.T) {
	source := &blockingManagedDiscoverer{started: make(chan struct{}), release: make(chan struct{})}
	cache := &managedResourceCache{source: source, now: time.Now, ttl: 30 * time.Second}

	results := make(chan error, 2)
	go func() {
		_, err := cache.Discover(context.Background())
		results <- err
	}()
	<-source.started
	go func() {
		_, err := cache.Discover(context.Background())
		results <- err
	}()

	time.Sleep(10 * time.Millisecond)
	if calls := source.callCount(); calls != 1 {
		t.Fatalf("expected concurrent refreshes to share one Kubernetes call, got %d", calls)
	}
	close(source.release)
	for index := 0; index < 2; index++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent cache read failed: %v", err)
		}
	}
	if calls := source.callCount(); calls != 1 {
		t.Fatalf("expected one completed Kubernetes call, got %d", calls)
	}
}
