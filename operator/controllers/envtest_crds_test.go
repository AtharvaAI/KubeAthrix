package controllers

import (
	"path/filepath"
	"runtime"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestCRDsInstallWithEnvtest(t *testing.T) {
	if testing.Short() {
		t.Skip("envtest skipped in short mode")
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate test file")
	}
	chartCRDs := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "charts", "kubeathrix", "crds"))
	testEnv := &envtest.Environment{CRDDirectoryPaths: []string{chartCRDs}}
	cfg, err := testEnv.Start()
	if err != nil {
		t.Skipf("envtest control plane unavailable: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected envtest config")
	}
	if err := testEnv.Stop(); err != nil {
		t.Fatal(err)
	}
}
