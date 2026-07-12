package main

import (
	"flag"
	"os"

	"github.com/atharvaai/kubeathrix/operator/controllers"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func main() {
	var probeAddr string
	var leaderElection bool
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "address for health and readiness probes")
	flag.BoolVar(&leaderElection, "leader-elect", false, "enable leader election for controller manager")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		ctrl.Log.Error(err, "unable to add Kubernetes types to scheme")
		os.Exit(1)
	}
	scheme.AddKnownTypeWithName(controllers.FindingGVK, controllers.NewFindingObject(ctrl.Request{}.NamespacedName))
	scheme.AddKnownTypeWithName(controllers.RemediationPlanGVK, controllers.NewRemediationPlanObject(ctrl.Request{}.NamespacedName))
	scheme.AddKnownTypeWithName(controllers.RemediationRunGVK, controllers.NewRemediationRunObject(ctrl.Request{}.NamespacedName))
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElection,
		LeaderElectionID:       "kubeathrix-operator.security.kubeathrix.io",
	})
	if err != nil {
		ctrl.Log.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := (&controllers.FindingReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		ctrl.Log.Error(err, "unable to create finding controller")
		os.Exit(1)
	}

	if err := (&controllers.RemediationPlanReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		MutationEnabled: os.Getenv("KUBEATHRIX_MUTATION_ENABLED") == "true",
	}).SetupWithManager(mgr); err != nil {
		ctrl.Log.Error(err, "unable to create remediation plan controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		ctrl.Log.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		ctrl.Log.Error(err, "unable to set up readiness check")
		os.Exit(1)
	}

	ctrl.Log.Info("starting kubeathrix operator")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		ctrl.Log.Error(err, "manager stopped")
		os.Exit(1)
	}
}
