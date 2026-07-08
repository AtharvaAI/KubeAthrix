package controllers

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var FindingGVK = schema.GroupVersionKind{
	Group:   "security.kubeathrix.io",
	Version: "v1alpha1",
	Kind:    "Finding",
}

type FindingReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Clock  func() time.Time
}

// +kubebuilder:rbac:groups=security.kubeathrix.io,resources=findings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.kubeathrix.io,resources=findings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.kubeathrix.io,resources=findings/finalizers,verbs=update

func (r *FindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	finding := NewFindingObject(req.NamespacedName)
	if err := r.Get(ctx, req.NamespacedName, finding); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if controllerutil.AddFinalizer(finding, "finding.security.kubeathrix.io/audit") {
		if err := r.Update(ctx, finding); err != nil {
			return ctrl.Result{}, err
		}
	}

	phase, _, _ := unstructured.NestedString(finding.Object, "status", "phase")
	observedGeneration, _, _ := unstructured.NestedInt64(finding.Object, "status", "observedGeneration")
	if phase == "Observed" && observedGeneration == finding.GetGeneration() {
		return ctrl.Result{}, nil
	}

	now := time.Now().UTC()
	if r.Clock != nil {
		now = r.Clock().UTC()
	}
	if _, ok := finding.Object["status"].(map[string]any); !ok {
		finding.Object["status"] = map[string]any{}
	}
	if err := unstructured.SetNestedField(finding.Object, "Observed", "status", "phase"); err != nil {
		return ctrl.Result{}, err
	}
	if err := unstructured.SetNestedField(finding.Object, finding.GetGeneration(), "status", "observedGeneration"); err != nil {
		return ctrl.Result{}, err
	}
	if err := unstructured.SetNestedField(finding.Object, now.Format(time.RFC3339), "status", "lastTransitionTime"); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.Status().Update(ctx, finding); err != nil {
		logger.Error(err, "failed to update finding status")
		return ctrl.Result{}, err
	}
	logger.Info("observed finding", "finding", req.NamespacedName.String())
	return ctrl.Result{}, nil
}

func (r *FindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(NewFindingObject(types.NamespacedName{})).
		Complete(r)
}

func NewFindingObject(name types.NamespacedName) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(FindingGVK)
	obj.SetNamespace(name.Namespace)
	obj.SetName(name.Name)
	return obj
}
