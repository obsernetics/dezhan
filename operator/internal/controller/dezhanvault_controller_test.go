package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	dezhanv1alpha1 "github.com/obsernetics/dezhan/operator/api/v1alpha1"
)

// TestReconcileCreatesResources spins up a real kube-apiserver + etcd via
// envtest, applies the DezhanVault CRD, creates a vault, and asserts the
// controller reconciles it into a Service, a StatefulSet, and a PVC template
// with the expected fields and owner references. envtest has no kubelet, so we
// do not assert pod readiness here (that needs a full cluster).
func TestReconcileCreatesResources(t *testing.T) {
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest (is KUBEBUILDER_ASSETS set?): %v", err)
	}
	defer func() { _ = env.Stop() }()

	if err := dezhanv1alpha1.AddToScheme(scheme.Scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	vault := &dezhanv1alpha1.DezhanVault{
		ObjectMeta: metav1.ObjectMeta{Name: "test-vault", Namespace: "default"},
		Spec: dezhanv1alpha1.DezhanVaultSpec{
			Storage:      resource.MustParse("10Gi"),
			RequireAuth:  true,
			DeleteQuorum: 2,
			SecretName:   "test-secrets",
		},
	}
	if err := c.Create(ctx, vault); err != nil {
		t.Fatalf("create vault: %v", err)
	}

	r := &DezhanVaultReconciler{Client: c, Scheme: scheme.Scheme}
	key := types.NamespacedName{Name: "test-vault", Namespace: "default"}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Service exists, headless, with the s3 port.
	var svc corev1.Service
	if err := c.Get(ctx, key, &svc); err != nil {
		t.Fatalf("service not created: %v", err)
	}
	if svc.Spec.ClusterIP != corev1.ClusterIPNone {
		t.Errorf("service: want headless ClusterIP None, got %q", svc.Spec.ClusterIP)
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 8080 {
		t.Errorf("service: want one port 8080, got %+v", svc.Spec.Ports)
	}
	if len(svc.OwnerReferences) != 1 || svc.OwnerReferences[0].Name != "test-vault" {
		t.Errorf("service: missing owner reference to vault")
	}

	// StatefulSet exists, single replica, env wired, PVC sized.
	var sts appsv1.StatefulSet
	if err := c.Get(ctx, key, &sts); err != nil {
		t.Fatalf("statefulset not created: %v", err)
	}
	if sts.Spec.Replicas == nil || *sts.Spec.Replicas != 1 {
		t.Errorf("statefulset: want 1 replica, got %v", sts.Spec.Replicas)
	}
	if len(sts.Spec.VolumeClaimTemplates) != 1 {
		t.Fatalf("statefulset: want 1 PVC template, got %d", len(sts.Spec.VolumeClaimTemplates))
	}
	got := sts.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests[corev1.ResourceStorage]
	if got.Cmp(resource.MustParse("10Gi")) != 0 {
		t.Errorf("statefulset PVC: want 10Gi, got %s", got.String())
	}
	cont := sts.Spec.Template.Spec.Containers[0]
	if !hasEnv(cont.Env, "DEZHAN_REQUIRE_AUTH", "1") {
		t.Errorf("statefulset: DEZHAN_REQUIRE_AUTH=1 not set")
	}
	if !hasEnv(cont.Env, "DEZHAN_DELETE_QUORUM", "2") {
		t.Errorf("statefulset: DEZHAN_DELETE_QUORUM=2 not set")
	}
	if cont.SecurityContext == nil || cont.SecurityContext.ReadOnlyRootFilesystem == nil ||
		!*cont.SecurityContext.ReadOnlyRootFilesystem {
		t.Errorf("statefulset: container should have read-only root filesystem")
	}

	// Status carries the endpoint.
	var got2 dezhanv1alpha1.DezhanVault
	if err := c.Get(ctx, key, &got2); err != nil {
		t.Fatal(err)
	}
	if got2.Status.Endpoint != "test-vault.default.svc:8080" {
		t.Errorf("status endpoint: got %q", got2.Status.Endpoint)
	}

	// PodDisruptionBudget protects the single writer (minAvailable=1).
	var pdb policyv1.PodDisruptionBudget
	if err := c.Get(ctx, key, &pdb); err != nil {
		t.Fatalf("pdb not created: %v", err)
	}
	if pdb.Spec.MinAvailable == nil || pdb.Spec.MinAvailable.IntValue() != 1 {
		t.Errorf("pdb: want minAvailable=1, got %v", pdb.Spec.MinAvailable)
	}

	// StatefulSet retains its PVC on delete/scale (data must outlive the object).
	if rp := sts.Spec.PersistentVolumeClaimRetentionPolicy; rp == nil ||
		rp.WhenDeleted != appsv1.RetainPersistentVolumeClaimRetentionPolicyType {
		t.Errorf("statefulset: PVC retention policy should be Retain on delete")
	}

	// No update churn: a second reconcile against a steady state must not
	// rewrite the StatefulSet. If it does, the controller is fighting the API
	// server's pod-template defaults and would spin in a hot loop.
	var before appsv1.StatefulSet
	if err := c.Get(ctx, key, &before); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	var after appsv1.StatefulSet
	if err := c.Get(ctx, key, &after); err != nil {
		t.Fatal(err)
	}
	if before.ResourceVersion != after.ResourceVersion {
		t.Errorf("statefulset churned on no-op reconcile: rv %s -> %s",
			before.ResourceVersion, after.ResourceVersion)
	}

	// A spec change must be applied (image roll).
	if err := c.Get(ctx, key, &got2); err != nil {
		t.Fatal(err)
	}
	got2.Spec.Image = "ghcr.io/obsernetics/dezhan:v2"
	if err := c.Update(ctx, &got2); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile after image change: %v", err)
	}
	var rolled appsv1.StatefulSet
	if err := c.Get(ctx, key, &rolled); err != nil {
		t.Fatal(err)
	}
	if got := rolled.Spec.Template.Spec.Containers[0].Image; got != "ghcr.io/obsernetics/dezhan:v2" {
		t.Errorf("image not rolled: got %q", got)
	}
}

func hasEnv(env []corev1.EnvVar, name, val string) bool {
	for _, e := range env {
		if e.Name == name && e.Value == val {
			return true
		}
	}
	return false
}
