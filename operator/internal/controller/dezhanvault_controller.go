package controller

import (
	"context"
	"fmt"
	"strconv"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	dezhanv1alpha1 "github.com/obsernetics/dezhan/operator/api/v1alpha1"
)

const (
	containerName = "dezhan"
	dataVolume    = "data"
	fieldOwnerUID = 65532 // distroless 'nonroot'
	requeueWait   = 20 * time.Second
)

// DezhanVaultReconciler reconciles a DezhanVault into a headless Service and a
// single-replica StatefulSet backed by a persistent volume.
type DezhanVaultReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=dezhan.obsernetics.io,resources=dezhanvaults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dezhan.obsernetics.io,resources=dezhanvaults/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=dezhan.obsernetics.io,resources=dezhanvaults/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *DezhanVaultReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var vault dezhanv1alpha1.DezhanVault
	if err := r.Get(ctx, req.NamespacedName, &vault); err != nil {
		// Ignore not-found: owned objects are garbage-collected via ownerRefs.
		// PersistentVolumeClaims created by the StatefulSet are intentionally
		// retained so vault data survives a CR deletion.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !vault.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	applyDefaults(&vault)

	if err := r.reconcileService(ctx, &vault); err != nil {
		return r.fail(ctx, &vault, "ServiceError", err)
	}
	if err := r.reconcileStatefulSet(ctx, &vault); err != nil {
		return r.fail(ctx, &vault, "StatefulSetError", err)
	}
	if err := r.reconcilePVCExpansion(ctx, &vault); err != nil {
		return r.fail(ctx, &vault, "ExpansionError", err)
	}
	if err := r.reconcilePDB(ctx, &vault); err != nil {
		return r.fail(ctx, &vault, "PDBError", err)
	}

	var sts appsv1.StatefulSet
	if err := r.Get(ctx, req.NamespacedName, &sts); err != nil {
		return ctrl.Result{}, err
	}
	ready := sts.Status.ReadyReplicas >= 1

	if err := r.updateStatus(ctx, &vault, ready); err != nil {
		return ctrl.Result{}, err
	}
	if !ready {
		l.V(1).Info("vault not ready, requeueing", "name", vault.Name)
		return ctrl.Result{RequeueAfter: requeueWait}, nil
	}
	return ctrl.Result{}, nil
}

// fail records an event, marks the vault unavailable, and returns the error so
// the work queue retries with backoff.
func (r *DezhanVaultReconciler) fail(ctx context.Context, v *dezhanv1alpha1.DezhanVault, reason string, err error) (ctrl.Result, error) {
	if r.Recorder != nil {
		r.Recorder.Eventf(v, corev1.EventTypeWarning, reason, "%v", err)
	}
	_ = r.updateStatus(ctx, v, false)
	return ctrl.Result{}, err
}

func applyDefaults(v *dezhanv1alpha1.DezhanVault) {
	if v.Spec.Image == "" {
		v.Spec.Image = "ghcr.io/obsernetics/dezhan:latest"
	}
	if v.Spec.Port == 0 {
		v.Spec.Port = 8080
	}
	if v.Spec.Storage.IsZero() {
		v.Spec.Storage = resource.MustParse("50Gi")
	}
	if v.Spec.ServiceType == "" {
		v.Spec.ServiceType = corev1.ServiceTypeClusterIP
	}
}

func labelsFor(name string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "dezhan",
		"app.kubernetes.io/instance":   name,
		"app.kubernetes.io/managed-by": "dezhan-operator",
	}
}

func mergeLabels(dst map[string]string, src map[string]string) map[string]string {
	if dst == nil {
		dst = map[string]string{}
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (r *DezhanVaultReconciler) reconcileService(ctx context.Context, v *dezhanv1alpha1.DezhanVault) error {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: v.Name, Namespace: v.Namespace}}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		svc.Labels = mergeLabels(svc.Labels, labelsFor(v.Name))
		// Prometheus scrape annotations so a plain Prometheus (no Operator)
		// discovers /metrics; the ServiceMonitor in config/observability covers
		// the Prometheus Operator case.
		svc.Annotations = mergeLabels(svc.Annotations, map[string]string{
			"prometheus.io/scrape": "true",
			"prometheus.io/port":   strconv.Itoa(int(v.Spec.Port)),
			"prometheus.io/path":   "/metrics",
		})
		svc.Spec.Type = v.Spec.ServiceType
		svc.Spec.Selector = labelsFor(v.Name)
		// ClusterIP is immutable; request a headless IP only at creation.
		if svc.CreationTimestamp.IsZero() && v.Spec.ServiceType == corev1.ServiceTypeClusterIP {
			svc.Spec.ClusterIP = corev1.ClusterIPNone
		}
		svc.Spec.Ports = []corev1.ServicePort{{
			Name:       "s3",
			Port:       v.Spec.Port,
			TargetPort: intstr.FromInt32(v.Spec.Port),
			Protocol:   corev1.ProtocolTCP,
		}}
		return controllerutil.SetControllerReference(v, svc, r.Scheme)
	})
	if err == nil && op != controllerutil.OperationResultNone && r.Recorder != nil {
		r.Recorder.Eventf(v, corev1.EventTypeNormal, "Reconciled", "service %s", op)
	}
	return err
}

func (r *DezhanVaultReconciler) reconcileStatefulSet(ctx context.Context, v *dezhanv1alpha1.DezhanVault) error {
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: v.Name, Namespace: v.Namespace}}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, sts, func() error {
		replicas := int32(1)
		sts.Labels = mergeLabels(sts.Labels, labelsFor(v.Name))
		sts.Spec.Replicas = &replicas
		// Consider the pod ready only after it has stayed up briefly.
		sts.Spec.MinReadySeconds = 10
		// Never delete the data PVC when the StatefulSet is deleted or scaled;
		// vault data must outlive the workload object.
		sts.Spec.PersistentVolumeClaimRetentionPolicy = &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
			WhenDeleted: appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
			WhenScaled:  appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
		}

		// Selector, ServiceName, and VolumeClaimTemplates are immutable after
		// creation; set them once. Mutating them later is rejected by the API.
		if sts.CreationTimestamp.IsZero() {
			sts.Spec.Selector = &metav1.LabelSelector{MatchLabels: labelsFor(v.Name)}
			sts.Spec.ServiceName = v.Name
			sts.Spec.VolumeClaimTemplates = []corev1.PersistentVolumeClaim{{
				ObjectMeta: metav1.ObjectMeta{Name: dataVolume},
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					StorageClassName: v.Spec.StorageClassName,
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceStorage: v.Spec.Storage},
					},
				},
			}}
		}

		sts.Spec.Template.Labels = mergeLabels(sts.Spec.Template.Labels, labelsFor(v.Name))
		applyPodSpec(&sts.Spec.Template.Spec, v)
		return controllerutil.SetControllerReference(v, sts, r.Scheme)
	})
	if err == nil && op != controllerutil.OperationResultNone && r.Recorder != nil {
		r.Recorder.Eventf(v, corev1.EventTypeNormal, "Reconciled", "statefulset %s", op)
	}
	return err
}

// reconcilePDB keeps a PodDisruptionBudget (minAvailable=1) for the vault so a
// node drain or cluster upgrade cannot voluntarily evict the single writer
// without a deliberate eviction. If disabled, any existing PDB is removed.
func (r *DezhanVaultReconciler) reconcilePDB(ctx context.Context, v *dezhanv1alpha1.DezhanVault) error {
	pdb := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: v.Name, Namespace: v.Namespace}}
	if v.Spec.DisablePodDisruptionBudget {
		err := r.Delete(ctx, pdb)
		return client.IgnoreNotFound(err)
	}
	minAvail := intstr.FromInt32(1)
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, pdb, func() error {
		pdb.Labels = mergeLabels(pdb.Labels, labelsFor(v.Name))
		pdb.Spec.MinAvailable = &minAvail
		pdb.Spec.Selector = &metav1.LabelSelector{MatchLabels: labelsFor(v.Name)}
		return controllerutil.SetControllerReference(v, pdb, r.Scheme)
	})
	return err
}

// reconcilePVCExpansion grows the vault's PersistentVolumeClaim when spec.storage
// increases. StatefulSet volumeClaimTemplates are immutable, so online expansion
// is done by patching the live PVC (data-<name>-0). The StorageClass must allow
// volume expansion. Shrinking is never attempted (the API forbids it).
func (r *DezhanVaultReconciler) reconcilePVCExpansion(ctx context.Context, v *dezhanv1alpha1.DezhanVault) error {
	pvcName := fmt.Sprintf("%s-%s-0", dataVolume, v.Name)
	var pvc corev1.PersistentVolumeClaim
	if err := r.Get(ctx, types.NamespacedName{Name: pvcName, Namespace: v.Namespace}, &pvc); err != nil {
		// Not provisioned yet (or no provisioner, as in tests): nothing to grow.
		return client.IgnoreNotFound(err)
	}
	cur := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	if v.Spec.Storage.Cmp(cur) <= 0 {
		return nil // desired <= current: no expansion
	}
	patch := client.MergeFrom(pvc.DeepCopy())
	if pvc.Spec.Resources.Requests == nil {
		pvc.Spec.Resources.Requests = corev1.ResourceList{}
	}
	pvc.Spec.Resources.Requests[corev1.ResourceStorage] = v.Spec.Storage
	if err := r.Patch(ctx, &pvc, patch); err != nil {
		return err
	}
	if r.Recorder != nil {
		r.Recorder.Eventf(v, corev1.EventTypeNormal, "Expanded",
			"PVC %s grown to %s", pvcName, v.Spec.Storage.String())
	}
	return nil
}

// applyPodSpec reconciles only the fields the operator owns, in place, so the
// API server's pod-template defaults (imagePullPolicy, dnsPolicy, ...) are left
// untouched. Replacing the whole PodSpec each pass would fight those defaults
// and spin the controller in a hot update loop.
func applyPodSpec(spec *corev1.PodSpec, v *dezhanv1alpha1.DezhanVault) {
	spec.SecurityContext = &corev1.PodSecurityContext{
		RunAsNonRoot: ptr(true),
		RunAsUser:    ptr[int64](fieldOwnerUID), // numeric: the image's USER is non-numeric (nonroot)
		FSGroup:      ptr[int64](fieldOwnerUID),
	}
	spec.PriorityClassName = v.Spec.PriorityClassName
	// Give the vault time to flush its journal/snapshot on shutdown.
	spec.TerminationGracePeriodSeconds = ptr[int64](60)

	var c *corev1.Container
	for i := range spec.Containers {
		if spec.Containers[i].Name == containerName {
			c = &spec.Containers[i]
			break
		}
	}
	if c == nil {
		spec.Containers = append(spec.Containers, corev1.Container{Name: containerName})
		c = &spec.Containers[len(spec.Containers)-1]
	}

	c.Image = v.Spec.Image
	c.Args = []string{strconv.Itoa(int(v.Spec.Port)), "/" + dataVolume}
	c.Env = vaultEnv(v)
	c.EnvFrom = vaultEnvFrom(v)
	c.Ports = []corev1.ContainerPort{{Name: "s3", ContainerPort: v.Spec.Port, Protocol: corev1.ProtocolTCP}}
	c.VolumeMounts = []corev1.VolumeMount{{Name: dataVolume, MountPath: "/" + dataVolume}}
	c.Resources = v.Spec.Resources
	c.ReadinessProbe = healthProbe(v.Spec.Port, 3)
	c.LivenessProbe = healthProbe(v.Spec.Port, 10)
	// Startup probe tolerates a slow first boot (journal replay over a large
	// vault) without the liveness probe killing the pod: up to 5 min.
	c.StartupProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(v.Spec.Port)},
		},
		PeriodSeconds:    5,
		FailureThreshold: 60,
	}
	c.SecurityContext = &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr(false),
		ReadOnlyRootFilesystem:   ptr(true),
		RunAsNonRoot:             ptr(true),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

func vaultEnv(v *dezhanv1alpha1.DezhanVault) []corev1.EnvVar {
	env := []corev1.EnvVar{}
	if v.Spec.RequireAuth {
		env = append(env, corev1.EnvVar{Name: "DEZHAN_REQUIRE_AUTH", Value: "1"})
	}
	if v.Spec.DeleteQuorum > 0 {
		env = append(env, corev1.EnvVar{Name: "DEZHAN_DELETE_QUORUM", Value: strconv.Itoa(int(v.Spec.DeleteQuorum))})
	}
	if v.Spec.ScrubIntervalSeconds > 0 {
		env = append(env, corev1.EnvVar{Name: "DEZHAN_SCRUB_INTERVAL", Value: strconv.Itoa(int(v.Spec.ScrubIntervalSeconds))})
	}
	return env
}

func vaultEnvFrom(v *dezhanv1alpha1.DezhanVault) []corev1.EnvFromSource {
	if v.Spec.SecretName == "" {
		return nil
	}
	return []corev1.EnvFromSource{{
		SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: v.Spec.SecretName}},
	}}
}

func healthProbe(port int32, initialDelay int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(port)},
		},
		InitialDelaySeconds: initialDelay,
		PeriodSeconds:       10,
		TimeoutSeconds:      3,
		FailureThreshold:    3,
	}
}

// updateStatus writes status with a fresh read to avoid stale-resourceVersion
// conflicts, and only patches when something actually changed.
func (r *DezhanVaultReconciler) updateStatus(ctx context.Context, v *dezhanv1alpha1.DezhanVault, ready bool) error {
	var cur dezhanv1alpha1.DezhanVault
	if err := r.Get(ctx, types.NamespacedName{Name: v.Name, Namespace: v.Namespace}, &cur); err != nil {
		return client.IgnoreNotFound(err)
	}
	patch := client.MergeFrom(cur.DeepCopy())

	cur.Status.ObservedGeneration = cur.Generation
	cur.Status.Ready = ready
	cur.Status.Endpoint = fmt.Sprintf("%s.%s.svc:%d", v.Name, v.Namespace, v.Spec.Port)
	cond := metav1.Condition{
		Type:               "Available",
		ObservedGeneration: cur.Generation,
		Status:             metav1.ConditionFalse,
		Reason:             "StatefulSetNotReady",
		Message:            "vault pod is not ready",
	}
	if ready {
		cond.Status = metav1.ConditionTrue
		cond.Reason = "StatefulSetReady"
		cond.Message = "vault pod is ready"
	}
	meta.SetStatusCondition(&cur.Status.Conditions, cond)
	return r.Status().Patch(ctx, &cur, patch)
}

func ptr[T any](x T) *T { return &x }

// requeueWait is also used as the default resync backstop for readiness.

// SetupWithManager wires the controller and the objects it owns.
func (r *DezhanVaultReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor("dezhan-operator")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&dezhanv1alpha1.DezhanVault{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.Service{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Complete(r)
}
