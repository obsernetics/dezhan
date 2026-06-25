package controller

import (
	"context"
	"fmt"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	dezhanv1alpha1 "github.com/obsernetics/dezhan/operator/api/v1alpha1"
)

// DezhanVaultReconciler reconciles a DezhanVault into a headless Service and a
// single-replica StatefulSet backed by a persistent volume.
type DezhanVaultReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=dezhan.obsernetics.io,resources=dezhanvaults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dezhan.obsernetics.io,resources=dezhanvaults/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=dezhan.obsernetics.io,resources=dezhanvaults/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete

func (r *DezhanVaultReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var vault dezhanv1alpha1.DezhanVault
	if err := r.Get(ctx, req.NamespacedName, &vault); err != nil {
		// Ignore not-found: owned objects are garbage-collected via ownerRefs.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	applyDefaults(&vault)

	if err := r.reconcileService(ctx, &vault); err != nil {
		return ctrl.Result{}, fmt.Errorf("reconcile service: %w", err)
	}
	if err := r.reconcileStatefulSet(ctx, &vault); err != nil {
		return ctrl.Result{}, fmt.Errorf("reconcile statefulset: %w", err)
	}

	// Read back StatefulSet readiness for status.
	var live appsv1.StatefulSet
	if err := r.Get(ctx, types.NamespacedName{Name: vault.Name, Namespace: vault.Namespace}, &live); err != nil {
		return ctrl.Result{}, err
	}
	ready := live.Status.ReadyReplicas >= 1

	vault.Status.ObservedGeneration = vault.Generation
	vault.Status.Ready = ready
	vault.Status.Endpoint = fmt.Sprintf("%s.%s.svc:%d", vault.Name, vault.Namespace, vault.Spec.Port)
	cond := metav1.Condition{
		Type:               "Available",
		Status:             metav1.ConditionFalse,
		Reason:             "StatefulSetNotReady",
		Message:            "vault pod is not ready",
		ObservedGeneration: vault.Generation,
	}
	if ready {
		cond.Status = metav1.ConditionTrue
		cond.Reason = "StatefulSetReady"
		cond.Message = "vault pod is ready"
	}
	setCondition(&vault.Status.Conditions, cond)

	if err := r.Status().Update(ctx, &vault); err != nil {
		return ctrl.Result{}, err
	}
	if !ready {
		l.Info("vault not ready yet, requeueing")
		return ctrl.Result{Requeue: true}, nil
	}
	return ctrl.Result{}, nil
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

func (r *DezhanVaultReconciler) reconcileService(ctx context.Context, v *dezhanv1alpha1.DezhanVault) error {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: v.Name, Namespace: v.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		svc.Labels = labelsFor(v.Name)
		svc.Spec.Type = v.Spec.ServiceType
		svc.Spec.Selector = labelsFor(v.Name)
		// ClusterIP is immutable; only request a headless IP at creation time.
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
	return err
}

func (r *DezhanVaultReconciler) reconcileStatefulSet(ctx context.Context, v *dezhanv1alpha1.DezhanVault) error {
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: v.Name, Namespace: v.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, sts, func() error {
		replicas := int32(1)
		sts.Labels = labelsFor(v.Name)
		sts.Spec.Replicas = &replicas
		sts.Spec.ServiceName = v.Name
		sts.Spec.Selector = &metav1.LabelSelector{MatchLabels: labelsFor(v.Name)}
		sts.Spec.Template.ObjectMeta.Labels = labelsFor(v.Name)
		sts.Spec.Template.Spec = r.podSpec(v)
		// VolumeClaimTemplates are immutable after creation; set once.
		if sts.CreationTimestamp.IsZero() {
			sts.Spec.VolumeClaimTemplates = []corev1.PersistentVolumeClaim{{
				ObjectMeta: metav1.ObjectMeta{Name: "data"},
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					StorageClassName: v.Spec.StorageClassName,
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceStorage: v.Spec.Storage},
					},
				},
			}}
		}
		return controllerutil.SetControllerReference(v, sts, r.Scheme)
	})
	return err
}

func (r *DezhanVaultReconciler) podSpec(v *dezhanv1alpha1.DezhanVault) corev1.PodSpec {
	env := []corev1.EnvVar{}
	if v.Spec.RequireAuth {
		env = append(env, corev1.EnvVar{Name: "DEZHAN_REQUIRE_AUTH", Value: "1"})
	}
	if v.Spec.DeleteQuorum > 0 {
		env = append(env, corev1.EnvVar{Name: "DEZHAN_DELETE_QUORUM", Value: strconv.Itoa(int(v.Spec.DeleteQuorum))})
	}
	envFrom := []corev1.EnvFromSource{}
	if v.Spec.SecretName != "" {
		envFrom = append(envFrom, corev1.EnvFromSource{
			SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: v.Spec.SecretName}},
		})
	}
	probe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(v.Spec.Port)},
		},
		InitialDelaySeconds: 3,
		PeriodSeconds:       10,
	}
	return corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: ptrBool(true),
			FSGroup:      ptrInt64(65532),
		},
		Containers: []corev1.Container{{
			Name:    "dezhan",
			Image:   v.Spec.Image,
			Args:    []string{strconv.Itoa(int(v.Spec.Port)), "/data"},
			Env:     env,
			EnvFrom: envFrom,
			Ports: []corev1.ContainerPort{{
				Name:          "s3",
				ContainerPort: v.Spec.Port,
				Protocol:      corev1.ProtocolTCP,
			}},
			VolumeMounts:   []corev1.VolumeMount{{Name: "data", MountPath: "/data"}},
			ReadinessProbe: probe,
			LivenessProbe:  probe,
			Resources:      v.Spec.Resources,
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: ptrBool(false),
				ReadOnlyRootFilesystem:   ptrBool(true),
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			},
		}},
	}
}

func setCondition(conds *[]metav1.Condition, c metav1.Condition) {
	for i := range *conds {
		if (*conds)[i].Type == c.Type {
			if (*conds)[i].Status != c.Status {
				(*conds)[i].LastTransitionTime = metav1.Now()
			}
			(*conds)[i].Status = c.Status
			(*conds)[i].Reason = c.Reason
			(*conds)[i].Message = c.Message
			(*conds)[i].ObservedGeneration = c.ObservedGeneration
			return
		}
	}
	c.LastTransitionTime = metav1.Now()
	*conds = append(*conds, c)
}

func ptrBool(b bool) *bool    { return &b }
func ptrInt64(i int64) *int64 { return &i }

// SetupWithManager wires the controller and the objects it owns.
func (r *DezhanVaultReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dezhanv1alpha1.DezhanVault{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.Service{}).
		Complete(r)
}
