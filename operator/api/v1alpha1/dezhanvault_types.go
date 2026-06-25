package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// DezhanVaultSpec defines a desired dezhan vault instance. A vault is a single
// writer over durable storage, so it is deployed as a one-replica StatefulSet
// with a persistent volume for the WORM data and audit chain.
type DezhanVaultSpec struct {
	// Image is the dezhan server container image to run.
	// +kubebuilder:default="ghcr.io/obsernetics/dezhan:latest"
	Image string `json:"image,omitempty"`

	// Port the server listens on.
	// +kubebuilder:default=8080
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// Storage is the size of the persistent volume for vault data.
	// +kubebuilder:default="50Gi"
	Storage resource.Quantity `json:"storage,omitempty"`

	// StorageClassName selects the PVC storage class (nil = cluster default).
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// RequireAuth rejects unsigned (anonymous) requests when true.
	// +kubebuilder:default=true
	RequireAuth bool `json:"requireAuth,omitempty"`

	// DeleteQuorum is the number of approver co-signatures required to delete
	// (four-eyes). Zero disables the quorum gate.
	// +optional
	// +kubebuilder:validation:Minimum=0
	DeleteQuorum int32 `json:"deleteQuorum,omitempty"`

	// SecretName names a Secret whose keys are exported as environment
	// variables to the server (e.g. DEZHAN_VAULT_KEY, DEZHAN_SECRET,
	// DEZHAN_ADMIN_TOKEN, DEZHAN_APPROVERS). Recommended for all production
	// instances so secrets never live in the CR.
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// Resources are the container resource requirements.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// ServiceType controls the Service exposing the vault.
	// +kubebuilder:default="ClusterIP"
	// +kubebuilder:validation:Enum=ClusterIP;NodePort;LoadBalancer
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`
}

// DezhanVaultStatus reports the observed state of a vault.
type DezhanVaultStatus struct {
	// ObservedGeneration is the .metadata.generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Ready is true when the underlying StatefulSet has its replica ready.
	// +optional
	Ready bool `json:"ready,omitempty"`

	// Endpoint is the in-cluster address clients use (service:port).
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// Conditions follow the standard Kubernetes condition convention.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=dv
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.status.endpoint`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// DezhanVault is an immutable, air-gapped, S3-compatible backup vault.
type DezhanVault struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DezhanVaultSpec   `json:"spec,omitempty"`
	Status DezhanVaultStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DezhanVaultList is a list of DezhanVault.
type DezhanVaultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DezhanVault `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DezhanVault{}, &DezhanVaultList{})
}
