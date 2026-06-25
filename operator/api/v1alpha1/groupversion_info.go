// Package v1alpha1 contains the DezhanVault API, group dezhan.obsernetics.io.
// +kubebuilder:object:generate=true
// +groupName=dezhan.obsernetics.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the group/version for this API.
	GroupVersion = schema.GroupVersion{Group: "dezhan.obsernetics.io", Version: "v1alpha1"}

	// SchemeBuilder registers the API types with a runtime.Scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group/version to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
