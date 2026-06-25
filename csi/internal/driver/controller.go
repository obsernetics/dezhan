package driver

import (
	"context"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"k8s.io/klog/v2"
)

type controllerServer struct {
	csi.UnimplementedControllerServer
	driver *Driver
}

// bucketName derives a dezhan bucket name from the requested PV name. The
// external-provisioner passes names like "pvc-<uuid>", which are valid bucket
// names; we lower-case and trim to be safe.
func bucketName(reqName string) string {
	b := strings.ToLower(reqName)
	if len(b) > 63 {
		b = b[:63]
	}
	return b
}

func (s *controllerServer) CreateVolume(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	if req.GetName() == "" {
		return nil, errf(codes.InvalidArgument, "volume name is required")
	}
	if len(req.GetVolumeCapabilities()) == 0 {
		return nil, errf(codes.InvalidArgument, "volume capabilities are required")
	}
	conn, err := connFrom(req.GetSecrets(), req.GetParameters())
	if err != nil {
		return nil, errf(codes.InvalidArgument, "%v", err)
	}
	bucket := bucketName(req.GetName())
	if err := conn.createBucket(ctx, bucket); err != nil {
		return nil, errf(codes.Internal, "%v", err)
	}
	klog.InfoS("provisioned volume", "bucket", bucket, "endpoint", conn.Endpoint)

	cap := req.GetCapacityRange().GetRequiredBytes() // advisory only for an object store

	// VolumeContext is handed back on NodePublishVolume so the node knows what
	// to mount. The endpoint is non-secret; credentials come from the
	// node-publish secret, not from here.
	return &csi.CreateVolumeResponse{Volume: &csi.Volume{
		VolumeId:      bucket,
		CapacityBytes: cap,
		VolumeContext: map[string]string{
			"bucket":   bucket,
			"endpoint": conn.Endpoint,
			"region":   conn.Region,
		},
	}}, nil
}

func (s *controllerServer) DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	if req.GetVolumeId() == "" {
		return nil, errf(codes.InvalidArgument, "volume id is required")
	}
	conn, err := connFrom(req.GetSecrets(), nil)
	if err != nil {
		return nil, errf(codes.InvalidArgument, "%v", err)
	}
	if err := conn.deleteBucket(ctx, req.GetVolumeId()); err != nil {
		return nil, errf(codes.Internal, "%v", err)
	}
	return &csi.DeleteVolumeResponse{}, nil
}

func (s *controllerServer) ControllerGetCapabilities(_ context.Context, _ *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error) {
	caps := []csi.ControllerServiceCapability_RPC_Type{
		csi.ControllerServiceCapability_RPC_CREATE_DELETE_VOLUME,
	}
	out := make([]*csi.ControllerServiceCapability, 0, len(caps))
	for _, c := range caps {
		out = append(out, &csi.ControllerServiceCapability{
			Type: &csi.ControllerServiceCapability_Rpc{Rpc: &csi.ControllerServiceCapability_RPC{Type: c}},
		})
	}
	return &csi.ControllerGetCapabilitiesResponse{Capabilities: out}, nil
}

func (s *controllerServer) ValidateVolumeCapabilities(_ context.Context, req *csi.ValidateVolumeCapabilitiesRequest) (*csi.ValidateVolumeCapabilitiesResponse, error) {
	if req.GetVolumeId() == "" || len(req.GetVolumeCapabilities()) == 0 {
		return nil, errf(codes.InvalidArgument, "volume id and capabilities are required")
	}
	return &csi.ValidateVolumeCapabilitiesResponse{
		Confirmed: &csi.ValidateVolumeCapabilitiesResponse_Confirmed{
			VolumeCapabilities: req.GetVolumeCapabilities(),
		},
	}, nil
}
