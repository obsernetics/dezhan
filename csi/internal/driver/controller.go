package driver

import (
	"context"
	"strings"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
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

	// Restore from a snapshot if requested: copy the snapshot bucket into the
	// new volume bucket. Otherwise just create an empty bucket.
	if src := req.GetVolumeContentSource().GetSnapshot(); src != nil {
		if _, err := conn.copyAll(ctx, src.GetSnapshotId(), bucket); err != nil {
			return nil, errf(codes.Internal, "restore from snapshot %s: %v", src.GetSnapshotId(), err)
		}
		klog.InfoS("provisioned volume from snapshot", "bucket", bucket, "snapshot", src.GetSnapshotId())
	} else if err := conn.createBucket(ctx, bucket); err != nil {
		return nil, errf(codes.Internal, "%v", err)
	} else {
		klog.InfoS("provisioned volume", "bucket", bucket, "endpoint", conn.Endpoint)
	}

	cap := req.GetCapacityRange().GetRequiredBytes() // advisory only for an object store

	// VolumeContext is handed back on NodePublishVolume so the node knows what
	// to mount. The endpoint is non-secret; credentials come from the
	// node-publish secret, not from here.
	return &csi.CreateVolumeResponse{Volume: &csi.Volume{
		VolumeId:      bucket,
		CapacityBytes: cap,
		ContentSource: req.GetVolumeContentSource(),
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
		csi.ControllerServiceCapability_RPC_CREATE_DELETE_SNAPSHOT,
	}
	out := make([]*csi.ControllerServiceCapability, 0, len(caps))
	for _, c := range caps {
		out = append(out, &csi.ControllerServiceCapability{
			Type: &csi.ControllerServiceCapability_Rpc{Rpc: &csi.ControllerServiceCapability_RPC{Type: c}},
		})
	}
	return &csi.ControllerGetCapabilitiesResponse{Capabilities: out}, nil
}

// snapshotBucket derives the snapshot bucket name from the CSI snapshot name.
func snapshotBucket(reqName string) string {
	b := "snap-" + strings.ToLower(strings.TrimPrefix(reqName, "snapshot-"))
	if len(b) > 63 {
		b = b[:63]
	}
	return b
}

func (s *controllerServer) CreateSnapshot(ctx context.Context, req *csi.CreateSnapshotRequest) (*csi.CreateSnapshotResponse, error) {
	if req.GetName() == "" || req.GetSourceVolumeId() == "" {
		return nil, errf(codes.InvalidArgument, "snapshot name and source volume id are required")
	}
	conn, err := connFrom(req.GetSecrets(), req.GetParameters())
	if err != nil {
		return nil, errf(codes.InvalidArgument, "%v", err)
	}
	snap := snapshotBucket(req.GetName())
	size, err := conn.copyAll(ctx, req.GetSourceVolumeId(), snap)
	if err != nil {
		return nil, errf(codes.Internal, "%v", err)
	}
	klog.InfoS("created snapshot", "snapshot", snap, "source", req.GetSourceVolumeId(), "bytes", size)
	return &csi.CreateSnapshotResponse{Snapshot: &csi.Snapshot{
		SnapshotId:     snap,
		SourceVolumeId: req.GetSourceVolumeId(),
		SizeBytes:      size,
		CreationTime:   timestamppb.New(time.Now()),
		ReadyToUse:     true,
	}}, nil
}

func (s *controllerServer) DeleteSnapshot(ctx context.Context, req *csi.DeleteSnapshotRequest) (*csi.DeleteSnapshotResponse, error) {
	if req.GetSnapshotId() == "" {
		return nil, errf(codes.InvalidArgument, "snapshot id is required")
	}
	conn, err := connFrom(req.GetSecrets(), nil)
	if err != nil {
		return nil, errf(codes.InvalidArgument, "%v", err)
	}
	if err := conn.deleteBucket(ctx, req.GetSnapshotId()); err != nil {
		return nil, errf(codes.Internal, "%v", err)
	}
	return &csi.DeleteSnapshotResponse{}, nil
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
