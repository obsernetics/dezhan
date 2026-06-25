package driver

import (
	"context"
	"os"
	"os/exec"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"k8s.io/klog/v2"
	"k8s.io/mount-utils"
)

// mountCmd is the mountpoint-s3 binary; overridable for tests.
var mountCmd = "mount-s3"

type nodeServer struct {
	csi.UnimplementedNodeServer
	driver  *Driver
	mounter mount.Interface
}

func newNodeServer(d *Driver) *nodeServer {
	return &nodeServer{driver: d, mounter: mount.New("")}
}

func (s *nodeServer) NodeGetInfo(_ context.Context, _ *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{NodeId: s.driver.opts.NodeID}, nil
}

func (s *nodeServer) NodeGetCapabilities(_ context.Context, _ *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	// No staging: the volume is mounted directly in NodePublishVolume.
	return &csi.NodeGetCapabilitiesResponse{}, nil
}

func (s *nodeServer) NodePublishVolume(_ context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	target := req.GetTargetPath()
	if target == "" || req.GetVolumeId() == "" {
		return nil, errf(codes.InvalidArgument, "volume id and target path are required")
	}
	vctx := req.GetVolumeContext()
	bucket := vctx["bucket"]
	if bucket == "" {
		bucket = req.GetVolumeId()
	}
	conn, err := connFrom(req.GetSecrets(), vctx)
	if err != nil {
		return nil, errf(codes.InvalidArgument, "%v", err)
	}

	if err := os.MkdirAll(target, 0o750); err != nil {
		return nil, errf(codes.Internal, "mkdir %s: %v", target, err)
	}
	notMnt, err := s.mounter.IsLikelyNotMountPoint(target)
	if err != nil && !os.IsNotExist(err) {
		return nil, errf(codes.Internal, "check mount %s: %v", target, err)
	}
	if !notMnt {
		return &csi.NodePublishVolumeResponse{}, nil // already mounted (idempotent)
	}

	args := []string{
		bucket, target,
		"--endpoint-url", conn.Endpoint,
		"--region", conn.Region,
		"--allow-other",
		"--force-path-style",
	}
	if req.GetReadonly() {
		args = append(args, "--read-only")
	} else {
		args = append(args, "--allow-delete")
	}
	cmd := exec.Command(mountCmd, args...)
	cmd.Env = append(os.Environ(),
		"AWS_ACCESS_KEY_ID="+conn.AccessKey,
		"AWS_SECRET_ACCESS_KEY="+conn.SecretKey,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, errf(codes.Internal, "%s failed: %v: %s", mountCmd, err, string(out))
	}
	klog.InfoS("mounted volume", "bucket", bucket, "target", target)
	return &csi.NodePublishVolumeResponse{}, nil
}

func (s *nodeServer) NodeUnpublishVolume(_ context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	target := req.GetTargetPath()
	if target == "" || req.GetVolumeId() == "" {
		return nil, errf(codes.InvalidArgument, "volume id and target path are required")
	}
	if err := mount.CleanupMountPoint(target, s.mounter, true); err != nil {
		return nil, errf(codes.Internal, "unmount %s: %v", target, err)
	}
	klog.InfoS("unmounted volume", "target", target)
	return &csi.NodeUnpublishVolumeResponse{}, nil
}
