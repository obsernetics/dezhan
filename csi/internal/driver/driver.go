package driver

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog/v2"
)

// Version is the reported plugin version.
const Version = "0.1.0"

// Mode selects which CSI services this process serves.
type Mode string

const (
	ModeController Mode = "controller"
	ModeNode       Mode = "node"
	ModeAll        Mode = "all"
)

type Options struct {
	Name     string
	NodeID   string
	Endpoint string
	Mode     Mode
}

// Driver wires the identity, controller, and node services onto one gRPC server.
type Driver struct {
	opts Options
	srv  *grpc.Server
}

func New(o Options) (*Driver, error) {
	switch o.Mode {
	case ModeController, ModeNode, ModeAll:
	default:
		return nil, fmt.Errorf("invalid mode %q", o.Mode)
	}
	if o.Mode != ModeController && o.NodeID == "" {
		return nil, fmt.Errorf("--node-id is required for the node service")
	}
	return &Driver{opts: o}, nil
}

func (d *Driver) Run() error {
	scheme, addr, err := parseEndpoint(d.opts.Endpoint)
	if err != nil {
		return err
	}
	if scheme == "unix" {
		_ = os.Remove(addr)
	}
	lis, err := net.Listen(scheme, addr)
	if err != nil {
		return fmt.Errorf("listen %s://%s: %w", scheme, addr, err)
	}

	d.srv = grpc.NewServer(grpc.ChainUnaryInterceptor(logInterceptor))
	csi.RegisterIdentityServer(d.srv, &identityServer{driver: d})
	if d.opts.Mode == ModeController || d.opts.Mode == ModeAll {
		csi.RegisterControllerServer(d.srv, &controllerServer{driver: d})
	}
	if d.opts.Mode == ModeNode || d.opts.Mode == ModeAll {
		csi.RegisterNodeServer(d.srv, newNodeServer(d))
	}

	klog.InfoS("serving CSI", "name", d.opts.Name, "mode", d.opts.Mode, "endpoint", d.opts.Endpoint)
	return d.srv.Serve(lis)
}

func logInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	resp, err := handler(ctx, req)
	if err != nil {
		klog.ErrorS(err, "rpc failed", "method", info.FullMethod)
	} else {
		klog.V(4).InfoS("rpc ok", "method", info.FullMethod)
	}
	return resp, err
}

func parseEndpoint(ep string) (scheme, addr string, err error) {
	if strings.HasPrefix(ep, "/") {
		return "unix", ep, nil
	}
	u, err := url.Parse(ep)
	if err != nil {
		return "", "", fmt.Errorf("parse endpoint %q: %w", ep, err)
	}
	switch u.Scheme {
	case "unix":
		return "unix", u.Path, nil
	case "tcp":
		return "tcp", u.Host, nil
	default:
		return "", "", fmt.Errorf("unsupported endpoint scheme %q", u.Scheme)
	}
}

func errf(c codes.Code, format string, a ...any) error {
	return status.Errorf(c, format, a...)
}
