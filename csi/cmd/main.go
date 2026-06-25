// dezhan CSI driver. Provisions a dezhan bucket per PersistentVolume and mounts
// it on nodes via mountpoint-s3. Suited to write-once/append and archival
// workloads, which match dezhan's WORM model; not for random-write volumes.
package main

import (
	"flag"
	"os"

	"k8s.io/klog/v2"

	"github.com/obsernetics/dezhan/csi/internal/driver"
)

func main() {
	var (
		endpoint   = flag.String("endpoint", "unix:///csi/csi.sock", "CSI gRPC endpoint")
		nodeID     = flag.String("node-id", "", "node identifier (required for the node service)")
		driverName = flag.String("driver-name", "dezhan.csi.obsernetics.io", "CSI driver name")
		mode       = flag.String("mode", "all", "controller | node | all")
	)
	klog.InitFlags(nil)
	flag.Parse()

	d, err := driver.New(driver.Options{
		Name:     *driverName,
		NodeID:   *nodeID,
		Endpoint: *endpoint,
		Mode:     driver.Mode(*mode),
	})
	if err != nil {
		klog.ErrorS(err, "failed to create driver")
		os.Exit(1)
	}
	if err := d.Run(); err != nil {
		klog.ErrorS(err, "driver exited")
		os.Exit(1)
	}
}
