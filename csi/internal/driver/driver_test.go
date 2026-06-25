package driver

import (
	"strings"
	"testing"
)

func TestBucketName(t *testing.T) {
	if got := bucketName("pvc-1234"); got != "pvc-1234" {
		t.Errorf("bucketName(pvc-1234) = %q", got)
	}
	if got := bucketName("PVC-Upper"); got != "pvc-upper" {
		t.Errorf("lower-casing failed: %q", got)
	}
	long := strings.Repeat("a", 100)
	if got := bucketName(long); len(got) != 63 {
		t.Errorf("bucketName truncation: got len %d, want 63", len(got))
	}
}

func TestSnapshotBucket(t *testing.T) {
	if got := snapshotBucket("snapshot-abc"); got != "snap-abc" {
		t.Errorf("snapshotBucket(snapshot-abc) = %q, want snap-abc", got)
	}
	if got := snapshotBucket("MyShot"); got != "snap-myshot" {
		t.Errorf("snapshotBucket(MyShot) = %q", got)
	}
	if got := snapshotBucket(strings.Repeat("z", 100)); len(got) > 63 {
		t.Errorf("snapshotBucket too long: %d", len(got))
	}
}

func TestConnFrom(t *testing.T) {
	// secret value wins over param; region falls back to the param.
	c, err := connFrom(
		map[string]string{"accessKeyID": "ak", "secretAccessKey": "sk", "endpoint": "http://s"},
		map[string]string{"endpoint": "http://ignored", "region": "eu-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != "http://s" || c.Region != "eu-1" || c.AccessKey != "ak" {
		t.Errorf("unexpected conn: %+v", c)
	}

	if _, err := connFrom(map[string]string{"accessKeyID": "a", "secretAccessKey": "b"}, nil); err == nil {
		t.Error("expected error when endpoint missing")
	}
	if _, err := connFrom(nil, map[string]string{"endpoint": "http://s"}); err == nil {
		t.Error("expected error when credentials missing")
	}
	if c, _ := connFrom(map[string]string{"accessKeyID": "a", "secretAccessKey": "b", "endpoint": "x"}, nil); c.Region != "us-east-1" {
		t.Errorf("region default = %q, want us-east-1", c.Region)
	}
}
