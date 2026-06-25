package driver

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// s3Conn holds the dezhan connection parameters resolved from CSI secrets and
// StorageClass parameters.
type s3Conn struct {
	Endpoint  string
	Region    string
	AccessKey string
	SecretKey string
}

// connFrom builds an s3Conn from the merged secrets and parameters maps. Keys:
// endpoint, region, accessKeyID, secretAccessKey.
func connFrom(secrets, params map[string]string) (s3Conn, error) {
	pick := func(k string) string {
		if v, ok := secrets[k]; ok && v != "" {
			return v
		}
		return params[k]
	}
	c := s3Conn{
		Endpoint:  pick("endpoint"),
		Region:    pick("region"),
		AccessKey: pick("accessKeyID"),
		SecretKey: pick("secretAccessKey"),
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if c.Endpoint == "" {
		return c, errors.New("missing dezhan endpoint (set 'endpoint' in the StorageClass parameters or secret)")
	}
	if c.AccessKey == "" || c.SecretKey == "" {
		return c, errors.New("missing accessKeyID/secretAccessKey in the CSI secret")
	}
	return c, nil
}

func (c s3Conn) client() *s3.Client {
	return s3.New(s3.Options{
		Region:       c.Region,
		BaseEndpoint: aws.String(c.Endpoint),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, ""),
	})
}

func (c s3Conn) createBucket(ctx context.Context, bucket string) error {
	_, err := c.client().CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	if err != nil {
		var owned *types.BucketAlreadyOwnedByYou
		var exists *types.BucketAlreadyExists
		if errors.As(err, &owned) || errors.As(err, &exists) {
			return nil // idempotent
		}
		return fmt.Errorf("create bucket %s: %w", bucket, err)
	}
	return nil
}

func (c s3Conn) deleteBucket(ctx context.Context, bucket string) error {
	if err := c.emptyBucket(ctx, bucket); err != nil {
		return err
	}
	_, err := c.client().DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	if err != nil {
		var nsb *types.NoSuchBucket
		if errors.As(err, &nsb) {
			return nil // already gone
		}
		return fmt.Errorf("delete bucket %s: %w", bucket, err)
	}
	return nil
}

// listKeys returns every object key in a bucket and their total size.
func (c s3Conn) listKeys(ctx context.Context, bucket string) ([]string, int64, error) {
	cl := c.client()
	p := s3.NewListObjectsV2Paginator(cl, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	var keys []string
	var total int64
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("list %s: %w", bucket, err)
		}
		for _, o := range page.Contents {
			keys = append(keys, aws.ToString(o.Key))
			total += aws.ToInt64(o.Size)
		}
	}
	return keys, total, nil
}

// emptyBucket deletes every object in a bucket (best-effort, one by one so it
// works against any S3 implementation).
func (c s3Conn) emptyBucket(ctx context.Context, bucket string) error {
	keys, _, err := c.listKeys(ctx, bucket)
	if err != nil {
		var nsb *types.NoSuchBucket
		if errors.As(err, &nsb) {
			return nil
		}
		return err
	}
	cl := c.client()
	for _, k := range keys {
		if _, err := cl.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket), Key: aws.String(k),
		}); err != nil {
			return fmt.Errorf("delete %s/%s: %w", bucket, k, err)
		}
	}
	return nil
}

// copyAll server-side-copies every object from src to dst (created if needed)
// and returns the bytes copied. Used to snapshot and to restore.
func (c s3Conn) copyAll(ctx context.Context, src, dst string) (int64, error) {
	if err := c.createBucket(ctx, dst); err != nil {
		return 0, err
	}
	keys, total, err := c.listKeys(ctx, src)
	if err != nil {
		return 0, err
	}
	cl := c.client()
	for _, k := range keys {
		if _, err := cl.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     aws.String(dst),
			Key:        aws.String(k),
			CopySource: aws.String(url.PathEscape(src + "/" + k)),
		}); err != nil {
			return 0, fmt.Errorf("copy %s/%s -> %s: %w", src, k, dst, err)
		}
	}
	return total, nil
}
