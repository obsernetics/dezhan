package driver

import (
	"context"
	"errors"
	"fmt"

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
