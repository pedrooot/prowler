// Package s3 collects the S3 buckets a scan evaluates and hosts the S3 checks.
package s3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	awsservice "github.com/prowler-cloud/prowler/prowler-go/pkg/provider/aws/service"
)

func init() {
	awsservice.Register("s3", collect)
}

// Bucket is one S3 bucket with everything the S3 checks read.
type Bucket struct {
	Name              string             `json:"name"`
	ARN               string             `json:"arn"`
	Region            string             `json:"region"`
	Versioning        bool               `json:"versioning"`
	MFADelete         bool               `json:"mfa_delete"`
	Logging           bool               `json:"logging"`
	LoggingTarget     string             `json:"logging_target,omitempty"`
	Encryption        string             `json:"encryption,omitempty"`
	Policy            json.RawMessage    `json:"policy,omitempty"`
	ACLGrantees       []Grantee          `json:"acl_grantees,omitempty"`
	PublicAccessBlock *PublicAccessBlock `json:"public_access_block,omitempty"`
	Tags              map[string]string  `json:"tags,omitempty"`
	ObjectLock        bool               `json:"object_lock"`
}

// Grantee is one entry of a bucket ACL.
type Grantee struct {
	DisplayName string `json:"display_name,omitempty"`
	ID          string `json:"id,omitempty"`
	Type        string `json:"type"`
	URI         string `json:"uri,omitempty"`
}

// PublicAccessBlock is the bucket-level block public access configuration.
type PublicAccessBlock struct {
	BlockPublicACLs       bool `json:"block_public_acls"`
	IgnorePublicACLs      bool `json:"ignore_public_acls"`
	BlockPublicPolicy     bool `json:"block_public_policy"`
	RestrictPublicBuckets bool `json:"restrict_public_buckets"`
}

func (b *Bucket) ResourceID() string              { return b.Name }
func (b *Bucket) ResourceName() string            { return b.Name }
func (b *Bucket) ResourceARN() string             { return b.ARN }
func (b *Bucket) ResourceRegion() string          { return b.Region }
func (b *Bucket) ResourceTags() map[string]string { return b.Tags }

// Service is the collected S3 state a check reads.
type Service struct {
	Buckets   []*Bucket
	Partition string
	Account   string
}

// API is the subset of the S3 client the collector uses, so the collection
// can be exercised without reaching AWS.
type API interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketLogging(context.Context, *s3.GetBucketLoggingInput, ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
	GetBucketPolicy(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetBucketAcl(context.Context, *s3.GetBucketAclInput, ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketTagging(context.Context, *s3.GetBucketTaggingInput, ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error)
	GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
}

func collect(ctx context.Context, scope awsservice.Scope) (any, error) {
	return Collect(ctx, s3.NewFromConfig(scope.Session.Config), scope)
}

// Collect lists the buckets in scope and enriches each one concurrently.
//
// Enrichment writes only into its own bucket, so the fan-out needs no lock;
// the errors it cannot attribute to a bucket are collected and returned.
func Collect(ctx context.Context, api API, scope awsservice.Scope) (*Service, error) {
	identity := scope.Session.Identity
	svc := &Service{Partition: identity.Partition, Account: identity.Account}

	listed, err := api.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	regions := regionFilter(scope.Regions)
	buckets := make([]*Bucket, 0, len(listed.Buckets))
	for _, b := range listed.Buckets {
		name := aws.ToString(b.Name)
		region, err := bucketRegion(ctx, api, name)
		if err != nil {
			continue
		}
		if regions != nil && !regions[region] {
			continue
		}
		buckets = append(buckets, &Bucket{
			Name:   name,
			ARN:    fmt.Sprintf("arn:%s:s3:::%s", identity.Partition, name),
			Region: region,
		})
	}

	var mu sync.Mutex
	var errs error
	awsservice.ForEach(ctx, scope.Concurrency, buckets, func(ctx context.Context, bucket *Bucket) {
		if err := enrich(ctx, api, bucket); err != nil {
			mu.Lock()
			errs = errors.Join(errs, err)
			mu.Unlock()
		}
	})

	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Name < buckets[j].Name })
	svc.Buckets = buckets
	return svc, errs
}

// bucketRegion resolves a bucket's region, translating the two location
// constraints that do not name their region directly.
func bucketRegion(ctx context.Context, api API, name string) (string, error) {
	out, err := api.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(name)})
	if err != nil {
		return "", err
	}
	switch out.LocationConstraint {
	case "":
		return "us-east-1", nil
	case "EU":
		return "eu-west-1", nil
	default:
		return string(out.LocationConstraint), nil
	}
}

// enrich fills in one bucket's configuration. A permission error on a single
// call leaves that field at its zero value rather than dropping the bucket,
// which is how the Python service behaves.
func enrich(ctx context.Context, api API, b *Bucket) error {
	name := aws.String(b.Name)

	if out, err := api.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: name}); err == nil {
		b.Versioning = out.Status == types.BucketVersioningStatusEnabled
		b.MFADelete = out.MFADelete == types.MFADeleteStatusEnabled
	}
	if out, err := api.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: name}); err == nil && out.LoggingEnabled != nil {
		b.Logging = true
		b.LoggingTarget = aws.ToString(out.LoggingEnabled.TargetBucket)
	}
	if out, err := api.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: name}); err == nil {
		b.Policy = json.RawMessage(aws.ToString(out.Policy))
	}
	if out, err := api.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: name}); err == nil {
		b.ACLGrantees = granteesOf(out.Grants)
	}
	if out, err := api.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: name}); err == nil && out.PublicAccessBlockConfiguration != nil {
		c := out.PublicAccessBlockConfiguration
		b.PublicAccessBlock = &PublicAccessBlock{
			BlockPublicACLs:       aws.ToBool(c.BlockPublicAcls),
			IgnorePublicACLs:      aws.ToBool(c.IgnorePublicAcls),
			BlockPublicPolicy:     aws.ToBool(c.BlockPublicPolicy),
			RestrictPublicBuckets: aws.ToBool(c.RestrictPublicBuckets),
		}
	}
	if out, err := api.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: name}); err == nil {
		b.Encryption = encryptionOf(out)
	}
	if out, err := api.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: name}); err == nil {
		b.Tags = tagsOf(out.TagSet)
	}
	if out, err := api.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: name}); err == nil && out.ObjectLockConfiguration != nil {
		b.ObjectLock = out.ObjectLockConfiguration.ObjectLockEnabled == types.ObjectLockEnabledEnabled
	}
	return nil
}

func granteesOf(grants []types.Grant) []Grantee {
	grantees := make([]Grantee, 0, len(grants))
	for _, grant := range grants {
		if grant.Grantee == nil {
			continue
		}
		grantees = append(grantees, Grantee{
			DisplayName: aws.ToString(grant.Grantee.DisplayName),
			ID:          aws.ToString(grant.Grantee.ID),
			Type:        string(grant.Grantee.Type),
			URI:         aws.ToString(grant.Grantee.URI),
		})
	}
	return grantees
}

// encryptionOf reports the algorithm of the first default encryption rule,
// which is the value the encryption check reports.
func encryptionOf(out *s3.GetBucketEncryptionOutput) string {
	if out.ServerSideEncryptionConfiguration == nil {
		return ""
	}
	for _, rule := range out.ServerSideEncryptionConfiguration.Rules {
		if rule.ApplyServerSideEncryptionByDefault != nil {
			return string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
		}
	}
	return ""
}

func tagsOf(tags []types.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return out
}

func regionFilter(regions []string) map[string]bool {
	if len(regions) == 0 {
		return nil
	}
	filter := make(map[string]bool, len(regions))
	for _, region := range regions {
		filter[strings.TrimSpace(region)] = true
	}
	return filter
}
