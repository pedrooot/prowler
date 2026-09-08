package s3

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/provider/aws/meta"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/provider/aws/policy"
)

func init() {
	check.Register(bucketDefaultEncryption{bucketCheck{"s3_bucket_default_encryption"}})
	check.Register(bucketServerAccessLogging{bucketCheck{"s3_bucket_server_access_logging_enabled"}})
	check.Register(bucketObjectVersioning{bucketCheck{"s3_bucket_object_versioning"}})
	check.Register(bucketNoMFADelete{bucketCheck{"s3_bucket_no_mfa_delete"}})
	check.Register(bucketPublicAccess{bucketCheck{"s3_bucket_public_access"}})
}

// bucketCheck is the plumbing every per-bucket S3 check shares. Embedding it
// leaves each check with nothing but its own verdict.
type bucketCheck struct{ id string }

func (c bucketCheck) Metadata() *check.Metadata { return meta.Get(c.id) }
func (bucketCheck) Requires() []string          { return []string{"s3"} }

func (c bucketCheck) report(b *Bucket) *check.Report {
	r := check.NewReport(c.Metadata(), b)
	r.Resource, _ = json.Marshal(b)
	return r
}

// service pulls the collected S3 state out of the session.
func service(s check.Session) (*Service, error) {
	resources, err := s.Service("s3")
	if err != nil {
		return nil, err
	}
	svc, ok := resources.(*Service)
	if !ok {
		return nil, fmt.Errorf("s3: unexpected resource type %T", resources)
	}
	return svc, nil
}

// eachBucket applies verdict to every bucket in scope and gathers the reports.
func (c bucketCheck) eachBucket(s check.Session, verdict func(*Bucket, *check.Report)) ([]*check.Report, error) {
	svc, err := service(s)
	if err != nil {
		return nil, err
	}
	reports := make([]*check.Report, 0, len(svc.Buckets))
	for _, bucket := range svc.Buckets {
		r := c.report(bucket)
		verdict(bucket, r)
		if r.Status != check.StatusUnknown {
			reports = append(reports, r)
		}
	}
	return reports, nil
}

type bucketDefaultEncryption struct{ bucketCheck }

func (c bucketDefaultEncryption) Execute(_ context.Context, s check.Session) ([]*check.Report, error) {
	return c.eachBucket(s, func(b *Bucket, r *check.Report) {
		if b.Encryption != "" {
			r.Pass(fmt.Sprintf("S3 Bucket %s has Server Side Encryption with %s.", b.Name, b.Encryption))
			return
		}
		r.Fail(fmt.Sprintf("S3 Bucket %s does not have Server Side Encryption enabled.", b.Name))
	})
}

type bucketServerAccessLogging struct{ bucketCheck }

func (c bucketServerAccessLogging) Execute(_ context.Context, s check.Session) ([]*check.Report, error) {
	return c.eachBucket(s, func(b *Bucket, r *check.Report) {
		r.Decide(b.Logging,
			fmt.Sprintf("S3 Bucket %s has server access logging enabled.", b.Name),
			fmt.Sprintf("S3 Bucket %s has server access logging disabled.", b.Name))
	})
}

type bucketObjectVersioning struct{ bucketCheck }

func (c bucketObjectVersioning) Execute(_ context.Context, s check.Session) ([]*check.Report, error) {
	return c.eachBucket(s, func(b *Bucket, r *check.Report) {
		r.Decide(b.Versioning,
			fmt.Sprintf("S3 Bucket %s has versioning enabled.", b.Name),
			fmt.Sprintf("S3 Bucket %s has versioning disabled.", b.Name))
	})
}

type bucketNoMFADelete struct{ bucketCheck }

func (c bucketNoMFADelete) Execute(_ context.Context, s check.Session) ([]*check.Report, error) {
	return c.eachBucket(s, func(b *Bucket, r *check.Report) {
		r.Decide(b.MFADelete,
			fmt.Sprintf("S3 Bucket %s has MFA Delete enabled.", b.Name),
			fmt.Sprintf("S3 Bucket %s has MFA Delete disabled.", b.Name))
	})
}

type bucketPublicAccess struct{ bucketCheck }

// Requires s3control too: when the account blocks public access outright,
// the check reports once for the account instead of once per bucket.
func (bucketPublicAccess) Requires() []string { return []string{"s3", "s3control"} }

func (c bucketPublicAccess) Execute(_ context.Context, s check.Session) ([]*check.Report, error) {
	svc, err := service(s)
	if err != nil {
		return nil, err
	}
	control, err := accountAccessBlock(s)
	if err != nil {
		return nil, err
	}

	if control != nil && control.IgnorePublicACLs && control.RestrictPublicBuckets {
		r := check.NewReport(c.Metadata(), control)
		r.Resource, _ = json.Marshal(control)
		r.ResourceID = svc.Account
		r.ResourceARN = fmt.Sprintf("arn:%s:s3:%s:%s:account", svc.Partition, control.Region, svc.Account)
		r.Region = control.Region
		return []*check.Report{r.Pass("All S3 public access blocked at account level.")}, nil
	}

	return c.eachBucket(s, func(b *Bucket, r *check.Report) {
		if b.PublicAccessBlock == nil {
			return
		}
		r.Pass(fmt.Sprintf("S3 Bucket %s is not public.", b.Name))
		if b.PublicAccessBlock.IgnorePublicACLs && b.PublicAccessBlock.RestrictPublicBuckets {
			return
		}
		if hasPublicGrantee(b.ACLGrantees) {
			r.Fail(fmt.Sprintf("S3 Bucket %s has public access due to bucket ACL.", b.Name))
		}
		if policy.IsPublic(b.Policy) {
			r.Fail(fmt.Sprintf("S3 Bucket %s has public access due to bucket policy.", b.Name))
		}
	})
}

// publicGroups are the canned ACL groups that expose a bucket to anyone, or
// to any authenticated AWS principal.
var publicGroups = []string{"AllUsers", "AuthenticatedUsers"}

func hasPublicGrantee(grantees []Grantee) bool {
	for _, grantee := range grantees {
		if grantee.Type != "Group" {
			continue
		}
		for _, group := range publicGroups {
			if strings.Contains(grantee.URI, group) {
				return true
			}
		}
	}
	return false
}
