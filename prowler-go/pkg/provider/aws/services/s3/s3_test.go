package s3

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
	awsservice "github.com/prowler-cloud/prowler/prowler-go/pkg/provider/aws/service"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/provider/aws/session"
)

// fakeS3 answers the calls the collector makes from a fixture, so collection
// and every check can be exercised without reaching AWS.
type fakeS3 struct {
	names      []string
	region     map[string]string
	versioning map[string]types.BucketVersioningStatus
	mfaDelete  map[string]types.MFADeleteStatus
	logging    map[string]string
	policy     map[string]string
	acl        map[string][]types.Grant
	block      map[string]*types.PublicAccessBlockConfiguration
	encryption map[string]types.ServerSideEncryption
	tags       map[string]map[string]string
}

func (f *fakeS3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	out := &s3.ListBucketsOutput{}
	for _, name := range f.names {
		out.Buckets = append(out.Buckets, types.Bucket{Name: aws.String(name)})
	}
	return out, nil
}

func (f *fakeS3) GetBucketLocation(_ context.Context, in *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	return &s3.GetBucketLocationOutput{
		LocationConstraint: types.BucketLocationConstraint(f.region[aws.ToString(in.Bucket)]),
	}, nil
}

func (f *fakeS3) GetBucketVersioning(_ context.Context, in *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	name := aws.ToString(in.Bucket)
	return &s3.GetBucketVersioningOutput{Status: f.versioning[name], MFADelete: f.mfaDelete[name]}, nil
}

func (f *fakeS3) GetBucketLogging(_ context.Context, in *s3.GetBucketLoggingInput, _ ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	target, ok := f.logging[aws.ToString(in.Bucket)]
	if !ok {
		return &s3.GetBucketLoggingOutput{}, nil
	}
	return &s3.GetBucketLoggingOutput{LoggingEnabled: &types.LoggingEnabled{TargetBucket: aws.String(target)}}, nil
}

func (f *fakeS3) GetBucketPolicy(_ context.Context, in *s3.GetBucketPolicyInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	doc, ok := f.policy[aws.ToString(in.Bucket)]
	if !ok {
		return nil, errNotFound
	}
	return &s3.GetBucketPolicyOutput{Policy: aws.String(doc)}, nil
}

func (f *fakeS3) GetBucketAcl(_ context.Context, in *s3.GetBucketAclInput, _ ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	return &s3.GetBucketAclOutput{Grants: f.acl[aws.ToString(in.Bucket)]}, nil
}

func (f *fakeS3) GetPublicAccessBlock(_ context.Context, in *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	config, ok := f.block[aws.ToString(in.Bucket)]
	if !ok {
		return nil, errNotFound
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: config}, nil
}

func (f *fakeS3) GetBucketEncryption(_ context.Context, in *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	algorithm, ok := f.encryption[aws.ToString(in.Bucket)]
	if !ok {
		return nil, errNotFound
	}
	return &s3.GetBucketEncryptionOutput{
		ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
			Rules: []types.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{SSEAlgorithm: algorithm},
			}},
		},
	}, nil
}

func (f *fakeS3) GetBucketTagging(_ context.Context, in *s3.GetBucketTaggingInput, _ ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	tags, ok := f.tags[aws.ToString(in.Bucket)]
	if !ok {
		return nil, errNotFound
	}
	out := &s3.GetBucketTaggingOutput{}
	for key, value := range tags {
		out.TagSet = append(out.TagSet, types.Tag{Key: aws.String(key), Value: aws.String(value)})
	}
	return out, nil
}

func (f *fakeS3) GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	return nil, errNotFound
}

type notFound struct{}

func (notFound) Error() string { return "not found" }

var errNotFound = notFound{}

const publicPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::open/*"}]}`
const privatePolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::closed/*"}]}`

func fixture() (*fakeS3, awsservice.Scope) {
	open := true
	api := &fakeS3{
		names:  []string{"hardened", "open", "plain"},
		region: map[string]string{"hardened": "eu-west-1", "open": "", "plain": "EU"},
		versioning: map[string]types.BucketVersioningStatus{
			"hardened": types.BucketVersioningStatusEnabled,
		},
		mfaDelete: map[string]types.MFADeleteStatus{"hardened": types.MFADeleteStatusEnabled},
		logging:   map[string]string{"hardened": "logs"},
		policy:    map[string]string{"open": publicPolicy, "hardened": privatePolicy},
		acl: map[string][]types.Grant{
			"open": {{Grantee: &types.Grantee{Type: types.TypeGroup, URI: aws.String("http://acs.amazonaws.com/groups/global/AllUsers")}}},
		},
		block: map[string]*types.PublicAccessBlockConfiguration{
			"hardened": {IgnorePublicAcls: &open, RestrictPublicBuckets: &open},
			"open":     {},
			"plain":    {},
		},
		encryption: map[string]types.ServerSideEncryption{"hardened": types.ServerSideEncryptionAwsKms},
		tags:       map[string]map[string]string{"hardened": {"env": "prod"}},
	}
	scope := awsservice.Scope{
		Session: &session.Session{Identity: session.Identity{
			Account: "123456789012", Partition: "aws", ProfileRegion: "eu-west-1",
		}},
		Concurrency: 4,
	}
	return api, scope
}

func TestCollectBuildsBuckets(t *testing.T) {
	api, scope := fixture()
	svc, err := Collect(context.Background(), api, scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(svc.Buckets) != 3 {
		t.Fatalf("collected %d buckets, want 3", len(svc.Buckets))
	}

	byName := map[string]*Bucket{}
	for _, b := range svc.Buckets {
		byName[b.Name] = b
	}

	if got := byName["open"].Region; got != "us-east-1" {
		t.Errorf("an empty location constraint should mean us-east-1, got %q", got)
	}
	if got := byName["plain"].Region; got != "eu-west-1" {
		t.Errorf("the EU location constraint should mean eu-west-1, got %q", got)
	}
	if got := byName["hardened"].ARN; got != "arn:aws:s3:::hardened" {
		t.Errorf("ARN = %q", got)
	}
	if got := byName["hardened"].Encryption; got != "aws:kms" {
		t.Errorf("encryption = %q, want aws:kms", got)
	}
	if !byName["hardened"].Versioning || !byName["hardened"].MFADelete || !byName["hardened"].Logging {
		t.Errorf("hardened bucket lost its configuration: %+v", byName["hardened"])
	}
	if got := byName["hardened"].Tags["env"]; got != "prod" {
		t.Errorf("tags = %v", byName["hardened"].Tags)
	}
}

func TestRegionFilterNarrowsCollection(t *testing.T) {
	api, scope := fixture()
	scope.Regions = []string{"us-east-1"}

	svc, err := Collect(context.Background(), api, scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(svc.Buckets) != 1 || svc.Buckets[0].Name != "open" {
		t.Errorf("region filter kept %d buckets, want only open", len(svc.Buckets))
	}
}

// session serving the collected S3 state to the checks under test.
type fakeSession struct {
	s3        *Service
	s3control *AccountAccessBlock
}

func (fakeSession) Provider() string       { return "aws" }
func (fakeSession) Config() map[string]any { return nil }
func (f fakeSession) Service(name string) (any, error) {
	switch name {
	case "s3":
		return f.s3, nil
	case "s3control":
		if f.s3control == nil {
			return nil, nil
		}
		return f.s3control, nil
	}
	return nil, errNotFound
}

func runCheck(t *testing.T, c check.Check, s check.Session) map[string]*check.Report {
	t.Helper()
	reports, err := c.Execute(context.Background(), s)
	if err != nil {
		t.Fatalf("%s: %v", c.Metadata().CheckID, err)
	}
	byResource := make(map[string]*check.Report, len(reports))
	for _, r := range reports {
		byResource[r.ResourceID] = r
	}
	return byResource
}

func collectedSession(t *testing.T) fakeSession {
	t.Helper()
	api, scope := fixture()
	svc, err := Collect(context.Background(), api, scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return fakeSession{s3: svc}
}

func TestDefaultEncryptionCheck(t *testing.T) {
	got := runCheck(t, bucketDefaultEncryption{bucketCheck{"s3_bucket_default_encryption"}}, collectedSession(t))

	if r := got["hardened"]; r.Status != check.StatusPass ||
		r.StatusExtended != "S3 Bucket hardened has Server Side Encryption with aws:kms." {
		t.Errorf("hardened: %v %q", r.Status, r.StatusExtended)
	}
	if r := got["open"]; r.Status != check.StatusFail ||
		r.StatusExtended != "S3 Bucket open does not have Server Side Encryption enabled." {
		t.Errorf("open: %v %q", r.Status, r.StatusExtended)
	}
}

func TestVersioningAndLoggingChecks(t *testing.T) {
	s := collectedSession(t)

	versioning := runCheck(t, bucketObjectVersioning{bucketCheck{"s3_bucket_object_versioning"}}, s)
	if got := versioning["hardened"].StatusExtended; got != "S3 Bucket hardened has versioning enabled." {
		t.Errorf("versioning pass text = %q", got)
	}
	if got := versioning["open"].StatusExtended; got != "S3 Bucket open has versioning disabled." {
		t.Errorf("versioning fail text = %q", got)
	}

	logging := runCheck(t, bucketServerAccessLogging{bucketCheck{"s3_bucket_server_access_logging_enabled"}}, s)
	if got := logging["hardened"].StatusExtended; got != "S3 Bucket hardened has server access logging enabled." {
		t.Errorf("logging pass text = %q", got)
	}
	if got := logging["plain"].StatusExtended; got != "S3 Bucket plain has server access logging disabled." {
		t.Errorf("logging fail text = %q", got)
	}
}

func TestMFADeleteCheck(t *testing.T) {
	got := runCheck(t, bucketNoMFADelete{bucketCheck{"s3_bucket_no_mfa_delete"}}, collectedSession(t))
	if got["hardened"].StatusExtended != "S3 Bucket hardened has MFA Delete enabled." {
		t.Errorf("pass text = %q", got["hardened"].StatusExtended)
	}
	if got["open"].StatusExtended != "S3 Bucket open has MFA Delete disabled." {
		t.Errorf("fail text = %q", got["open"].StatusExtended)
	}
}

func TestPublicAccessCheckPerBucket(t *testing.T) {
	got := runCheck(t, bucketPublicAccess{bucketCheck{"s3_bucket_public_access"}}, collectedSession(t))

	if r := got["hardened"]; r.Status != check.StatusPass ||
		r.StatusExtended != "S3 Bucket hardened is not public." {
		t.Errorf("hardened: %v %q", r.Status, r.StatusExtended)
	}
	if r := got["open"]; r.Status != check.StatusFail ||
		!strings.Contains(r.StatusExtended, "has public access due to bucket") {
		t.Errorf("open: %v %q", r.Status, r.StatusExtended)
	}
	if r := got["plain"]; r.Status != check.StatusPass {
		t.Errorf("plain has neither a public ACL nor a policy, want PASS, got %v", r.Status)
	}
}

func TestPublicAccessCheckAtAccountLevel(t *testing.T) {
	s := collectedSession(t)
	s.s3control = &AccountAccessBlock{
		Account: "123456789012", Region: "eu-west-1",
		IgnorePublicACLs: true, RestrictPublicBuckets: true,
	}

	reports, err := bucketPublicAccess{bucketCheck{"s3_bucket_public_access"}}.Execute(context.Background(), s)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want a single account-level one", len(reports))
	}
	r := reports[0]
	if r.Status != check.StatusPass || r.StatusExtended != "All S3 public access blocked at account level." {
		t.Errorf("%v %q", r.Status, r.StatusExtended)
	}
	if r.ResourceARN != "arn:aws:s3:eu-west-1:123456789012:account" {
		t.Errorf("account ARN = %q", r.ResourceARN)
	}
}

func TestReportsCarryTheirResource(t *testing.T) {
	got := runCheck(t, bucketDefaultEncryption{bucketCheck{"s3_bucket_default_encryption"}}, collectedSession(t))
	var bucket map[string]any
	if err := json.Unmarshal(got["hardened"].Resource, &bucket); err != nil {
		t.Fatalf("resource is not valid JSON: %v", err)
	}
	if bucket["name"] != "hardened" {
		t.Errorf("resource = %v", bucket)
	}
}
