package s3

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3control"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
	awsservice "github.com/prowler-cloud/prowler/prowler-go/pkg/provider/aws/service"
)

func init() {
	awsservice.Register("s3control", collectControl)
}

// AccountAccessBlock is the account-wide block public access configuration.
type AccountAccessBlock struct {
	Account               string `json:"account"`
	Region                string `json:"region"`
	BlockPublicACLs       bool   `json:"block_public_acls"`
	IgnorePublicACLs      bool   `json:"ignore_public_acls"`
	BlockPublicPolicy     bool   `json:"block_public_policy"`
	RestrictPublicBuckets bool   `json:"restrict_public_buckets"`
}

func (a *AccountAccessBlock) ResourceID() string              { return a.Account }
func (a *AccountAccessBlock) ResourceName() string            { return a.Account }
func (a *AccountAccessBlock) ResourceRegion() string          { return a.Region }
func (a *AccountAccessBlock) ResourceTags() map[string]string { return nil }

// ControlAPI is the subset of the S3 Control client the collector uses.
type ControlAPI interface {
	GetPublicAccessBlock(context.Context, *s3control.GetPublicAccessBlockInput, ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

func collectControl(ctx context.Context, scope awsservice.Scope) (any, error) {
	return CollectControl(ctx, s3control.NewFromConfig(scope.Session.Config), scope)
}

// CollectControl reads the account-level public access block. An account that
// has never configured one returns no block, which is not an error.
func CollectControl(ctx context.Context, api ControlAPI, scope awsservice.Scope) (*AccountAccessBlock, error) {
	identity := scope.Session.Identity
	out, err := api.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
		AccountId: aws.String(identity.Account),
	})
	if err != nil || out.PublicAccessBlockConfiguration == nil {
		return nil, nil
	}

	c := out.PublicAccessBlockConfiguration
	return &AccountAccessBlock{
		Account:               identity.Account,
		Region:                identity.ProfileRegion,
		BlockPublicACLs:       aws.ToBool(c.BlockPublicAcls),
		IgnorePublicACLs:      aws.ToBool(c.IgnorePublicAcls),
		BlockPublicPolicy:     aws.ToBool(c.BlockPublicPolicy),
		RestrictPublicBuckets: aws.ToBool(c.RestrictPublicBuckets),
	}, nil
}

// accountAccessBlock reads the s3control service out of the session, treating
// an account with no configuration as no block.
func accountAccessBlock(s check.Session) (*AccountAccessBlock, error) {
	resources, err := s.Service("s3control")
	if err != nil {
		return nil, err
	}
	if resources == nil {
		return nil, nil
	}
	block, ok := resources.(*AccountAccessBlock)
	if !ok {
		return nil, fmt.Errorf("s3control: unexpected resource type %T", resources)
	}
	return block, nil
}
