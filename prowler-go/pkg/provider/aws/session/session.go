// Package session establishes the AWS credentials and identity a scan runs
// under, including assumed roles and their refresh.
package session

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Identity is who the scan runs as, resolved from STS.
type Identity struct {
	Account       string
	AccountARN    string
	UserID        string
	Partition     string
	IdentityARN   string
	Profile       string
	ProfileRegion string
	Regions       []string
}

// AssumeRole describes a role the scan should assume before reading anything.
type AssumeRole struct {
	RoleARN     string
	SessionName string
	ExternalID  string
	Duration    time.Duration
	// MFA is resolved by Prompt when the role requires it.
	MFASerial string
	MFAPrompt func(serial string) (string, error)
}

// Options configures how the session is built.
type Options struct {
	Profile            string
	Region             string
	Regions            []string
	RetriesMaxAttempts int
	Role               *AssumeRole
}

// Session is a configured AWS session plus the identity behind it.
type Session struct {
	Config   aws.Config
	Identity Identity
}

// New resolves credentials, assumes a role when asked, and reads back the
// caller identity.
func New(ctx context.Context, opts Options) (*Session, error) {
	loadOpts := []func(*awsconfig.LoadOptions) error{}
	if opts.Profile != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(opts.Profile))
	}
	if opts.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(opts.Region))
	}
	if opts.RetriesMaxAttempts > 0 {
		loadOpts = append(loadOpts, awsconfig.WithRetryMaxAttempts(opts.RetriesMaxAttempts))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	if opts.Role != nil {
		cfg, err = assume(ctx, cfg, *opts.Role)
		if err != nil {
			return nil, err
		}
	}

	identity, err := resolveIdentity(ctx, cfg, opts)
	if err != nil {
		return nil, err
	}
	return &Session{Config: cfg, Identity: identity}, nil
}

// assume swaps the session's credentials for those of an assumed role. The
// provider refreshes them on expiry, so long scans do not lose access.
func assume(ctx context.Context, cfg aws.Config, role AssumeRole) (aws.Config, error) {
	client := sts.NewFromConfig(cfg)
	provider := stscreds.NewAssumeRoleProvider(client, role.RoleARN, func(o *stscreds.AssumeRoleOptions) {
		if role.SessionName != "" {
			o.RoleSessionName = role.SessionName
		}
		if role.ExternalID != "" {
			o.ExternalID = aws.String(role.ExternalID)
		}
		if role.Duration > 0 {
			o.Duration = role.Duration
		}
		if role.MFASerial != "" {
			o.SerialNumber = aws.String(role.MFASerial)
			o.TokenProvider = func() (string, error) { return role.MFAPrompt(role.MFASerial) }
		}
	})

	cfg.Credentials = aws.NewCredentialsCache(provider)
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return cfg, fmt.Errorf("assume role %s: %w", role.RoleARN, err)
	}
	return cfg, nil
}

func resolveIdentity(ctx context.Context, cfg aws.Config, opts Options) (Identity, error) {
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, fmt.Errorf("get caller identity: %w", err)
	}

	arn := aws.ToString(out.Arn)
	partition, err := PartitionOf(arn)
	if err != nil {
		return Identity{}, err
	}
	account := aws.ToString(out.Account)

	return Identity{
		Account:       account,
		AccountARN:    fmt.Sprintf("arn:%s:iam::%s:root", partition, account),
		UserID:        aws.ToString(out.UserId),
		Partition:     partition,
		IdentityARN:   arn,
		Profile:       opts.Profile,
		ProfileRegion: cfg.Region,
		Regions:       opts.Regions,
	}, nil
}

// PartitionOf extracts the partition from an ARN, which is what decides the
// endpoints and the ARNs a scan builds.
func PartitionOf(arn string) (string, error) {
	parts := strings.SplitN(arn, ":", 3)
	if len(parts) < 3 || parts[0] != "arn" || parts[1] == "" {
		return "", fmt.Errorf("invalid identity ARN %q", arn)
	}
	return parts[1], nil
}

// AuthMethod describes how the session authenticated, for the finding's
// auth_method field.
func (s *Session) AuthMethod() string {
	if s.Identity.Profile != "" {
		return "profile: " + s.Identity.Profile
	}
	return "credentials"
}
