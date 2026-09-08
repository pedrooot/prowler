// Package aws implements the AWS provider: the session it scans under and
// the services its checks read from.
package aws

import (
	"context"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/provider/aws/service"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/provider/aws/session"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/scan"
)

// Provider adapts an AWS session to the scan engine.
type Provider struct {
	session *session.Session
	scope   service.Scope
	config  map[string]any
}

// New builds the provider from an established session.
func New(s *session.Session, scope service.Scope, config map[string]any) *Provider {
	scope.Session = s
	if len(scope.Regions) == 0 {
		scope.Regions = s.Identity.Regions
	}
	return &Provider{session: s, scope: scope, config: config}
}

func (p *Provider) Type() string { return "aws" }

func (p *Provider) Config() map[string]any { return p.config }

func (p *Provider) Identity() scan.Identity {
	id := p.session.Identity
	return scan.Identity{
		AuthMethod: p.session.AuthMethod(),
		AccountUID: id.Account,
		Partition:  id.Partition,
	}
}

// Collect delegates to the registered collector of the named service.
func (p *Provider) Collect(ctx context.Context, name string) (any, error) {
	return service.Collect(ctx, name, p.scope)
}

// Session exposes the underlying session to services that need it directly.
func (p *Provider) Session() *session.Session { return p.session }
