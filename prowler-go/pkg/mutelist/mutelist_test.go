package mutelist

import (
	"testing"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/finding"
)

func load(t *testing.T, yaml string) *Mutelist {
	t.Helper()
	m, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

func findingFor(checkID, account, region, resource string, tags map[string]string) *finding.Finding {
	return &finding.Finding{
		AccountUID:   account,
		Region:       region,
		ResourceUID:  resource,
		ResourceTags: tags,
		Metadata:     &check.Metadata{CheckID: checkID, ServiceName: "ec2"},
	}
}

func TestWildcardAccountAndRegion(t *testing.T) {
	m := load(t, `
Mutelist:
  Accounts:
    '*':
      Checks:
        ec2_instance_detailed_monitoring_enabled:
          Regions: ['*']
          Resources: ['i-123456789']
`)
	if !m.Muted(findingFor("ec2_instance_detailed_monitoring_enabled", "111", "eu-west-1", "i-123456789", nil)) {
		t.Error("the listed resource should be muted")
	}
	if m.Muted(findingFor("ec2_instance_detailed_monitoring_enabled", "111", "eu-west-1", "i-999999999", nil)) {
		t.Error("an unlisted resource must not be muted")
	}
	if m.Muted(findingFor("ec2_other_check", "111", "eu-west-1", "i-123456789", nil)) {
		t.Error("a different check must not be muted")
	}
}

func TestAccountScoping(t *testing.T) {
	m := load(t, `
Mutelist:
  Accounts:
    '123456789012':
      Checks:
        '*':
          Regions: ['*']
          Resources: ['*']
`)
	if !m.Muted(findingFor("any_check", "123456789012", "eu-west-1", "r", nil)) {
		t.Error("the listed account should be muted")
	}
	if m.Muted(findingFor("any_check", "999999999999", "eu-west-1", "r", nil)) {
		t.Error("another account must not be muted")
	}
}

func TestRegionScoping(t *testing.T) {
	m := load(t, `
Mutelist:
  Accounts:
    '*':
      Checks:
        '*':
          Regions: ['eu-west-1', 'us-east-1']
          Resources: ['*']
`)
	if !m.Muted(findingFor("c", "1", "us-east-1", "r", nil)) {
		t.Error("us-east-1 should be muted")
	}
	if m.Muted(findingFor("c", "1", "ap-south-1", "r", nil)) {
		t.Error("ap-south-1 must not be muted")
	}
}

func TestTagsUseAndLogicAcrossEntries(t *testing.T) {
	m := load(t, `
Mutelist:
  Accounts:
    '*':
      Checks:
        '*':
          Regions: ['*']
          Resources: ['*']
          Tags:
            - 'Name=Admin'
            - 'Env=Prod'
`)
	both := map[string]string{"Name": "Admin", "Env": "Prod"}
	if !m.Muted(findingFor("c", "1", "eu-west-1", "r", both)) {
		t.Error("a resource carrying both tags should be muted")
	}
	only := map[string]string{"Name": "Admin"}
	if m.Muted(findingFor("c", "1", "eu-west-1", "r", only)) {
		t.Error("a resource missing one of the tags must not be muted")
	}
}

func TestTagsUseOrLogicWithinOnePattern(t *testing.T) {
	m := load(t, `
Mutelist:
  Accounts:
    '*':
      Checks:
        '*':
          Regions: ['*']
          Resources: ['*']
          Tags:
            - 'Name=Admin|Env=Prod'
`)
	if !m.Muted(findingFor("c", "1", "eu-west-1", "r", map[string]string{"Env": "Prod"})) {
		t.Error("regex alternation should mute when either side matches")
	}
	if m.Muted(findingFor("c", "1", "eu-west-1", "r", map[string]string{"Team": "sec"})) {
		t.Error("a resource matching neither side must not be muted")
	}
}

func TestExceptionUnmutes(t *testing.T) {
	m := load(t, `
Mutelist:
  Accounts:
    '*':
      Checks:
        '*':
          Regions: ['*']
          Resources: ['*']
          Exceptions:
            Regions: ['eu-west-1']
`)
	if m.Muted(findingFor("c", "1", "eu-west-1", "r", nil)) {
		t.Error("the excepted region must not be muted")
	}
	if !m.Muted(findingFor("c", "1", "us-east-1", "r", nil)) {
		t.Error("a region outside the exception should stay muted")
	}
}

func TestLambdaPrefixMapsToAwslambda(t *testing.T) {
	m := load(t, `
Mutelist:
  Accounts:
    '*':
      Checks:
        lambda_function_no_secrets_in_code:
          Regions: ['*']
          Resources: ['*']
`)
	if !m.Muted(findingFor("awslambda_function_no_secrets_in_code", "1", "eu-west-1", "r", nil)) {
		t.Error("a lambda-prefixed entry should match the awslambda check")
	}
}

func TestNilMutelistMutesNothing(t *testing.T) {
	var m *Mutelist
	if m.Muted(findingFor("c", "1", "eu-west-1", "r", nil)) {
		t.Error("a nil mutelist must mute nothing")
	}
}

func TestMissingRequiredKeysAreRejected(t *testing.T) {
	for _, doc := range []string{
		`Mutelist: {}`,
		"Mutelist:\n  Accounts:\n    '*': {}\n",
		"Mutelist:\n  Accounts:\n    '*':\n      Checks:\n        c:\n          Regions: ['*']\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("expected %q to be rejected", doc)
		}
	}
}
