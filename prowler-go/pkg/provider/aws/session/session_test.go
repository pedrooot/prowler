package session

import "testing"

func TestPartitionOf(t *testing.T) {
	tests := []struct {
		arn     string
		want    string
		wantErr bool
	}{
		{"arn:aws:iam::123456789012:user/prowler", "aws", false},
		{"arn:aws-us-gov:iam::123456789012:user/prowler", "aws-us-gov", false},
		{"arn:aws-cn:iam::123456789012:role/prowler", "aws-cn", false},
		{"arn:aws-iso:sts::123456789012:assumed-role/x/y", "aws-iso", false},
		{"not-an-arn", "", true},
		{"arn::iam::123:user/x", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		got, err := PartitionOf(tt.arn)
		if tt.wantErr {
			if err == nil {
				t.Errorf("PartitionOf(%q) should have failed", tt.arn)
			}
			continue
		}
		if err != nil {
			t.Errorf("PartitionOf(%q): %v", tt.arn, err)
			continue
		}
		if got != tt.want {
			t.Errorf("PartitionOf(%q) = %q, want %q", tt.arn, got, tt.want)
		}
	}
}

func TestAuthMethod(t *testing.T) {
	withProfile := &Session{Identity: Identity{Profile: "prod"}}
	if got := withProfile.AuthMethod(); got != "profile: prod" {
		t.Errorf("AuthMethod = %q, want %q", got, "profile: prod")
	}
	if got := (&Session{}).AuthMethod(); got != "credentials" {
		t.Errorf("AuthMethod = %q, want credentials", got)
	}
}
