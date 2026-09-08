package cli

import "github.com/spf13/pflag"

// ProviderOptions holds the provider-specific flags. Exactly one of the
// pointers is non-nil, matching the subcommand the user invoked.
type ProviderOptions struct {
	AWS          *AWSOptions
	Azure        *AzureOptions
	GCP          *GCPOptions
	Kubernetes   *KubernetesOptions
	M365         *M365Options
	GitHub       *GitHubOptions
	Cloudflare   *CloudflareOptions
	OracleCloud  *OracleCloudOptions
	OpenStack    *OpenStackOptions
	AlibabaCloud *AlibabaCloudOptions
	IaC          *IaCOptions
	LLM          *LLMOptions
	NHN          *NHNOptions
	MongoDBAtlas *MongoDBAtlasOptions
}

type AWSOptions struct {
	Profile                  string
	Role                     string
	RoleSessionName          string
	MFA                      bool
	SessionDuration          int
	ExternalID               string
	Regions                  []string
	OrganizationsRole        string
	SecurityHub              bool
	SkipSecurityHubUpdate    bool
	SendSecurityHubOnlyFails bool
	QuickInventory           bool
	OutputBucket             string
	OutputBucketNoAssume     string
	ResourceTags             []string
	ResourceARNs             []string
	RetriesMaxAttempts       int
	ScanUnusedServices       bool
	Fixer                    bool
}

type AzureOptions struct {
	AzCLIAuth               bool
	ServicePrincipalEnvAuth bool
	BrowserAuth             bool
	ManagedIdentityAuth     bool
	SubscriptionIDs         []string
	TenantID                string
	Region                  string
}

type GCPOptions struct {
	CredentialsFile           string
	ImpersonateServiceAccount string
	OrganizationID            string
	ProjectIDs                []string
	ExcludedProjectIDs        []string
	ListProjectIDs            bool
	RetriesMaxAttempts        int
	SkipAPICheck              bool
}

type KubernetesOptions struct {
	KubeconfigFile string
	Context        string
	Namespaces     []string
	ClusterName    string
}

type M365Options struct {
	AzCLIAuth               bool
	ServicePrincipalEnvAuth bool
	EnvAuth                 bool
	BrowserAuth             bool
	CertificateAuth         bool
	CertificatePath         string
	TenantID                string
	InitModules             bool
	Region                  string
}

type GitHubOptions struct {
	PersonalAccessToken string
	OAuthAppToken       string
	AppID               string
	AppKey              string
	Repositories        []string
	Organizations       []string
}

type CloudflareOptions struct {
	AccountIDs []string
	Regions    []string
}

type OracleCloudOptions struct {
	ConfigFile           string
	Profile              string
	UseInstancePrincipal bool
	Region               string
	CompartmentIDs       []string
}

type OpenStackOptions struct {
	CloudsYAMLFile     string
	CloudsYAMLCloud    string
	AuthURL            string
	Username           string
	Password           string
	ProjectID          string
	RegionName         string
	UserDomainName     string
	ProjectDomainName  string
	IdentityAPIVersion string
}

type AlibabaCloudOptions struct {
	RoleARN         string
	RoleSessionName string
	ECSRAMRole      string
	OIDCRoleARN     string
	CredentialsURI  string
	Regions         []string
}

type IaCOptions struct {
	ScanPath            string
	ScanRepositoryURL   string
	Scanners            []string
	ExcludePaths        []string
	GitHubUsername      string
	PersonalAccessToken string
	OAuthAppToken       string
}

type LLMOptions struct {
	MaxConcurrency int
}

type NHNOptions struct {
	Username string
	Password string
	TenantID string
}

type MongoDBAtlasOptions struct {
	PublicKey  string
	PrivateKey string
	ProjectID  string
}

// registerProviderFlags attaches the flags of one provider to its subcommand.
func registerProviderFlags(fs *pflag.FlagSet, provider string, o *Options) {
	switch provider {
	case "aws":
		registerAWS(fs, o)
	case "azure":
		registerAzure(fs, o)
	case "gcp":
		registerGCP(fs, o)
	case "kubernetes":
		registerKubernetes(fs, o)
	case "m365":
		registerM365(fs, o)
	case "github":
		registerGitHub(fs, o)
	case "cloudflare":
		registerCloudflare(fs, o)
	case "oraclecloud":
		registerOracleCloud(fs, o)
	case "openstack":
		registerOpenStack(fs, o)
	case "alibabacloud":
		registerAlibabaCloud(fs, o)
	case "iac":
		registerIaC(fs, o)
	case "llm":
		registerLLM(fs, o)
	case "nhn":
		registerNHN(fs, o)
	case "mongodbatlas":
		registerMongoDBAtlas(fs, o)
	}
}

func registerAWS(fs *pflag.FlagSet, o *Options) {
	a := &AWSOptions{}
	o.Provider.AWS = a
	fs.StringVarP(&a.Profile, "profile", "p", "", "AWS profile to launch prowler with")
	fs.StringVarP(&a.Role, "role", "R", "", "ARN of the role to be assumed")
	fs.StringVar(&a.RoleSessionName, "role-session-name", "ProwlerAssessmentSession",
		"An identifier for the assumed role session. Defaults to ProwlerAssessmentSession")
	fs.BoolVar(&a.MFA, "mfa", false, "IAM entity enforces MFA so you need to input the MFA ARN and the TOTP")
	fs.IntVarP(&a.SessionDuration, "session-duration", "T", 3600,
		"Assumed role session duration in seconds, must be between 900 and 43200. Default: 3600")
	fs.StringVarP(&a.ExternalID, "external-id", "I", "", "External ID to be passed when assuming role")
	fs.StringSliceVarP(&a.Regions, "region", "f", nil, "AWS region names to run Prowler against")
	fs.StringVarP(&a.OrganizationsRole, "organizations-role", "O", "",
		"Specify AWS Organizations management role ARN to be assumed, to get Organization metadata")
	fs.BoolVarP(&a.SecurityHub, "security-hub", "S", false, "Send check output to AWS Security Hub")
	fs.BoolVar(&a.SkipSecurityHubUpdate, "skip-sh-update", false,
		"Skip updating previous findings of Prowler in Security Hub")
	fs.BoolVar(&a.SendSecurityHubOnlyFails, "send-sh-only-fails", false,
		"Send only Prowler failed findings to SecurityHub")
	fs.BoolVarP(&a.QuickInventory, "quick-inventory", "i", false, "Run inventory of AWS resources")
	fs.StringVarP(&a.OutputBucket, "output-bucket", "B", "",
		"Custom output bucket, requires --output-modes/-M to be set")
	fs.StringVarP(&a.OutputBucketNoAssume, "output-bucket-no-assume", "D", "",
		"Same as --output-bucket but do not use the assumed role credentials to put objects")
	fs.StringSliceVar(&a.ResourceTags, "resource-tag", nil,
		"Scan only resources with specific AWS Tags (Key=Value), e.g., Environment=dev Project=prowler")
	fs.StringSliceVar(&a.ResourceARNs, "resource-arn", nil,
		"Scan only resources with specific AWS Resource ARNs, e.g., arn:aws:iam::012345678910:user/test")
	fs.IntVar(&a.RetriesMaxAttempts, "aws-retries-max-attempts", 0,
		"Set the maximum retries for the standard retrier config")
	fs.BoolVar(&a.ScanUnusedServices, "scan-unused-services", false, "Scan unused services")
	fs.BoolVar(&a.Fixer, "fixer", false, "Fix the failed findings that can be fixed")
	aliasFlags(fs, map[string]string{"filter-region": "region", "resource-tags": "resource-tag", "resource-arns": "resource-arn"})
}

func registerAzure(fs *pflag.FlagSet, o *Options) {
	a := &AzureOptions{}
	o.Provider.Azure = a
	fs.BoolVar(&a.AzCLIAuth, "az-cli-auth", false, "Use Azure CLI authentication")
	fs.BoolVar(&a.ServicePrincipalEnvAuth, "sp-env-auth", false,
		"Use Azure Service Principal environment variables authentication")
	fs.BoolVar(&a.BrowserAuth, "browser-auth", false, "Use Azure interactive browser authentication")
	fs.BoolVar(&a.ManagedIdentityAuth, "managed-identity-auth", false, "Use Azure managed identity authentication")
	fs.StringSliceVar(&a.SubscriptionIDs, "subscription-id", nil, "Azure subscription IDs to be scanned")
	fs.StringVar(&a.TenantID, "tenant-id", "", "Azure tenant ID to be used with browser authentication")
	fs.StringVar(&a.Region, "azure-region", "AzureCloud", "Azure region to be used, default is AzureCloud")
	aliasFlags(fs, map[string]string{"subscription-ids": "subscription-id"})
}

func registerGCP(fs *pflag.FlagSet, o *Options) {
	g := &GCPOptions{}
	o.Provider.GCP = g
	fs.StringVar(&g.CredentialsFile, "credentials-file", "", "Authenticate using a GCP Service Account Key file")
	fs.StringVar(&g.ImpersonateServiceAccount, "impersonate-service-account", "",
		"Impersonate a GCP Service Account")
	fs.StringVar(&g.OrganizationID, "organization-id", "", "GCP Organization ID to be scanned")
	fs.StringSliceVar(&g.ProjectIDs, "project-id", nil, "GCP Project IDs to be scanned")
	fs.StringSliceVar(&g.ExcludedProjectIDs, "excluded-project-id", nil, "GCP Project IDs to be excluded")
	fs.BoolVar(&g.ListProjectIDs, "list-project-id", false, "List available GCP Project IDs")
	fs.IntVar(&g.RetriesMaxAttempts, "gcp-retries-max-attempts", 0,
		"Set the maximum retries for the standard retrier config")
	fs.BoolVar(&g.SkipAPICheck, "skip-api-check", false, "Skip the checks for enabled APIs")
	aliasFlags(fs, map[string]string{
		"project-ids": "project-id", "excluded-project-ids": "excluded-project-id",
		"list-project-ids": "list-project-id",
	})
}

func registerKubernetes(fs *pflag.FlagSet, o *Options) {
	k := &KubernetesOptions{}
	o.Provider.Kubernetes = k
	fs.StringVar(&k.KubeconfigFile, "kubeconfig-file", "~/.kube/config", "Path to the kubeconfig file")
	fs.StringVar(&k.Context, "context", "", "Context to be scanned")
	fs.StringSliceVar(&k.Namespaces, "namespace", nil, "Namespaces to be scanned")
	fs.StringVar(&k.ClusterName, "cluster-name", "", "Name of the cluster to be scanned")
	aliasFlags(fs, map[string]string{"namespaces": "namespace"})
}

func registerM365(fs *pflag.FlagSet, o *Options) {
	m := &M365Options{}
	o.Provider.M365 = m
	fs.BoolVar(&m.AzCLIAuth, "az-cli-auth", false, "Use Azure CLI authentication")
	fs.BoolVar(&m.ServicePrincipalEnvAuth, "sp-env-auth", false,
		"Use Azure Service Principal environment variables authentication")
	fs.BoolVar(&m.EnvAuth, "env-auth", false, "Use user and password environment variables authentication")
	fs.BoolVar(&m.BrowserAuth, "browser-auth", false, "Use Azure interactive browser authentication")
	fs.BoolVar(&m.CertificateAuth, "certificate-auth", false, "Use certificate authentication")
	fs.StringVar(&m.CertificatePath, "certificate-path", "", "Path to the certificate file")
	fs.StringVar(&m.TenantID, "tenant-id", "", "Microsoft 365 tenant ID")
	fs.BoolVar(&m.InitModules, "init-modules", false, "Install the required PowerShell modules")
	fs.StringVar(&m.Region, "region", "M365Global", "Microsoft 365 region, default is M365Global")
}

func registerGitHub(fs *pflag.FlagSet, o *Options) {
	g := &GitHubOptions{}
	o.Provider.GitHub = g
	fs.StringVar(&g.PersonalAccessToken, "personal-access-token", "", "GitHub personal access token")
	fs.StringVar(&g.OAuthAppToken, "oauth-app-token", "", "GitHub OAuth App token")
	fs.StringVar(&g.AppID, "github-app-id", "", "GitHub App ID")
	fs.StringVar(&g.AppKey, "github-app-key", "", "GitHub App key or path to the key file")
	fs.StringSliceVar(&g.Repositories, "repository", nil, "Repositories to be scanned")
	fs.StringSliceVar(&g.Organizations, "organization", nil, "Organizations to be scanned")
	aliasFlags(fs, map[string]string{
		"repositories": "repository", "organizations": "organization",
		"github-app-key-path": "github-app-key",
	})
}

func registerCloudflare(fs *pflag.FlagSet, o *Options) {
	c := &CloudflareOptions{}
	o.Provider.Cloudflare = c
	fs.StringSliceVar(&c.AccountIDs, "account-id", nil, "Cloudflare account IDs to be scanned")
	fs.StringSliceVarP(&c.Regions, "region", "f", nil, "Cloudflare regions to be scanned")
	aliasFlags(fs, map[string]string{"filter-region": "region"})
}

func registerOracleCloud(fs *pflag.FlagSet, o *Options) {
	c := &OracleCloudOptions{}
	o.Provider.OracleCloud = c
	fs.StringVar(&c.ConfigFile, "oci-config-file", "", "Path to the OCI config file")
	fs.StringVarP(&c.Profile, "profile", "p", "", "OCI profile to launch prowler with")
	fs.BoolVar(&c.UseInstancePrincipal, "use-instance-principal", false, "Use instance principal authentication")
	fs.StringVarP(&c.Region, "region", "r", "", "OCI region to be scanned")
	fs.StringSliceVar(&c.CompartmentIDs, "compartment-id", nil, "OCI compartment IDs to be scanned")
	aliasFlags(fs, map[string]string{"instance-principal": "use-instance-principal", "compartment": "compartment-id"})
}

func registerOpenStack(fs *pflag.FlagSet, o *Options) {
	s := &OpenStackOptions{}
	o.Provider.OpenStack = s
	fs.StringVar(&s.CloudsYAMLFile, "clouds-yaml-file", "", "Path to the clouds.yaml file")
	fs.StringVar(&s.CloudsYAMLCloud, "clouds-yaml-cloud", "", "Cloud entry to use from clouds.yaml")
	fs.StringVar(&s.AuthURL, "os-auth-url", "", "OpenStack authentication URL")
	fs.StringVar(&s.Username, "os-username", "", "OpenStack username")
	fs.StringVar(&s.Password, "os-password", "", "OpenStack password")
	fs.StringVar(&s.ProjectID, "os-project-id", "", "OpenStack project ID")
	fs.StringVar(&s.RegionName, "os-region-name", "", "OpenStack region name")
	fs.StringVar(&s.UserDomainName, "os-user-domain-name", "", "OpenStack user domain name")
	fs.StringVar(&s.ProjectDomainName, "os-project-domain-name", "", "OpenStack project domain name")
	fs.StringVar(&s.IdentityAPIVersion, "os-identity-api-version", "", "OpenStack identity API version")
}

func registerAlibabaCloud(fs *pflag.FlagSet, o *Options) {
	a := &AlibabaCloudOptions{}
	o.Provider.AlibabaCloud = a
	fs.StringVar(&a.RoleARN, "role-arn", "", "ARN of the RAM role to assume")
	fs.StringVar(&a.RoleSessionName, "role-session-name", "", "An identifier for the assumed role session")
	fs.StringVar(&a.ECSRAMRole, "ecs-ram-role", "", "ECS instance RAM role name")
	fs.StringVar(&a.OIDCRoleARN, "oidc-role-arn", "", "ARN of the RAM role to assume with OIDC")
	fs.StringVar(&a.CredentialsURI, "credentials-uri", "", "URI to fetch credentials from")
	fs.StringSliceVarP(&a.Regions, "region", "f", nil, "Alibaba Cloud region names to run Prowler against")
	aliasFlags(fs, map[string]string{"filter-region": "region"})
}

func registerIaC(fs *pflag.FlagSet, o *Options) {
	i := &IaCOptions{}
	o.Provider.IaC = i
	fs.StringVarP(&i.ScanPath, "scan-path", "P", ".", "Path to the directory to scan")
	fs.StringVarP(&i.ScanRepositoryURL, "scan-repository-url", "R", "", "URL of the repository to scan")
	fs.StringSliceVar(&i.Scanners, "scanners", []string{"misconfig", "secret"}, "Scanners to run")
	fs.StringSliceVar(&i.ExcludePaths, "exclude-path", nil, "Paths to exclude from the scan")
	fs.StringVar(&i.GitHubUsername, "github-username", "", "GitHub username for private repositories")
	fs.StringVar(&i.PersonalAccessToken, "personal-access-token", "", "GitHub personal access token")
	fs.StringVar(&i.OAuthAppToken, "oauth-app-token", "", "GitHub OAuth App token")
	aliasFlags(fs, map[string]string{"scanner": "scanners"})
}

func registerLLM(fs *pflag.FlagSet, o *Options) {
	l := &LLMOptions{}
	o.Provider.LLM = l
	fs.IntVar(&l.MaxConcurrency, "max-concurrency", 10, "Maximum number of concurrent requests")
}

func registerNHN(fs *pflag.FlagSet, o *Options) {
	n := &NHNOptions{}
	o.Provider.NHN = n
	fs.StringVar(&n.Username, "nhn-username", "", "NHN username")
	fs.StringVar(&n.Password, "nhn-password", "", "NHN password")
	fs.StringVar(&n.TenantID, "nhn-tenant-id", "", "NHN tenant ID")
}

func registerMongoDBAtlas(fs *pflag.FlagSet, o *Options) {
	m := &MongoDBAtlasOptions{}
	o.Provider.MongoDBAtlas = m
	fs.StringVar(&m.PublicKey, "atlas-public-key", "", "MongoDB Atlas public key")
	fs.StringVar(&m.PrivateKey, "atlas-private-key", "", "MongoDB Atlas private key")
	fs.StringVar(&m.ProjectID, "atlas-project-id", "", "MongoDB Atlas project ID")
}

// aliasFlags extends the flag set's normalisation with provider-specific
// alternative spellings.
func aliasFlags(fs *pflag.FlagSet, aliases map[string]string) {
	previous := fs.GetNormalizeFunc()
	fs.SetNormalizeFunc(func(f *pflag.FlagSet, name string) pflag.NormalizedName {
		if target, ok := aliases[name]; ok {
			name = target
		}
		return previous(f, name)
	})
}
