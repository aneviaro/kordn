// Package config owns the versioned, immutable startup document. Loading and
// validating a Config has no runtime side effects: it does not resolve
// credentials, open listeners, or start a process.
package config

const (
	APIVersion = "kordn.dev/v1alpha1"
	Kind       = "LocalRunPolicy"

	DefaultListen                       = "127.0.0.1:0"
	DefaultNonAWSTraffic                = "tunnel"
	DefaultUpstreamProxy                = "inherit"
	DefaultMaxInMemoryBodyBytes   int64 = 8 * 1024 * 1024
	DefaultMaxSpoolBodyBytes      int64 = 64 * 1024 * 1024
	DefaultRoleSessionName              = "kordn-local"
	DefaultRoleDurationSeconds          = 3600
	DefaultAuditPath                    = "~/.kordn/audit/events.jsonl"
	DefaultAuditFsync                   = FsyncBatch
	DefaultAuditFailureMode             = AuditDeny
	DefaultAuditLogResourceARNs         = true
	DefaultAuditHashResourceNames       = false
)

// Effect is the only rule outcome. V0.1 has no warning, approval, or
// permissive fallback effect.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// PolicyDefault is separate from Effect so a rule effect cannot accidentally
// be used as a policy default in a future extension.
type PolicyDefault string

const PolicyDeny PolicyDefault = "deny"

// FsyncMode controls audit durability.
type FsyncMode string

const (
	FsyncBatch    FsyncMode = "batch"
	FsyncDecision FsyncMode = "decision"
)

// AuditFailureMode controls behavior when the audit writer cannot accept an
// event. V0.1 intentionally exposes only fail-closed behavior.
type AuditFailureMode string

const AuditDeny AuditFailureMode = "deny"

// Config is the complete startup snapshot. SourcePath and PolicyHash are
// derived values and are never accepted from YAML.
type Config struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Upstream   Upstream `yaml:"upstream" json:"upstream"`
	Proxy      Proxy    `yaml:"proxy" json:"proxy"`
	Policy     Policy   `yaml:"policy" json:"policy"`
	Audit      Audit    `yaml:"audit" json:"audit"`

	SourcePath string `yaml:"-" json:"-"`
	PolicyHash string `yaml:"-" json:"-"`
}

// Upstream selects one explicit shared-config profile and, optionally, one
// fixed AssumeRole ceiling. The child cannot select either value.
type Upstream struct {
	Profile         string `yaml:"profile" json:"profile"`
	AssumeRoleARN   string `yaml:"assumeRoleArn" json:"assumeRoleArn"`
	ExternalID      string `yaml:"externalId" json:"externalId"`
	SourceIdentity  string `yaml:"sourceIdentity" json:"sourceIdentity"`
	RoleSessionName string `yaml:"roleSessionName" json:"roleSessionName"`
	DurationSeconds int    `yaml:"durationSeconds" json:"durationSeconds"`
	Region          string `yaml:"region" json:"region"`
}

// Proxy contains local listener, chaining, and bounded request-body settings.
type Proxy struct {
	Listen               string `yaml:"listen" json:"listen"`
	NonAWSTraffic        string `yaml:"nonAwsTraffic" json:"nonAwsTraffic"`
	UpstreamProxy        string `yaml:"upstreamProxy" json:"upstreamProxy"`
	MaxInMemoryBodyBytes int64  `yaml:"maxInMemoryBodyBytes" json:"maxInMemoryBodyBytes"`
	MaxSpoolBodyBytes    int64  `yaml:"maxSpoolBodyBytes" json:"maxSpoolBodyBytes"`
}

// Policy is immutable after Load. Rule ordering and set-like list ordering
// have no authorization meaning and are normalized for PolicyHash.
type Policy struct {
	Default PolicyDefault `yaml:"default" json:"default"`
	Rules   []Rule        `yaml:"rules" json:"rules"`
}

type Rule struct {
	ID                       string   `yaml:"id" json:"id"`
	Effect                   Effect   `yaml:"effect" json:"effect"`
	Actions                  []string `yaml:"actions" json:"actions"`
	Resources                []string `yaml:"resources" json:"resources"`
	Regions                  []string `yaml:"regions,omitempty" json:"regions,omitempty"`
	Accounts                 []string `yaml:"accounts,omitempty" json:"accounts,omitempty"`
	Partitions               []string `yaml:"partitions,omitempty" json:"partitions,omitempty"`
	AllowAWSRequiredWildcard bool     `yaml:"allowAwsRequiredWildcard,omitempty" json:"allowAwsRequiredWildcard,omitempty"`
}

// Audit controls the append-only JSONL destination and resource redaction.
type Audit struct {
	Path              string           `yaml:"path" json:"path"`
	Fsync             FsyncMode        `yaml:"fsync" json:"fsync"`
	FailureMode       AuditFailureMode `yaml:"failureMode" json:"failureMode"`
	LogResourceARNs   bool             `yaml:"logResourceArns" json:"logResourceArns"`
	HashResourceNames bool             `yaml:"hashResourceNames" json:"hashResourceNames"`
}
