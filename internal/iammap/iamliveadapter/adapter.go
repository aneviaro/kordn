package iamliveadapter

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
	"github.com/kordn-ai/kordn/internal/iammap/data"
)

const UpstreamCommit = iamlivecatalog.UpstreamCommit
const AdapterVersion = "iamlive-derived/v1@" + UpstreamCommit

type Action struct{ Service, Name string }
type DependencyCandidate struct {
	Action    Action
	Resources []string
}
type DependencyResult struct {
	Candidates []DependencyCandidate
	Certain    bool
}
type LookupResult struct {
	Entry               data.Entry
	Primary             []Action
	Dependencies        []DependencyCandidate
	DependenciesCertain bool
}
type Adapter struct{ catalog *iamlivecatalog.Catalog }

func New() (*Adapter, error) {
	c, e := iamlivecatalog.Load()
	if e != nil {
		return nil, e
	}
	return &Adapter{catalog: c}, nil
}
func NormalizeOperation(operation string) string {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return ""
	}
	for _, r := range operation {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return ""
		}
	}
	return operation
}
func (a *Adapter) Lookup(service, operation string, parameters ...map[string]awsrequest.Value) (LookupResult, error) {
	if a == nil || a.catalog == nil {
		return LookupResult{}, fmt.Errorf("adapter unavailable")
	}
	op := NormalizeOperation(operation)
	if op == "" {
		return LookupResult{}, fmt.Errorf("unknown operation")
	}
	if len(parameters) > 1 {
		return LookupResult{}, fmt.Errorf("too many parameter maps")
	}
	var p map[string]awsrequest.Value
	if len(parameters) == 1 {
		p = parameters[0]
	}
	o, e := a.catalog.Operation(service, op)
	if e != nil {
		return LookupResult{}, fmt.Errorf("unknown operation")
	}
	if o.MappingState != iamlivecatalog.EvidenceKnown {
		return LookupResult{}, fmt.Errorf("operation mapping evidence unavailable: %s", o.MappingState)
	}
	if len(o.Mappings) == 0 {
		return LookupResult{}, fmt.Errorf("operation has no iamlive mapping")
	}
	entry := entryFor(a.catalog, service, o)
	primary := []Action{}
	seen := map[string]bool{}
	deps := []DependencyCandidate{}
	certain := true
	for _, m := range o.Mappings {
		// A mapping is authorization-facing only when the cross-file catalog
		// validation established exactly one non-contradictory definition.
		// Unknown or conflicting evidence must remain fail-closed.
		if m.State == iamlivecatalog.EvidenceAbsent {
			return LookupResult{}, fmt.Errorf("mapping action evidence absent: %s", m.Action)
		}
		if m.State == iamlivecatalog.EvidenceContradictory {
			return LookupResult{}, fmt.Errorf("mapping action evidence contradictory: %s", m.Action)
		}
		if m.State != iamlivecatalog.EvidenceKnown {
			return LookupResult{}, fmt.Errorf("mapping action evidence unavailable: %s", m.Action)
		}
		parts := strings.SplitN(m.Action, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return LookupResult{}, fmt.Errorf("malformed action mapping")
		}
		act := Action{Service: parts[0], Name: parts[1]}
		// Every non-PassRole mapping is primary evidence, including an
		// action in another IAM service. The operation's endpoint service is
		// not a safe substitute for the upstream action service.
		if !strings.EqualFold(parts[1], "PassRole") {
			k := strings.ToLower(m.Action)
			if !seen[k] {
				seen[k] = true
				primary = append(primary, act)
			}
			continue
		}
		if strings.EqualFold(parts[1], "PassRole") {
			vals, ok := dependencyValues(m, p)
			if !ok {
				certain = false
			}
			for _, v := range vals {
				deps = append(deps, DependencyCandidate{Action: act, Resources: []string{v}})
			}
			if len(vals) == 0 {
				certain = false
			}
		}
	}
	if len(primary) == 0 {
		return LookupResult{}, fmt.Errorf("mapping has no primary action")
	}
	return LookupResult{Entry: entry, Primary: append([]Action(nil), primary...), Dependencies: deps, DependenciesCertain: certain}, nil
}
func entryFor(c *iamlivecatalog.Catalog, service string, o iamlivecatalog.Operation) data.Entry {
	m := o.Mappings[0]
	e := data.Entry{Service: strings.ToLower(service), Operation: o.Name, Action: m.Action, Resource: "global", Scope: "known_global"}
	a, err := c.Action(m.Action)
	if err != nil {
		return e
	}
	for _, r := range a.Resources {
		e.Dependencies = append(e.Dependencies, r.DependentActions...)
		if r.Name != "" && e.Resource == "global" {
			e.Resource = r.Name
			e.Scope = "exact"
		}
	}
	if len(a.Resources) > 1 && e.Resource != "global" {
		e.Scope = "unresolved"
	}
	return e
}
func dependencyValues(m iamlivecatalog.ActionMapping, p map[string]awsrequest.Value) ([]string, bool) {
	names := []string{"Role", "RoleArn", "TaskRoleArn", "ExecutionRoleArn", "IamRoleArn"}
	if m.ARNOverride != "" {
		for _, n := range templateNames(m.ARNOverride) {
			names = []string{n}
			break
		}
	}
	values := Find(p, names...)
	return values, len(values) > 0
}
func templateNames(t string) []string {
	out := []string{}
	for {
		i := strings.Index(t, "${")
		if i < 0 {
			break
		}
		t = t[i+2:]
		j := strings.IndexByte(t, '}')
		if j < 0 {
			break
		}
		n := t[:j]
		if strings.IndexAny(n, "[].") < 0 {
			out = append(out, n)
		}
		t = t[j+1:]
	}
	return out
}
func (a *Adapter) LookupOperation(service, operation string) (string, data.Entry, error) {
	x, e := a.Lookup(service, operation)
	if e != nil {
		return "", data.Entry{}, e
	}
	return x.Entry.Operation, x.Entry, nil
}
func (a *Adapter) Version() string {
	if a == nil || a.catalog == nil {
		return ""
	}
	return AdapterVersion
}
func (a *Adapter) DataVersion() string {
	if a == nil || a.catalog == nil {
		return ""
	}
	return data.AuthorizationDataVersion()
}
func Find(v map[string]awsrequest.Value, names ...string) []string {
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	out := []string{}
	var walk func(string, awsrequest.Value, int)
	walk = func(k string, x awsrequest.Value, d int) {
		if d > 16 {
			return
		}
		if x.Kind == awsrequest.ValueString && want[strings.ToLower(k)] && x.String != "" {
			out = append(out, x.String)
		}
		if x.Kind == awsrequest.ValueObject {
			for k, v := range x.Object {
				walk(k, v, d+1)
			}
		}
		if x.Kind == awsrequest.ValueArray {
			for _, v := range x.Array {
				if v.Kind == awsrequest.ValueObject {
					for k, x := range v.Object {
						walk(k, x, d+1)
					}
				}
			}
		}
	}
	for k, x := range v {
		walk(k, x, 0)
	}
	return out
}
func (a *Adapter) Map(context.Context, *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
	return nil, fmt.Errorf("iamlive adapter is metadata-only; use kordn mapper")
}
