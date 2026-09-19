// Package data is a compatibility facade over the immutable iamlive catalog.
package data

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
)

const (
	SnapshotVersion = "iamlive-catalog/v3@" + iamlivecatalog.UpstreamCommit
	SnapshotSource  = "github.com/iann0036/iamlive/iamlivecore/{map.json,iam_definition.json,apis/**}"
	SnapshotDate    = "pinned"
)

type Entry struct {
	Service      string   `json:"service"`
	Operation    string   `json:"operation"`
	Action       string   `json:"action"`
	Resource     string   `json:"resource"`
	Scope        string   `json:"scope,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// Entries is retained for callers written against the old facade. Records are
// derived at construction time from upstream mappings and SAR definitions; no
// Kordn operation dataset is embedded or consulted.
func Entries() ([]Entry, error) {
	c, e := iamlivecatalog.Load()
	if e != nil {
		return nil, e
	}
	out := []Entry{}
	err := c.ForEachOperationOccurrence(func(occurrence iamlivecatalog.OperationOccurrence) error {
		s := occurrence.Service.EndpointPrefix
		o := occurrence.Operation
		if c.OperationCardinality(s, o.Name) != 1 || o.State != iamlivecatalog.EvidenceKnown || o.MappingState != iamlivecatalog.EvidenceKnown || !occurrence.Plan.Valid() || len(occurrence.Plan.Mappings) == 0 {
			return nil
		}
		m := occurrence.Plan.Mappings[0].Mapping
		if m.State != iamlivecatalog.EvidenceKnown || len(strings.SplitN(m.Action, ":", 2)) != 2 {
			return nil
		}
		a := occurrence.Plan.Mappings[0].Definition
		if a.State != iamlivecatalog.EvidenceKnown {
			return nil
		}
		resource, scope := "global", "known_global"
		var deps []string
		var nonGlobal []iamlivecatalog.ResourceType
		for _, r := range a.Resources {
			if r.Name != "" {
				nonGlobal = append(nonGlobal, r)
			}
			deps = append(deps, r.DependentActions...)
		}
		if len(nonGlobal) > 0 {
			resource, scope = nonGlobal[0].Name, "exact"
			if len(nonGlobal) > 1 {
				scope = "unresolved"
			}
		}
		sort.Strings(deps)
		x := Entry{Service: strings.ToLower(s), Operation: o.Name, Action: m.Action, Resource: resource, Scope: scope, Dependencies: append([]string(nil), deps...)}
		out = append(out, x)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].Operation < out[j].Operation
	})
	if len(out) == 0 {
		return nil, errors.New("catalog has no mapped operations")
	}
	return out, nil
}

func operationRecordCount(c *iamlivecatalog.Catalog, service, operation string) int {
	return c.OperationCardinality(service, operation)
}

func ValidateEntry(e Entry) error {
	if e.Service == "" || e.Operation == "" || e.Action == "" || e.Resource == "" {
		return errors.New("incomplete catalog entry")
	}
	c, err := iamlivecatalog.Load()
	if err != nil {
		return err
	}
	if operationRecordCount(c, e.Service, e.Operation) != 1 {
		return fmt.Errorf("ambiguous catalog operation: %s:%s", e.Service, e.Operation)
	}
	occurrences := c.OperationOccurrences(e.Service, e.Operation)
	if len(occurrences) != 1 {
		return fmt.Errorf("catalog operation occurrence unavailable: %s:%s", e.Service, e.Operation)
	}
	op := occurrences[0].Operation
	plan := occurrences[0].Plan
	if op.State != iamlivecatalog.EvidenceKnown || op.MappingState != iamlivecatalog.EvidenceKnown || !plan.Valid() {
		return fmt.Errorf("catalog static validation failed: %s:%s", e.Service, e.Operation)
	}
	var a iamlivecatalog.ActionDefinition
	found := false
	for _, compiled := range plan.Mappings {
		if compiled.Mapping.Action == e.Action {
			if compiled.Mapping.State != iamlivecatalog.EvidenceKnown {
				return fmt.Errorf("catalog action mapping evidence is %s: %s", compiled.Mapping.State, e.Action)
			}
			a, found = compiled.Definition, true
			break
		}
	}
	if !found || a.State != iamlivecatalog.EvidenceKnown {
		return fmt.Errorf("catalog operation/action disagreement: %s:%s", e.Service, e.Operation)
	}
	namedResources := make([]string, 0, len(a.Resources))
	for _, r := range a.Resources {
		if r.Name != "" {
			namedResources = append(namedResources, r.Name)
		}
	}
	if e.Resource == "global" {
		if len(namedResources) != 0 || e.Scope != "known_global" {
			return fmt.Errorf("global resource metadata disagreement: %s", e.Action)
		}
	} else if len(namedResources) == 1 {
		if namedResources[0] != e.Resource || e.Scope != "exact" {
			return fmt.Errorf("catalog resource metadata disagreement: %s/%s", e.Action, e.Resource)
		}
	} else if len(namedResources) <= 1 || namedResources[0] != e.Resource || e.Scope != "unresolved" {
		return fmt.Errorf("catalog resource metadata disagreement: %s/%s", e.Action, e.Resource)
	}
	var need []string
	for _, r := range a.Resources {
		need = append(need, r.DependentActions...)
	}
	have := append([]string(nil), e.Dependencies...)
	sort.Strings(need)
	sort.Strings(have)
	if len(need) != len(have) {
		return fmt.Errorf("catalog dependency disagreement")
	}
	for i := range need {
		if need[i] != have[i] {
			return fmt.Errorf("catalog dependency disagreement: %s", need[i])
		}
	}
	return nil
}

func AuthorizationDataVersion() string {
	c, e := iamlivecatalog.Load()
	if e != nil {
		return SnapshotVersion
	}
	return c.Version() + "+sha256:" + c.SourceHash()
}
func SourceVersion() string { return SnapshotVersion }

// These names remain source-compatible but intentionally expose no generated
// or widening-baseline bytes.
func GeneratedBytes() []byte            { return nil }
func BaselineBytes() []byte             { return nil }
func BaselineEntries() ([]Entry, error) { return Entries() }
func CheckNoWidening(base, candidate []Entry) error {
	bm := map[string]Entry{}
	for _, x := range base {
		k := x.Service + "\x00" + x.Operation
		if _, ok := bm[k]; ok {
			return fmt.Errorf("widening: duplicate operation %s", k)
		}
		bm[k] = x
	}
	cm := map[string]Entry{}
	for _, x := range candidate {
		k := x.Service + "\x00" + x.Operation
		if _, ok := cm[k]; ok {
			return fmt.Errorf("widening: duplicate operation %s", k)
		}
		cm[k] = x
		if _, ok := bm[k]; !ok {
			return fmt.Errorf("widening: new operation %s", k)
		}
	}
	for k, b := range bm {
		c, ok := cm[k]
		if !ok {
			return fmt.Errorf("widening: removed operation %s", k)
		}
		if c.Action != b.Action || c.Resource != b.Resource || c.Scope != b.Scope {
			return fmt.Errorf("widening: metadata changed for %s", k)
		}
		need := append([]string(nil), b.Dependencies...)
		have := append([]string(nil), c.Dependencies...)
		sort.Strings(need)
		sort.Strings(have)
		if len(need) != len(have) {
			return fmt.Errorf("widening: dependency multiplicity changed for %s", k)
		}
		for i := range need {
			if need[i] != have[i] {
				return fmt.Errorf("widening: dependency changed for %s", k)
			}
		}
	}
	return nil
}
func unique(in []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, x := range in {
		if x != "" && !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
