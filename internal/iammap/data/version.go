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
	SnapshotVersion = "iamlive-catalog/v1@" + iamlivecatalog.UpstreamCommit
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
	seen := map[string]bool{}
	out := []Entry{}
	for _, s := range c.Services() {
		for _, o := range s.Operations {
			if len(o.Mappings) == 0 {
				continue
			}
			m := o.Mappings[0]
			parts := strings.SplitN(m.Action, ":", 2)
			if len(parts) != 2 {
				continue
			}
			a, _ := c.Action(m.Action)
			resource := "global"
			scope := "known_global"
			var deps []string
			nonGlobal := []iamlivecatalog.ResourceType{}
			for _, r := range a.Resources {
				if r.Name != "" {
					nonGlobal = append(nonGlobal, r)
				}
				deps = append(deps, r.DependentActions...)
			}
			if len(nonGlobal) > 0 {
				resource = nonGlobal[0].Name
				scope = "exact"
				if len(nonGlobal) > 1 {
					scope = "unresolved"
				}
			}
			x := Entry{Service: strings.ToLower(s.EndpointPrefix), Operation: o.Name, Action: m.Action, Resource: resource, Scope: scope, Dependencies: unique(deps)}
			k := x.Service + "\x00" + x.Operation
			if !seen[k] {
				seen[k] = true
				out = append(out, x)
			}
		}
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

func ValidateEntry(e Entry) error {
	if e.Service == "" || e.Operation == "" || e.Action == "" || e.Resource == "" {
		return errors.New("incomplete catalog entry")
	}
	c, err := iamlivecatalog.Load()
	if err != nil {
		return err
	}
	o, err := c.Operation(e.Service, e.Operation)
	if err != nil {
		return err
	}
	if o.MappingState != iamlivecatalog.EvidenceKnown {
		return fmt.Errorf("catalog operation mapping evidence is %s: %s:%s", o.MappingState, e.Service, e.Operation)
	}
	found := false
	for _, m := range o.Mappings {
		if m.Action == e.Action {
			if m.State != iamlivecatalog.EvidenceKnown {
				return fmt.Errorf("catalog action mapping evidence is %s: %s", m.State, e.Action)
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("catalog operation/action disagreement: %s:%s", e.Service, e.Operation)
	}
	a, err := c.Action(e.Action)
	if err != nil {
		return fmt.Errorf("catalog action unavailable: %w", err)
	}
	if e.Resource == "global" {
		for _, r := range a.Resources {
			if r.Name != "" {
				return fmt.Errorf("global resource metadata disagreement: %s", e.Action)
			}
		}
	} else {
		found = false
		for _, r := range a.Resources {
			if r.Name == e.Resource {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("catalog resource missing: %s/%s", e.Action, e.Resource)
		}
	}
	need := map[string]bool{}
	for _, r := range a.Resources {
		for _, d := range r.DependentActions {
			need[d] = true
		}
	}
	for _, d := range e.Dependencies {
		if !need[d] {
			return fmt.Errorf("catalog dependency disagreement: %s", d)
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
		bm[x.Service+"\x00"+x.Operation] = x
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
		need := map[string]bool{}
		for _, d := range b.Dependencies {
			need[d] = true
		}
		have := map[string]bool{}
		for _, d := range c.Dependencies {
			have[d] = true
		}
		for d := range need {
			if !have[d] {
				return fmt.Errorf("widening: dependency removed for %s", k)
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
