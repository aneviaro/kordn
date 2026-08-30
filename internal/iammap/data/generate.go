//go:build ignore

// Offline generator for the deliberately bounded nine-service snapshot. The
// service files are byte-for-byte AWS Service Reference files. operation-model
// is the reviewed supported-operation matrix: it combines the iamlive
// operation table with SAR action/resource metadata; it is not a replacement
// for either source.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type entry struct {
	Service      string   `json:"service"`
	Operation    string   `json:"operation"`
	Action       string   `json:"action"`
	Resource     string   `json:"resource"`
	Scope        string   `json:"scope,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}
type model struct {
	Version string  `json:"version"`
	Entries []entry `json:"entries"`
}
type manifest struct {
	SnapshotVersion string `json:"snapshot_version"`
	RetrievalDate   string `json:"retrieval_date"`
	CatalogURL      string `json:"catalog_url"`
	MappingURL      string `json:"mapping_url"`
	Files           []file `json:"files"`
}
type file struct {
	Path          string `json:"path"`
	URL           string `json:"url"`
	RetrievalDate string `json:"retrieval_date"`
	SHA256        string `json:"sha256"`
	Format        string `json:"format"`
}
type action struct {
	Name      string
	Resources []struct{ Name string } `json:"Resources"`
}
type operation struct {
	Name              string
	AuthorizedActions []struct{ Name, Service string } `json:"AuthorizedActions"`
}
type service struct {
	Name       string
	Actions    []action
	Operations []operation
}

const snapshot = "aws-sar-nine-service-2026-08-27"
const date = "2026-08-27"

func main() {
	check := flag.Bool("check", false, "verify sources, generated output, and protected widening baseline")
	update := flag.Bool("update-baseline", false, "not permitted by normal generation; baseline updates require review")
	flag.Parse()
	if *update {
		panic("-update-baseline is intentionally unavailable in the normal generator")
	}
	dir := "internal/iammap/data"
	if _, err := os.Stat(filepath.Join(dir, "source")); err != nil {
		dir = "."
	}
	m := mustManifest(dir)
	services := readSources(dir, m)
	modelBytes := mustRead(filepath.Join(dir, "source", "operation-model.json"))
	var mod model
	must(json.Unmarshal(modelBytes, &mod))
	if mod.Version != "supported-operations/v1" {
		panic("unsupported operation model version")
	}
	entries := validateModel(mod.Entries, services)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Service != entries[j].Service {
			return entries[i].Service < entries[j].Service
		}
		return entries[i].Operation < entries[j].Operation
	})
	out := struct {
		SnapshotVersion string  `json:"snapshot_version"`
		RetrievalDate   string  `json:"retrieval_date"`
		SourceManifest  string  `json:"source_manifest_sha256"`
		SupportedMatrix string  `json:"supported_matrix"`
		Entries         []entry `json:"entries"`
	}{snapshot, date, sha(mustRead(filepath.Join(dir, "source", "manifest.json"))), mod.Version, entries}
	generated := canonical(out)
	old := mustRead(filepath.Join(dir, "authorization.json"))
	baseline := mustRead(filepath.Join(dir, "widening-baseline.json"))
	if *check {
		if !bytes.Equal(old, generated) {
			panic("authorization.json is not generated from pinned sources")
		}
		if err := noWidening(baseline, entries); err != nil {
			panic(err)
		}
		fmt.Printf("iammap source-hash: PASS %s\n", sha(mustRead(filepath.Join(dir, "source", "manifest.json"))))
		fmt.Println("iammap catalog/mapping: PASS")
		fmt.Println("iammap generation: PASS")
		fmt.Println("iammap widening baseline: PASS")
		return
	}
	must(os.WriteFile(filepath.Join(dir, "authorization.json"), generated, 0644))
}

func mustManifest(dir string) manifest {
	var m manifest
	must(json.Unmarshal(mustRead(filepath.Join(dir, "source", "manifest.json")), &m))
	if m.SnapshotVersion != snapshot || m.RetrievalDate != date || m.CatalogURL != "https://servicereference.us-east-1.amazonaws.com/v1/service-list.json" || m.MappingURL != "https://servicereference.us-east-1.amazonaws.com/v1/mapping.json" {
		panic("source manifest provenance mismatch")
	}
	urls := map[string]string{
		"service-list.json": "https://servicereference.us-east-1.amazonaws.com/v1/service-list.json",
		"mapping.json":      "https://servicereference.us-east-1.amazonaws.com/v1/mapping.json",
		"ec2.json":          "https://servicereference.us-east-1.amazonaws.com/v1/ec2/ec2.json",
		"ecs.json":          "https://servicereference.us-east-1.amazonaws.com/v1/ecs/ecs.json",
		"sts.json":          "https://servicereference.us-east-1.amazonaws.com/v1/sts/sts.json",
		"s3.json":           "https://servicereference.us-east-1.amazonaws.com/v1/s3/s3.json",
		"cloudwatch.json":   "https://servicereference.us-east-1.amazonaws.com/v1/cloudwatch/cloudwatch.json",
		"logs.json":         "https://servicereference.us-east-1.amazonaws.com/v1/logs/logs.json",
		"iam.json":          "https://servicereference.us-east-1.amazonaws.com/v1/iam/iam.json",
		"lambda.json":       "https://servicereference.us-east-1.amazonaws.com/v1/lambda/lambda.json",
		"dynamodb.json":     "https://servicereference.us-east-1.amazonaws.com/v1/dynamodb/dynamodb.json",
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		want, ok := urls[f.Path]
		if !ok {
			panic("manifest contains unapproved source path: " + f.Path)
		}
		if seen[f.Path] {
			panic("duplicate source manifest path")
		}
		seen[f.Path] = true
		b := mustRead(filepath.Join(dir, "source", f.Path))
		if sha(b) != f.SHA256 {
			panic("source hash mismatch: " + f.Path)
		}
		if f.URL != want || f.RetrievalDate != date || f.Format != "official-aws-service-reference" {
			panic("incomplete source provenance: " + f.Path)
		}
	}
	for p := range urls {
		if !seen[p] {
			panic("manifest omits " + p)
		}
	}
	return m
}
func readSources(dir string, m manifest) map[string]service {
	var catalog []struct{ Service, URL string }
	must(json.Unmarshal(mustRead(filepath.Join(dir, "source", "service-list.json")), &catalog))
	// mapping has a stable nested object, so retain it as generic JSON to avoid
	// coupling to the many SDK-specific keys in the official catalog.
	var raw map[string]map[string]map[string]map[string]struct{ Service, URL string }
	must(json.Unmarshal(mustRead(filepath.Join(dir, "source", "mapping.json")), &raw))
	py := raw["SDK"]["Python"]["Boto3"]
	selected := []string{"ec2", "ecs", "sts", "s3", "cloudwatch", "logs", "iam", "lambda", "dynamodb"}
	out := map[string]service{}
	for _, name := range selected {
		var found bool
		want := "https://servicereference.us-east-1.amazonaws.com/v1/" + name + "/" + name + ".json"
		for _, c := range catalog {
			if c.Service == name && c.URL == want {
				found = true
			}
		}
		if !found {
			panic("catalog does not select " + name)
		}
		if x, ok := py[name]; !ok || x.URL != want || x.Service != name {
			panic("mapping does not select " + name)
		}
		var s service
		must(json.Unmarshal(mustRead(filepath.Join(dir, "source", name+".json")), &s))
		if s.Name != name {
			panic("service name mismatch: " + name)
		}
		out[name] = s
	}
	return out
}
func validateModel(in []entry, services map[string]service) []entry {
	seen := map[string]bool{}
	out := make([]entry, 0, len(in))
	for _, e := range in {
		if e.Service == "" || e.Operation == "" || e.Action == "" || e.Resource == "" {
			panic("incomplete supported operation")
		}
		k := e.Service + "\x00" + e.Operation
		if seen[k] {
			panic("duplicate supported operation: " + k)
		}
		seen[k] = true
		s, ok := services[e.Service]
		if !ok {
			panic("unsupported service: " + e.Service)
		}
		parts := strings.SplitN(e.Action, ":", 2)
		if len(parts) != 2 || parts[0] != e.Service {
			panic("action service mismatch: " + e.Action)
		}
		var a *action
		for i := range s.Actions {
			if s.Actions[i].Name == parts[1] {
				a = &s.Actions[i]
				break
			}
		}
		if a == nil {
			panic("SAR action missing: " + e.Action)
		}
		var o *operation
		for i := range s.Operations {
			if s.Operations[i].Name == e.Operation {
				o = &s.Operations[i]
				break
			}
		}
		if o == nil {
			panic("SAR operation missing: " + e.Service + ":" + e.Operation)
		}
		hasPrimary := false
		for _, aa := range o.AuthorizedActions {
			if aa.Service == parts[0] && aa.Name == parts[1] {
				hasPrimary = true
			}
		}
		if !hasPrimary {
			panic("iamlive operation/action disagreement: " + k)
		}
		if e.Resource == "global" {
			if len(a.Resources) != 0 {
				panic("globalized resource rejected: " + e.Action)
			}
		} else {
			found := false
			for _, r := range a.Resources {
				if r.Name == e.Resource {
					found = true
				}
			}
			if !found {
				panic("SAR resource type missing: " + e.Action + "/" + e.Resource)
			}
		}
		for _, d := range e.Dependencies {
			if d != "iam:PassRole" {
				panic("unknown dependency: " + d)
			}
			ok := false
			for _, aa := range o.AuthorizedActions {
				if aa.Service == "iam" && aa.Name == "PassRole" {
					ok = true
				}
			}
			if !ok {
				panic("dependency disagreement: " + k)
			}
		}
		out = append(out, e)
	}
	return out
}
func noWidening(raw []byte, candidate []entry) error {
	var x struct {
		Entries []entry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &x); err != nil {
		return err
	}
	b := map[string]entry{}
	for _, e := range x.Entries {
		b[e.Service+"\x00"+e.Operation] = e
	}
	c := map[string]entry{}
	for _, e := range candidate {
		k := e.Service + "\x00" + e.Operation
		if _, ok := c[k]; ok {
			return errors.New("widening: duplicate operation")
		}
		c[k] = e
		if _, ok := b[k]; !ok {
			return fmt.Errorf("widening: new operation %s", k)
		}
	}
	for k, e := range b {
		x, ok := c[k]
		if !ok {
			return fmt.Errorf("widening: removed operation %s", k)
		}
		if x.Action != e.Action || x.Resource != e.Resource || x.Scope != e.Scope {
			return fmt.Errorf("widening: metadata changed for %s", k)
		}
		need := map[string]bool{}
		for _, d := range e.Dependencies {
			need[d] = true
		}
		have := map[string]bool{}
		for _, d := range x.Dependencies {
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
func canonical(v any) []byte {
	b, e := json.MarshalIndent(v, "", "  ")
	must(e)
	return append(b, '\n')
}
func mustRead(p string) []byte { b, e := os.ReadFile(p); must(e); return b }
func must(e error) {
	if e != nil {
		panic(e)
	}
}
func sha(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
