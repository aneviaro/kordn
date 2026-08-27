// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
// Package data contains the bounded, offline AWS Service Authorization snapshot.
package data

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

const (
	SnapshotVersion = "aws-sar-nine-service-2026-08-27"
	SnapshotSource  = "https://servicereference.us-east-1.amazonaws.com/v1/service-list.json; https://servicereference.us-east-1.amazonaws.com/v1/mapping.json"
	SnapshotDate    = "2026-08-27"
)

type Entry struct {
	Service      string   `json:"service"`
	Operation    string   `json:"operation"`
	Action       string   `json:"action"`
	Resource     string   `json:"resource"`
	Scope        string   `json:"scope,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

//go:embed source/*.json
var sourceFiles embed.FS

//go:embed authorization.json
var generated []byte

//go:embed widening-baseline.json
var baseline []byte

type manifest struct {
	SnapshotVersion string `json:"snapshot_version"`
	RetrievalDate   string `json:"retrieval_date"`
	CatalogURL      string `json:"catalog_url"`
	MappingURL      string `json:"mapping_url"`
	Files           []struct {
		Path          string `json:"path"`
		URL           string `json:"url"`
		RetrievalDate string `json:"retrieval_date"`
		SHA256        string `json:"sha256"`
		Format        string `json:"format"`
	} `json:"files"`
}

func sourceManifest() (manifest, error) {
	b, e := sourceFiles.ReadFile("source/manifest.json")
	if e != nil {
		return manifest{}, e
	}
	var m manifest
	if e = json.Unmarshal(b, &m); e != nil {
		return m, e
	}
	if m.SnapshotVersion != SnapshotVersion || m.RetrievalDate != SnapshotDate || m.CatalogURL != "https://servicereference.us-east-1.amazonaws.com/v1/service-list.json" || m.MappingURL != "https://servicereference.us-east-1.amazonaws.com/v1/mapping.json" {
		return m, errors.New("SAR source provenance mismatch")
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		want, ok := officialSourceURLs[f.Path]
		if !ok || seen[f.Path] || f.URL != want || f.RetrievalDate != SnapshotDate || f.Format != "official-aws-service-reference" {
			return m, fmt.Errorf("invalid SAR source provenance for %s", f.Path)
		}
		seen[f.Path] = true
	}
	for path := range officialSourceURLs {
		if !seen[path] {
			return m, fmt.Errorf("source manifest omits %s", path)
		}
	}
	return m, nil
}

var officialSourceURLs = map[string]string{
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

// Entries verifies every vendored official byte sequence on every construction;
// runtime mapping therefore never fetches or trusts a mutable catalog.
func Entries() ([]Entry, error) {
	m, e := sourceManifest()
	if e != nil {
		return nil, e
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		if seen[f.Path] {
			return nil, errors.New("duplicate source manifest path")
		}
		seen[f.Path] = true
		b, e := sourceFiles.ReadFile("source/" + f.Path)
		if e != nil {
			return nil, e
		}
		x := sha256.Sum256(b)
		if hex.EncodeToString(x[:]) != f.SHA256 {
			return nil, fmt.Errorf("SAR source hash mismatch for %s", f.Path)
		}
		if f.RetrievalDate != SnapshotDate || f.Format != "official-aws-service-reference" {
			return nil, errors.New("invalid source provenance")
		}
	}
	for _, p := range []string{"service-list.json", "mapping.json", "ec2.json", "ecs.json", "sts.json", "s3.json", "cloudwatch.json", "logs.json", "iam.json", "lambda.json", "dynamodb.json"} {
		if !seen[p] {
			return nil, fmt.Errorf("source manifest omits %s", p)
		}
	}
	var model struct {
		Version string  `json:"version"`
		Entries []Entry `json:"entries"`
	}
	b, e := sourceFiles.ReadFile("source/operation-model.json")
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(b, &model); e != nil {
		return nil, e
	}
	if model.Version != "supported-operations/v1" || len(model.Entries) == 0 {
		return nil, errors.New("invalid supported operation matrix")
	}
	all := append([]Entry(nil), model.Entries...)
	sort.Slice(all, func(i, j int) bool {
		if all[i].Service != all[j].Service {
			return all[i].Service < all[j].Service
		}
		return all[i].Operation < all[j].Operation
	})
	var document struct {
		SnapshotVersion string  `json:"snapshot_version"`
		RetrievalDate   string  `json:"retrieval_date"`
		SourceManifest  string  `json:"source_manifest_sha256"`
		SupportedMatrix string  `json:"supported_matrix"`
		Entries         []Entry `json:"entries"`
	}
	if e = json.Unmarshal(generated, &document); e != nil {
		return nil, errors.New("invalid generated authorization data")
	}
	manifestBytes, e := sourceFiles.ReadFile("source/manifest.json")
	if e != nil {
		return nil, e
	}
	manifestHash := sha256.Sum256(manifestBytes)
	if document.SnapshotVersion != SnapshotVersion || document.RetrievalDate != SnapshotDate || document.SupportedMatrix != "supported-operations/v1" || document.SourceManifest != hex.EncodeToString(manifestHash[:]) {
		return nil, errors.New("generated authorization provenance mismatch")
	}
	generatedEntries := append([]Entry(nil), document.Entries...)
	sort.Slice(generatedEntries, func(i, j int) bool {
		if generatedEntries[i].Service != generatedEntries[j].Service {
			return generatedEntries[i].Service < generatedEntries[j].Service
		}
		return generatedEntries[i].Operation < generatedEntries[j].Operation
	})
	if !reflect.DeepEqual(all, generatedEntries) {
		return nil, errors.New("generated authorization data disagrees with supported operation matrix")
	}
	return all, nil
}

// ValidateEntry independently checks a selected record against the pinned
// official SAR service document. Generated matrix validation is performed by
// Entries; this second check keeps mapper action/resource agreement explicit.
func ValidateEntry(e Entry) error {
	if e.Service == "" || e.Operation == "" || e.Action == "" || e.Resource == "" {
		return errors.New("incomplete authorization entry")
	}
	parts := strings.Split(e.Action, ":")
	if len(parts) != 2 || parts[0] != e.Service || parts[1] == "" {
		return fmt.Errorf("malformed authorization action %q", e.Action)
	}
	b, err := sourceFiles.ReadFile("source/" + e.Service + ".json")
	if err != nil {
		return fmt.Errorf("SAR service is unavailable: %w", err)
	}
	var service struct {
		Actions []struct {
			Name      string `json:"Name"`
			Resources []struct {
				Name string `json:"Name"`
			}
		} `json:"Actions"`
		Operations []struct {
			Name              string `json:"Name"`
			AuthorizedActions []struct {
				Name    string `json:"Name"`
				Service string `json:"Service"`
			} `json:"AuthorizedActions"`
		} `json:"Operations"`
	}
	if err := json.Unmarshal(b, &service); err != nil {
		return fmt.Errorf("invalid SAR service: %w", err)
	}
	actionIndex := -1
	for i := range service.Actions {
		if service.Actions[i].Name == parts[1] {
			actionIndex = i
			break
		}
	}
	if actionIndex < 0 {
		return fmt.Errorf("SAR action missing: %s", e.Action)
	}
	operationIndex := -1
	for i := range service.Operations {
		if service.Operations[i].Name == e.Operation {
			operationIndex = i
			break
		}
	}
	if operationIndex < 0 {
		return fmt.Errorf("SAR operation missing: %s:%s", e.Service, e.Operation)
	}
	primary := false
	passRole := false
	for _, authorized := range service.Operations[operationIndex].AuthorizedActions {
		if authorized.Service == parts[0] && authorized.Name == parts[1] {
			primary = true
		}
		if authorized.Service == "iam" && authorized.Name == "PassRole" {
			passRole = true
		}
	}
	if !primary {
		return fmt.Errorf("SAR operation/action disagreement: %s:%s", e.Service, e.Operation)
	}
	if e.Resource == "global" {
		if len(service.Actions[actionIndex].Resources) != 0 {
			return fmt.Errorf("global resource metadata disagreement: %s", e.Action)
		}
	} else {
		found := false
		for _, resource := range service.Actions[actionIndex].Resources {
			if resource.Name == e.Resource {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("SAR resource missing: %s/%s", e.Action, e.Resource)
		}
	}
	for _, dependency := range e.Dependencies {
		if dependency != "iam:PassRole" || !passRole {
			return fmt.Errorf("SAR dependency disagreement: %s:%s", e.Service, e.Operation)
		}
	}
	return nil
}

func AuthorizationDataVersion() string {
	b, _ := sourceFiles.ReadFile("source/manifest.json")
	x := sha256.Sum256(b)
	return SnapshotVersion + "+sha256:" + hex.EncodeToString(x[:])
}
func SourceVersion() string  { return SnapshotVersion }
func GeneratedBytes() []byte { return append([]byte(nil), generated...) }
func BaselineBytes() []byte  { return append([]byte(nil), baseline...) }
func BaselineEntries() ([]Entry, error) {
	var x struct {
		Entries []Entry `json:"entries"`
	}
	if e := json.Unmarshal(baseline, &x); e != nil {
		return nil, e
	}
	return x.Entries, nil
}
func CheckNoWidening(base, candidate []Entry) error {
	bm := map[string]Entry{}
	for _, e := range base {
		bm[e.Service+"\x00"+e.Operation] = e
	}
	cm := map[string]Entry{}
	for _, e := range candidate {
		k := e.Service + "\x00" + e.Operation
		if _, ok := cm[k]; ok {
			return fmt.Errorf("widening: duplicate operation %s", k)
		}
		cm[k] = e
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
