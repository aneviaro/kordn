package iamlivecatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
)

const catalogVersion = "iamlive-catalog/v1@" + UpstreamCommit
const maxJSONBytes = 64 << 20

var (
	defaultOnce    sync.Once
	defaultCatalog *Catalog
	defaultErr     error
)

// Load parses the embedded upstream files once and returns a catalog whose
// exported values are defensive copies. It performs no filesystem or network IO.
func Load() (*Catalog, error) {
	defaultOnce.Do(func() { defaultCatalog, defaultErr = parse() })
	return defaultCatalog, defaultErr
}
func Default() (*Catalog, error) { return Load() }
func Version() string            { return catalogVersion }

func (c *Catalog) Version() string {
	if c == nil {
		return ""
	}
	return c.version
}
func (c *Catalog) SourceHash() string {
	if c == nil {
		return ""
	}
	return c.sourceHash
}
func (c *Catalog) Services() []Service {
	if c == nil {
		return nil
	}
	out := make([]Service, len(c.services))
	for i := range c.services {
		out[i] = c.services[i].Clone()
	}
	return out
}
func (c *Catalog) Service(name string) (Service, error) {
	if c == nil {
		return Service{}, errors.New("catalog unavailable")
	}
	idx := c.serviceIndex[strings.ToLower(strings.TrimSpace(name))]
	if len(idx) != 1 {
		if len(idx) == 0 {
			return Service{}, fmt.Errorf("unknown service %q", name)
		}
		return Service{}, fmt.Errorf("ambiguous service %q", name)
	}
	return c.services[idx[0]].Clone(), nil
}
func (c *Catalog) Operations() []Operation {
	if c == nil {
		return nil
	}
	var out []Operation
	for _, s := range c.services {
		for _, o := range s.Operations {
			out = append(out, o.Clone())
		}
	}
	return out
}
func operationKey(service, operation string) string {
	return strings.ToLower(strings.TrimSpace(service)) + "\x00" + strings.ToLower(strings.TrimSpace(operation))
}
func (c *Catalog) Operation(service, operation string) (Operation, error) {
	if c == nil {
		return Operation{}, errors.New("catalog unavailable")
	}
	x := c.operations[operationKey(service, operation)]
	if len(x) != 1 {
		if len(x) == 0 {
			return Operation{}, fmt.Errorf("unknown operation %s:%s", service, operation)
		}
		return Operation{}, fmt.Errorf("ambiguous operation %s:%s", service, operation)
	}
	return x[0].Clone(), nil
}
func (c *Catalog) Actions() []ActionDefinition {
	if c == nil {
		return nil
	}
	keys := make([]string, 0, len(c.actions))
	for key := range c.actions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out []ActionDefinition
	for _, key := range keys {
		out = append(out, cloneActionDefinitions(c.actions[key])...)
	}
	return out
}

func (c *Catalog) Action(action string) (ActionDefinition, error) {
	if c == nil {
		return ActionDefinition{}, errors.New("catalog unavailable")
	}
	p := strings.SplitN(action, ":", 2)
	if len(p) != 2 {
		return ActionDefinition{}, fmt.Errorf("malformed action %q", action)
	}
	x, ok := c.actions[strings.ToLower(p[0])+"\x00"+strings.ToLower(p[1])]
	if !ok {
		return ActionDefinition{}, fmt.Errorf("unknown action %q", action)
	}
	if len(x) != 1 || x[0].State == EvidenceContradictory {
		return ActionDefinition{}, fmt.Errorf("contradictory action evidence %q", action)
	}
	return x[0].Clone(), nil
}

// parse is intentionally kept separate from the package-level cache so tests
// can exercise construction through the immutable public API.
func parse() (*Catalog, error) {
	licenseBytes, err := readEmbedded("upstream/LICENSE")
	if err != nil {
		return nil, err
	}
	noticeBytes, err := readEmbedded("upstream/NOTICE")
	if err != nil {
		return nil, err
	}
	mapBytes, err := readEmbedded("upstream/iamlivecore/map.json")
	if err != nil {
		return nil, err
	}
	defBytes, err := readEmbedded("upstream/iamlivecore/iam_definition.json")
	if err != nil {
		return nil, err
	}
	if err = validJSON(mapBytes, "map.json"); err != nil {
		return nil, err
	}
	if err = validJSON(defBytes, "iam_definition.json"); err != nil {
		return nil, err
	}
	var rawMap struct {
		Schema         string                  `json:"schema_version"`
		SDK            map[string][]rawMapping `json:"sdk_method_iam_mappings"`
		ServiceSDK     map[string][]string     `json:"service_sdk_mappings"`
		Permissionless []string                `json:"sdk_permissionless_actions"`
	}
	if err = json.Unmarshal(mapBytes, &rawMap); err != nil {
		return nil, fmt.Errorf("map.json: %w", err)
	}
	if rawMap.Schema == "" {
		return nil, errors.New("map.json: missing schema_version")
	}
	var rawDefs []rawService
	if err = json.Unmarshal(defBytes, &rawDefs); err != nil {
		return nil, fmt.Errorf("iam_definition.json: %w", err)
	}
	if len(rawDefs) == 0 {
		return nil, errors.New("iam_definition.json: empty")
	}
	cat := &Catalog{version: catalogVersion, serviceIndex: map[string][]int{}, operations: map[string][]Operation{}, actions: map[string][]ActionDefinition{}, mappings: map[string][]ActionMapping{}, permissionless: map[string]bool{}}
	h := sha256.New()
	for _, item := range []struct {
		name string
		data []byte
	}{{"LICENSE", licenseBytes}, {"NOTICE", noticeBytes}, {"iamlivecore/map.json", mapBytes}, {"iamlivecore/iam_definition.json", defBytes}} {
		h.Write([]byte(item.name))
		h.Write([]byte{0})
		h.Write(item.data)
	}
	apiPaths, err := fs.Glob(embeddedData, "upstream/iamlivecore/apis/*/*/api-2.json")
	if err != nil {
		return nil, err
	}
	sort.Strings(apiPaths)
	if len(apiPaths) == 0 {
		return nil, errors.New("API model set is empty")
	}
	for _, file := range apiPaths {
		b, e := readEmbedded(file)
		if e != nil {
			return nil, e
		}
		h.Write([]byte(file))
		h.Write([]byte{0})
		h.Write(b)
		if e = validJSON(b, file); e != nil {
			return nil, e
		}
		var a rawAPI
		if e = json.Unmarshal(b, &a); e != nil {
			return nil, fmt.Errorf("%s: %w", file, e)
		}
		if e = cat.addAPI(file, a); e != nil {
			return nil, e
		}
	}
	for _, d := range rawDefs {
		if err = cat.addDefinition(d); err != nil {
			return nil, err
		}
	}
	// Resolve SDK aliases only after every API alias has been indexed. A mapping
	// is evidence for an operation even when its action is absent from the SAR
	// dataset; that disagreement remains visible through Action lookup failure.
	sdkToService := map[string][]string{}
	for service, names := range rawMap.ServiceSDK {
		for _, name := range names {
			sdkToService[strings.ToLower(name)] = append(sdkToService[strings.ToLower(name)], service)
		}
	}
	for _, k := range rawMap.Permissionless {
		parts := strings.SplitN(k, ".", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("map.json: malformed permissionless operation key %q", k)
		}
		services := append([]string{parts[0]}, sdkToService[strings.ToLower(parts[0])]...)
		for _, s := range services {
			key := operationKey(s, parts[1])
			if len(cat.operations[key]) > 0 {
				cat.permissionless[key] = true
				break
			}
		}
	}
	for k, vals := range rawMap.SDK {
		parts := strings.SplitN(k, ".", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("map.json: malformed operation key %q", k)
		}
		services := append([]string{parts[0]}, sdkToService[strings.ToLower(parts[0])]...)
		for _, s := range services {
			key := operationKey(s, parts[1])
			if len(cat.operations[key]) > 0 {
				for _, v := range vals {
					m, e := convertMapping(v)
					if e != nil {
						return nil, fmt.Errorf("map.json %s: %w", k, e)
					}
					cat.mappings[key] = append(cat.mappings[key], m)
				}
				break
			}
		}
	}
	// Cross-file disagreements must be evaluated only after the SDK map has
	// populated cat.mappings. Missing IAM definitions remain absent evidence;
	// contradictory definitions remain contradictory and fail closed.
	for key, mappings := range cat.mappings {
		for i := range mappings {
			parts := strings.SplitN(mappings[i].Action, ":", 2)
			if len(parts) != 2 {
				mappings[i].State = EvidenceContradictory
				continue
			}
			defs := cat.actions[strings.ToLower(parts[0])+"\x00"+strings.ToLower(parts[1])]
			switch len(defs) {
			case 0:
				mappings[i].State = EvidenceAbsent
			case 1:
				mappings[i].State = defs[0].State
			default:
				mappings[i].State = EvidenceContradictory
			}
		}
		cat.mappings[key] = mappings
	}
	// Attach mapping slices to operation copies in both indexes.
	for i := range cat.services {
		for j := range cat.services[i].Operations {
			o := &cat.services[i].Operations[j]
			var ms []ActionMapping
			for _, alias := range cat.services[i].Aliases {
				if candidate := cat.mappings[operationKey(alias, o.Name)]; len(candidate) > 0 {
					ms = candidate
					break
				}
			}
			isPermissionless := cat.permissionless[operationKey(cat.services[i].EndpointPrefix, o.Name)]
			if len(ms) > 0 {
				o.Mappings = cloneMappings(ms)
				if isPermissionless {
					o.MappingState = EvidencePermissionless
				} else {
					o.MappingState = EvidenceKnown
					allAbsent := true
					for _, m := range ms {
						if m.State != EvidenceAbsent {
							allAbsent = false
						}
						if m.State == EvidenceContradictory {
							o.MappingState = EvidenceContradictory
						}
					}
					if allAbsent {
						o.MappingState = EvidenceAbsent
					}
				}
			} else if isPermissionless {
				o.MappingState = EvidencePermissionless
			} else {
				o.MappingState = EvidenceAbsent
			}
			cat.replaceOperation(*o)
		}
	}
	cat.sourceHash = hex.EncodeToString(h.Sum(nil))
	return cat, nil
}

type rawAPI struct {
	Metadata   rawMetadata             `json:"metadata"`
	Operations map[string]rawOperation `json:"operations"`
}
type rawMetadata struct {
	APIVersion, EndpointPrefix, Protocol, ServiceFullName, ServiceID, SigningName, TargetPrefix, UID, JSONVersion string
	Protocols                                                                                                     []string `json:"protocols"`
}
type rawOperation struct {
	Name string `json:"name"`
	HTTP struct {
		Method, RequestURI string
		ResponseCode       int `json:"responseCode"`
	} `json:"http"`
	Input struct {
		Shape string `json:"shape"`
	} `json:"input"`
	Output struct {
		Shape string `json:"shape"`
	} `json:"output"`
}
type rawService struct {
	Prefix     string         `json:"prefix"`
	Privileges []rawPrivilege `json:"privileges"`
}
type rawPrivilege struct {
	AccessLevel   string        `json:"access_level"`
	Description   string        `json:"description"`
	Privilege     string        `json:"privilege"`
	ResourceTypes []rawResource `json:"resource_types"`
}
type rawResource struct {
	ConditionKeys    []string `json:"condition_keys"`
	DependentActions []string `json:"dependent_actions"`
	ResourceType     string   `json:"resource_type"`
}
type rawMapping struct {
	Action              string                        `json:"action"`
	ResourceMappings    map[string]rawResourceMapping `json:"resource_mappings"`
	ResourceARNMappings map[string]string             `json:"resourcearn_mappings"`
	Condition           *rawCondition                 `json:"conditions"`
	ConditionMappings   map[string]rawResourceMapping `json:"condition_mappings"`
	ARNOverride         *rawTemplate                  `json:"arn_override"`
	Notice              string                        `json:"notice"`
}
type rawResourceMapping struct {
	Template   string        `json:"template"`
	Conditions *rawCondition `json:"conditions"`
}
type rawTemplate struct {
	Template string `json:"template"`
}
type rawCondition struct {
	LHS, Op, RHS string
	And          *rawCondition `json:"andCondition"`
}

func (c *Catalog) addAPI(file string, a rawAPI) error {
	m := a.Metadata
	if m.EndpointPrefix == "" || m.Protocol == "" || m.UID == "" {
		return fmt.Errorf("%s: incomplete API metadata", file)
	}
	key := m.UID
	if _, ok := c.serviceIndex[strings.ToLower(key)]; ok {
		key = path.Dir(file) + "/" + key
	}
	s := Service{Key: key, ID: m.ServiceID, EndpointPrefix: m.EndpointPrefix, SigningName: m.SigningName, TargetPrefix: m.TargetPrefix, APIVersion: m.APIVersion, Protocol: m.Protocol, Protocols: cloneStrings(m.Protocols)}
	if len(s.Protocols) == 0 {
		s.Protocols = []string{m.Protocol}
	}
	s.Aliases = uniqueStrings([]string{m.EndpointPrefix, m.ServiceID, m.ServiceFullName, key})
	for n, o := range a.Operations {
		name := o.Name
		if name == "" {
			name = n
		}
		if name == "" {
			return fmt.Errorf("%s: operation %q has no name", file, n)
		}
		state := EvidenceKnown
		if name != n {
			// A few historical Smithy models disagree between the operation key
			// and its nested name. Keep the key for lookup and expose the issue.
			state = EvidenceContradictory
		}
		discriminator := o.HTTP.RequestURI
		switch strings.ToLower(m.Protocol) {
		case "query":
			discriminator = n
		case "json":
			discriminator = m.TargetPrefix + "." + n
		}
		s.Operations = append(s.Operations, Operation{Service: m.EndpointPrefix, Name: n, State: state, InputShape: o.Input.Shape, OutputShape: o.Output.Shape, Route: Route{Method: o.HTTP.Method, URI: o.HTTP.RequestURI, ResponseCode: o.HTTP.ResponseCode, QueryDiscriminator: discriminator, TargetPrefix: m.TargetPrefix, JSONVersion: m.JSONVersion}})
	}
	sort.Slice(s.Operations, func(i, j int) bool { return s.Operations[i].Name < s.Operations[j].Name })
	idx := len(c.services)
	c.services = append(c.services, s)
	for _, alias := range s.Aliases {
		c.serviceIndex[strings.ToLower(alias)] = append(c.serviceIndex[strings.ToLower(alias)], idx)
	}
	for _, alias := range s.Aliases {
		for _, o := range s.Operations {
			k := operationKey(alias, o.Name)
			conflict := false
			for _, prior := range c.operations[k] {
				// API model revisions commonly repeat an operation byte-for-byte.
				// Collapse only those equivalent index records; retain distinct
				// definitions and make their lookup fail closed below.
				if !operationEquivalent(prior, o) {
					conflict = true
				}
			}
			if conflict {
				for i := range c.operations[k] {
					c.operations[k][i].State = EvidenceContradictory
				}
				for si := range c.services {
					for sj := range c.services[si].Operations {
						if c.services[si].Operations[sj].Service == o.Service && strings.EqualFold(c.services[si].Operations[sj].Name, o.Name) {
							c.services[si].Operations[sj].State = EvidenceContradictory
						}
					}
				}
				o.State = EvidenceContradictory
				c.operations[k] = append(c.operations[k], o)
				continue
			}
			if len(c.operations[k]) == 0 {
				c.operations[k] = append(c.operations[k], o)
			}
		}
	}
	return nil
}

func operationEquivalent(a, b Operation) bool {
	return a.Service == b.Service && strings.EqualFold(a.Name, b.Name) &&
		a.InputShape == b.InputShape && a.OutputShape == b.OutputShape && a.Route == b.Route
}
func (c *Catalog) replaceOperation(o Operation) {
	// Update only the service and alias buckets that can contain this record.
	// Scanning the complete operation index here makes loading quadratic in the
	// size of the AWS model set.
	serviceIndexes := c.serviceIndex[strings.ToLower(o.Service)]
	for _, si := range serviceIndexes {
		for j := range c.services[si].Operations {
			if c.services[si].Operations[j].Name == o.Name {
				c.services[si].Operations[j] = o
			}
		}
		for _, alias := range c.services[si].Aliases {
			k := operationKey(alias, o.Name)
			values := c.operations[k]
			for i := range values {
				if values[i].Service == o.Service && values[i].Name == o.Name {
					values[i] = o
				}
			}
			c.operations[k] = values
		}
	}
}
func (c *Catalog) addDefinition(d rawService) error {
	if d.Prefix == "" {
		return errors.New("iam_definition.json: empty service prefix")
	}
	for _, p := range d.Privileges {
		if p.Privilege == "" {
			return fmt.Errorf("iam_definition.json: empty privilege in %s", d.Prefix)
		}
		k := strings.ToLower(d.Prefix) + "\x00" + strings.ToLower(p.Privilege)
		state := EvidenceKnown
		if strings.EqualFold(p.AccessLevel, "Unknown") {
			state = EvidenceUndocumented
		}
		a := ActionDefinition{Service: d.Prefix, Name: p.Privilege, AccessLevel: p.AccessLevel, Description: p.Description, State: state}
		seen := map[string]bool{}
		for _, r := range p.ResourceTypes {
			rkey := strings.ToLower(r.ResourceType)
			if seen[rkey] {
				a.State = EvidenceContradictory
			}
			seen[rkey] = true
			a.Resources = append(a.Resources, ResourceType{Name: r.ResourceType, ConditionKeys: cloneStrings(r.ConditionKeys), DependentActions: cloneStrings(r.DependentActions)})
		}
		if prior := c.actions[k]; len(prior) > 0 {
			// IAM definitions contain case-variant duplicate evidence in the
			// pinned snapshot. Retain every record and make lookup fail closed
			// rather than selecting one permission silently.
			a.State = EvidenceContradictory
			for i := range prior {
				prior[i].State = EvidenceContradictory
			}
			c.actions[k] = append(prior, a)
		} else {
			c.actions[k] = []ActionDefinition{a}
		}
	}
	return nil
}
func convertMapping(r rawMapping) (ActionMapping, error) {
	if r.Action == "" {
		return ActionMapping{}, errors.New("mapping has empty action")
	}
	m := ActionMapping{Action: r.Action, State: EvidenceKnown, ResourceARNMappings: map[string]string{}, ConditionMappings: map[string]ResourceMapping{}, Notice: r.Notice}
	for p, x := range r.ResourceMappings {
		// Empty templates are upstream evidence, not parser instructions. Keep
		// them observable so consumers can reject them without dropping the
		// rest of the pinned catalog.
		m.Resources = append(m.Resources, ResourceMapping{Parameter: p, Template: x.Template, Condition: convertCondition(x.Conditions)})
	}
	sort.Slice(m.Resources, func(i, j int) bool { return m.Resources[i].Parameter < m.Resources[j].Parameter })
	for k, v := range r.ResourceARNMappings {
		m.ResourceARNMappings[k] = v
	}
	for k, v := range r.ConditionMappings {
		m.ConditionMappings[k] = ResourceMapping{Parameter: k, Template: v.Template, Condition: convertCondition(v.Conditions)}
	}
	if r.ARNOverride != nil {
		m.ARNOverride = r.ARNOverride.Template
	}
	m.Condition = convertCondition(r.Condition)
	return m, nil
}
func convertCondition(c *rawCondition) *Condition {
	if c == nil {
		return nil
	}
	return &Condition{LHS: c.LHS, Op: c.Op, RHS: c.RHS, And: convertCondition(c.And)}
}
func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range in {
		if x != "" && !seen[strings.ToLower(x)] {
			seen[strings.ToLower(x)] = true
			out = append(out, x)
		}
	}
	return out
}
func readEmbedded(name string) ([]byte, error) {
	b, e := fs.ReadFile(embeddedData, name)
	if e != nil {
		return nil, e
	}
	if len(b) > maxJSONBytes {
		return nil, fmt.Errorf("%s exceeds parser bound", name)
	}
	return b, nil
}
func validJSON(b []byte, name string) error {
	var x interface{}
	d := json.NewDecoder(strings.NewReader(string(b)))
	if err := d.Decode(&x); err != nil {
		return fmt.Errorf("%s: invalid JSON: %w", name, err)
	}
	var extra interface{}
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%s: trailing JSON", name)
		}
		return fmt.Errorf("%s: invalid trailing JSON: %w", name, err)
	}
	return nil
}
