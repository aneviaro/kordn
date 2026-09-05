package iamlivecatalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// CatalogVersion identifies the parsed catalog implementation and upstream
// gitlink revision. The selected-content digest is exposed by Catalog.SourceHash.
const CatalogVersion = "iamlive-catalog/v2@" + UpstreamCommit
const catalogVersion = CatalogVersion
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

// SchemaVersion returns the neutral catalog schema implementation version.
func SchemaVersion() string { return CatalogSchemaVersion }

// SchemaVersion returns the neutral catalog representation contract used by
// this catalog, independent of the upstream map schema.
func (c *Catalog) SchemaVersion() string {
	if c == nil {
		return ""
	}
	return CatalogSchemaVersion
}

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

// WireServices returns an isolated snapshot containing only the wire evidence
// for every API model. It does not copy operation mappings or IAM definitions.
func (c *Catalog) WireServices() []WireService {
	if c == nil {
		return nil
	}
	out := make([]WireService, len(c.wireServices))
	for i := range c.wireServices {
		out[i] = c.wireServices[i].Clone()
	}
	return out
}

// OperationOccurrences returns every concrete operation occurrence for the
// normalized endpoint prefix and operation name, in catalog construction
// order. Each selected operation is deeply copied before it is returned.
func (c *Catalog) OperationOccurrences(service, operation string) []OperationOccurrence {
	if c == nil {
		return nil
	}
	positions := c.operationOccurrences[operationKey(service, operation)]
	if len(positions) == 0 {
		return nil
	}
	out := make([]OperationOccurrence, len(positions))
	for i, position := range positions {
		s := c.services[position.serviceIndex]
		out[i] = OperationOccurrence{
			Service: WireService{
				EndpointPrefix: s.EndpointPrefix,
				APIVersion:     s.APIVersion,
				TargetPrefix:   s.TargetPrefix,
				Protocols:      cloneStrings(s.Protocols),
				Protocol:       s.Protocol,
			},
			Operation: s.Operations[position.operationIndex].Clone(),
		}
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
	return x[0].operation.Clone(), nil
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
	cat := &Catalog{version: catalogVersion, serviceIndex: map[string][]int{}, operations: map[string][]indexedOperation{}, actions: map[string][]ActionDefinition{}, mappings: map[string][]ActionMapping{}, permissionless: map[string]bool{}}
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
		a, e := decodeAPI(file, b)
		if e != nil {
			return nil, e
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
			cat.replaceOperation(i, *o)
		}
	}
	cat.buildWireIndexes()
	cat.sourceHash = hex.EncodeToString(h.Sum(nil))
	return cat, nil
}

func (c *Catalog) buildWireIndexes() {
	c.wireServices = make([]WireService, len(c.services))
	counts := make(map[string]int, len(c.operations))
	for _, service := range c.services {
		for _, operation := range service.Operations {
			counts[operationKey(service.EndpointPrefix, operation.Name)]++
		}
	}
	c.operationOccurrences = make(map[string][]operationPosition, len(counts))
	for key, count := range counts {
		c.operationOccurrences[key] = make([]operationPosition, 0, count)
	}
	for serviceIndex, service := range c.services {
		wire := WireService{
			EndpointPrefix: service.EndpointPrefix,
			APIVersion:     service.APIVersion,
			TargetPrefix:   service.TargetPrefix,
			Protocols:      cloneStrings(service.Protocols),
			Protocol:       service.Protocol,
			Operations:     make([]WireOperation, len(service.Operations)),
		}
		for operationIndex, operation := range service.Operations {
			wire.Operations[operationIndex] = WireOperation{
				Name:          operation.Name,
				State:         operation.State,
				Route:         operation.Route,
				QueryBindings: cloneQueryBindings(operation.QueryBindings),
			}
			key := operationKey(service.EndpointPrefix, operation.Name)
			c.operationOccurrences[key] = append(c.operationOccurrences[key], operationPosition{
				serviceIndex:   serviceIndex,
				operationIndex: operationIndex,
			})
		}
		c.wireServices[serviceIndex] = wire
	}
}

type rawAPI struct {
	Metadata   rawMetadata             `json:"metadata"`
	Operations map[string]rawOperation `json:"operations"`
	Shapes     map[string]rawShape     `json:"shapes"`
}
type rawShape struct {
	Type     string               `json:"type"`
	Required []string             `json:"required"`
	Members  map[string]rawMember `json:"members"`
}
type rawMember struct {
	Shape        string  `json:"shape"`
	Location     string  `json:"location"`
	LocationName *string `json:"locationName"`
}

// decodeAPI is the production API-model construction boundary. Strict JSON
// validation must happen before unmarshalling because encoding/json otherwise
// silently overwrites duplicate object members in maps.
func decodeAPI(file string, b []byte) (rawAPI, error) {
	if err := validJSON(b, file); err != nil {
		return rawAPI{}, err
	}
	var a rawAPI
	if err := json.Unmarshal(b, &a); err != nil {
		return rawAPI{}, fmt.Errorf("%s: %w", file, err)
	}
	if err := validateAPI(file, a); err != nil {
		return rawAPI{}, err
	}
	return a, nil
}

func validateAPI(file string, a rawAPI) error {
	for operation, raw := range a.Operations {
		shapeName := raw.Input.Shape
		if shapeName == "" {
			continue
		}
		shape, ok := a.Shapes[shapeName]
		if !ok || shape.Type != "structure" {
			return fmt.Errorf("%s: operation %q input shape %q is missing or malformed", file, operation, shapeName)
		}
		required := map[string]bool{}
		for _, member := range shape.Required {
			if member == "" {
				return fmt.Errorf("%s: operation %q input shape %q has empty required member", file, operation, shapeName)
			}
			if required[member] {
				return fmt.Errorf("%s: operation %q input shape %q has duplicate required member %q", file, operation, shapeName, member)
			}
			if _, ok := shape.Members[member]; !ok {
				return fmt.Errorf("%s: operation %q input shape %q has absent required member %q", file, operation, shapeName, member)
			}
			required[member] = true
		}
		queryNames := map[string]string{}
		for memberName, member := range shape.Members {
			if memberName == "" || member.Shape == "" || a.Shapes[member.Shape].Type == "" {
				return fmt.Errorf("%s: operation %q input shape %q has malformed member %q", file, operation, shapeName, memberName)
			}
			if member.Location != "querystring" {
				continue
			}
			if member.LocationName != nil && strings.TrimSpace(*member.LocationName) == "" {
				return fmt.Errorf("%s: operation %q input shape %q member %q has empty query locationName", file, operation, shapeName, memberName)
			}
			locationName := memberName
			if member.LocationName != nil {
				locationName = *member.LocationName
			}
			if prior, ok := queryNames[locationName]; ok {
				return fmt.Errorf("%s: operation %q input shape %q has duplicate query locationName %q for members %q and %q", file, operation, shapeName, locationName, prior, memberName)
			}
			queryNames[locationName] = memberName
		}
	}
	return nil
}

func queryBindings(a rawAPI, operation, file string, shapeName string) ([]QueryBinding, error) {
	if shapeName == "" {
		return nil, nil
	}
	shape, ok := a.Shapes[shapeName]
	if !ok {
		return nil, fmt.Errorf("%s: operation %q input shape %q is missing", file, operation, shapeName)
	}
	required := map[string]bool{}
	for _, member := range shape.Required {
		required[member] = true
	}
	var out []QueryBinding
	for memberName, member := range shape.Members {
		if member.Location != "querystring" {
			continue
		}
		locationName := memberName
		if member.LocationName != nil {
			locationName = *member.LocationName
		}
		out = append(out, QueryBinding{Member: memberName, LocationName: locationName, Required: required[memberName]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LocationName < out[j].LocationName })
	return out, nil
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
		bindings, err := queryBindings(a, n, file, o.Input.Shape)
		if err != nil {
			return err
		}
		discriminator := o.HTTP.RequestURI
		switch strings.ToLower(m.Protocol) {
		case "query":
			discriminator = n
		case "json":
			discriminator = m.TargetPrefix + "." + n
		}
		s.Operations = append(s.Operations, Operation{Service: m.EndpointPrefix, Name: n, State: state, InputShape: o.Input.Shape, OutputShape: o.Output.Shape, QueryBindings: bindings, Route: Route{Method: o.HTTP.Method, URI: o.HTTP.RequestURI, ResponseCode: o.HTTP.ResponseCode, QueryDiscriminator: discriminator, TargetPrefix: m.TargetPrefix, JSONVersion: m.JSONVersion}})
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
			equivalent := false
			for _, prior := range c.operations[k] {
				if prior.modelKey == key && operationEquivalent(prior.operation, o) {
					equivalent = true
					break
				}
			}
			if !equivalent {
				c.operations[k] = append(c.operations[k], indexedOperation{modelKey: key, operation: o})
			}
		}
	}
	return nil
}

func operationEquivalent(a, b Operation) bool {
	return a.Service == b.Service && strings.EqualFold(a.Name, b.Name) &&
		a.InputShape == b.InputShape && a.OutputShape == b.OutputShape && a.Route == b.Route &&
		reflect.DeepEqual(a.QueryBindings, b.QueryBindings)
}
func (c *Catalog) replaceOperation(serviceIndex int, o Operation) {
	// Update only the selected service model and its alias buckets. Matching by
	// endpoint and operation alone would overwrite API-version variants.
	if serviceIndex < 0 || serviceIndex >= len(c.services) {
		return
	}
	service := c.services[serviceIndex]
	for _, alias := range service.Aliases {
		k := operationKey(alias, o.Name)
		values := c.operations[k]
		for i := range values {
			if values[i].modelKey == service.Key && operationEquivalent(values[i].operation, o) {
				values[i].operation = o
			}
		}
		c.operations[k] = values
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
	if len(b) > maxJSONBytes {
		return fmt.Errorf("%s exceeds parser bound", name)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	state := jsonValidationState{maxDepth: 256}
	if err := state.value(d, "$", 0); err != nil {
		return fmt.Errorf("%s: invalid JSON: %w", name, err)
	}
	var extra json.Token
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%s: trailing JSON", name)
		}
		return fmt.Errorf("%s: invalid trailing JSON: %w", name, err)
	}
	return nil
}

type jsonValidationState struct {
	tokens   int
	maxDepth int
}

// value validates JSON without materializing it. In particular, object keys
// are checked before any map unmarshal can overwrite an earlier key.
func (s *jsonValidationState) value(d *json.Decoder, jsonPath string, depth int) error {
	s.tokens++
	if s.tokens > maxJSONBytes || depth > s.maxDepth {
		return errors.New("JSON validation limit exceeded")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch token := t.(type) {
	case json.Delim:
		switch token {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate object key %q at %s", key, jsonPath)
				}
				seen[key] = true
				if err := s.value(d, jsonPath+"."+jsonPathName(key), depth+1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("malformed JSON object")
			}
		case '[':
			for i := 0; d.More(); i++ {
				if err := s.value(d, fmt.Sprintf("%s[%d]", jsonPath, i), depth+1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("malformed JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	return nil
}

func jsonPathName(key string) string {
	if key == "" {
		return `""`
	}
	for _, r := range key {
		if r != '_' && r != '-' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return "[" + strconv.Quote(key) + "]"
		}
	}
	return key
}
