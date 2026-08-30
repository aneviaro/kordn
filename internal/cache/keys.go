package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

func CanonicalKey(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
		b.WriteByte(0)
	}
	return b.String()
}
func HashKey(parts ...string) string {
	s := sha256.Sum256([]byte(CanonicalKey(parts...)))
	return hex.EncodeToString(s[:])
}
func RequirementsKey(reqs interface{}) string {
	parts := []string{"requirements"}
	v := reflect.ValueOf(reqs)
	if v.IsValid() && v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return HashKey(parts...)
		}
		v = v.Elem()
	}
	if !v.IsValid() || v.Kind() != reflect.Slice {
		return HashKey(parts...)
	}
	items := make([]string, 0, v.Len())
	for i := 0; i < v.Len(); i++ {
		r := v.Index(i)
		if r.Kind() == reflect.Pointer {
			if r.IsNil() {
				continue
			}
			r = r.Elem()
		}
		if r.Kind() != reflect.Struct {
			items = append(items, fmt.Sprint(r.Interface()))
			continue
		}
		action, scope, dep := "", "", ""
		if f := r.FieldByName("Action"); f.IsValid() && f.CanInterface() {
			action = fmt.Sprint(f.Interface())
		}
		if f := r.FieldByName("ScopeKind"); f.IsValid() && f.CanInterface() {
			scope = fmt.Sprint(f.Interface())
		}
		if f := r.FieldByName("Dependent"); f.IsValid() && f.CanInterface() {
			dep = fmt.Sprint(f.Interface())
		}
		resources := []string{}
		if f := r.FieldByName("Resources"); f.IsValid() && f.Kind() == reflect.Slice {
			for j := 0; j < f.Len(); j++ {
				if f.Index(j).CanInterface() {
					resources = append(resources, fmt.Sprint(f.Index(j).Interface()))
				}
			}
		}
		sort.Strings(resources)
		// ConditionHint is part of the authorization input. Include both keys
		// and values; omitting it would allow a cached decision to cross a
		// condition boundary. Map iteration is normalized for determinism.
		conditions := ""
		if f := r.FieldByName("ConditionHint"); f.IsValid() && f.Kind() == reflect.Map {
			keys := f.MapKeys()
			sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i].Interface()) < fmt.Sprint(keys[j].Interface()) })
			parts := make([]string, 0, len(keys))
			for _, key := range keys {
				value := f.MapIndex(key)
				vals := []string{}
				if value.IsValid() && value.Kind() == reflect.Slice {
					for j := 0; j < value.Len(); j++ {
						vals = append(vals, fmt.Sprint(value.Index(j).Interface()))
					}
				}
				sort.Strings(vals)
				parts = append(parts, CanonicalKey(fmt.Sprint(key.Interface()), strings.Join(vals, "\x00")))
			}
			conditions = strings.Join(parts, "\x00")
		}
		items = append(items, CanonicalKey(action, scope, dep, strings.Join(resources, "\x00"), conditions))
	}
	sort.Strings(items)
	parts = append(parts, items...)
	return HashKey(parts...)
}

type EndpointKey struct{ RunID, Host, Partition, Region, Service, Account, Operation string }

func (k EndpointKey) String() string {
	return HashKey("endpoint", k.RunID, k.Host, k.Partition, k.Region, k.Service, k.Account, k.Operation)
}

type LeafKey struct{ RunID, Host, Identity string }

func (k LeafKey) String() string { return HashKey("leaf", k.RunID, k.Host, k.Identity) }

type OperationKey struct{ RunID, Service, Operation, MapperVersion, DataVersion string }

func (k OperationKey) String() string {
	return HashKey("operation", k.RunID, k.Service, k.Operation, k.MapperVersion, k.DataVersion)
}

type DecisionKey struct {
	RunID                                   string
	Endpoint                                EndpointKey
	PolicyHash, MapperVersion, Requirements string
}

func (k DecisionKey) String() string {
	return HashKey("decision", k.RunID, k.Endpoint.String(), k.PolicyHash, k.MapperVersion, k.Requirements)
}

type RunCaches struct {
	Endpoints  *LRU[string, any]
	Leaves     *LRU[string, any]
	Operations *LRU[string, any]
	Decisions  *LRU[string, any]
}
type CacheOptions struct{ EndpointCapacity, LeafCapacity, OperationCapacity, DecisionCapacity int }

func NewRunCaches(o CacheOptions) (*RunCaches, error) {
	if o.EndpointCapacity <= 0 {
		o.EndpointCapacity = 256
	}
	if o.LeafCapacity <= 0 {
		o.LeafCapacity = 256
	}
	if o.OperationCapacity <= 0 {
		o.OperationCapacity = 256
	}
	if o.DecisionCapacity <= 0 {
		o.DecisionCapacity = 256
	}
	e, err := NewLRU[string, any](o.EndpointCapacity)
	if err != nil {
		return nil, err
	}
	l, err := NewLRU[string, any](o.LeafCapacity)
	if err != nil {
		return nil, err
	}
	op, err := NewLRU[string, any](o.OperationCapacity)
	if err != nil {
		return nil, err
	}
	d, err := NewLRU[string, any](o.DecisionCapacity)
	if err != nil {
		return nil, err
	}
	return &RunCaches{e, l, op, d}, nil
}
func (c *RunCaches) Clear() {
	if c == nil {
		return
	}
	c.Endpoints.Clear()
	c.Leaves.Clear()
	c.Operations.Clear()
	c.Decisions.Clear()
}
