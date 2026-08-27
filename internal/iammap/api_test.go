package iammap_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/kordn-ai/kordn/internal/iammap"
	"github.com/kordn-ai/kordn/internal/iammap/iamliveadapter"
)

func TestPublicConstructorsExposeNoInjectionHooks(t *testing.T) {
	options := reflect.TypeOf(iammap.MapperOptions{})
	for i := 0; i < options.NumField(); i++ {
		field := options.Field(i)
		if field.PkgPath == "" && (field.Type.Kind() == reflect.Func || strings.Contains(strings.ToLower(field.Name), "hook")) {
			t.Fatalf("public mapper option exposes an injection hook: %s", field.Name)
		}
	}
	adapter := reflect.TypeOf(iamliveadapter.Adapter{})
	for i := 0; i < adapter.NumField(); i++ {
		field := adapter.Field(i)
		if field.PkgPath == "" && field.Type.Kind() == reflect.Func {
			t.Fatalf("public adapter exposes a writable function field: %s", field.Name)
		}
	}

	if zero := (&iamliveadapter.Adapter{}).Version(); zero != "" {
		t.Fatalf("zero adapter advertises provenance: %q", zero)
	}
	a, err := iamliveadapter.New()
	if err != nil {
		t.Fatal(err)
	}
	m, err := iammap.NewMapper()
	if err != nil {
		t.Fatal(err)
	}
	if a.Version() == "" || m.IamLiveVersion() != a.Version() {
		t.Fatalf("public constructors did not use pinned adapter: adapter=%q mapper=%q", a.Version(), m.IamLiveVersion())
	}
}
