package data

import (
	"strings"
	"testing"

	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
)

func TestVersionFacadeUsesPinnedCatalog(t *testing.T) {
	entries, err := Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || !strings.Contains(AuthorizationDataVersion(), iamlivecatalog.UpstreamCommit) {
		t.Fatalf("catalog version or compatibility entries missing: %d, %q", len(entries), AuthorizationDataVersion())
	}
	var listUsers Entry
	for _, entry := range entries {
		if entry.Service == "iam" && entry.Operation == "ListUsers" {
			listUsers = entry
			break
		}
	}
	if listUsers.Action == "" {
		t.Fatal("catalog facade omitted iam/ListUsers")
	}
	if err := ValidateEntry(listUsers); err != nil {
		t.Fatalf("derived entry is not cross-file consistent: %+v: %v", listUsers, err)
	}
	if GeneratedBytes() != nil || BaselineBytes() != nil {
		t.Fatal("legacy generated datasets remain exposed")
	}
}
