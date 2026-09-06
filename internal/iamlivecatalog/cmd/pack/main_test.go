package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSourceRejectsParentRepositoryTopLevel(t *testing.T) {
	parent := t.TempDir()
	if output, err := exec.Command("git", "-C", parent, "init").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	source := filepath.Join(parent, "source")
	if err := os.MkdirAll(filepath.Join(source, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := validateSource(source)
	if err == nil || !strings.Contains(err.Error(), "top-level") {
		t.Fatalf("validateSource error = %v, want parent top-level rejection", err)
	}
}
