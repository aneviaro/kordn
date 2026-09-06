package iamlivecatalog

import _ "embed"

// embeddedBundle is the immutable, offline input boundary. The selected
// upstream data files are packed into one deterministic archive; upstream
// runtime and module files are not embedded.
//
//go:embed catalog.bundle.gz
var embeddedBundle []byte
