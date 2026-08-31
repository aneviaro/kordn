package iamlivecatalog

import "embed"

// embeddedData is the immutable, offline input boundary. Only the selected
// upstream data files are embedded; upstream runtime and module files are not.
//
//go:embed upstream/LICENSE upstream/NOTICE upstream/iamlivecore/map.json upstream/iamlivecore/iam_definition.json upstream/iamlivecore/apis/*/*/api-2.json
var embeddedData embed.FS
