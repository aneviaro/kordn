package app

import "context"

// Run is deliberately a startup-failure default for library callers. The
// shipped command wires the protected composition root in cmd/kordn; keeping
// that dependency out of this package avoids an import cycle with runtime
// package tests and prevents a public runner hook from becoming a bypass.
func Run(context.Context, RunInvocation) int { return 78 }
