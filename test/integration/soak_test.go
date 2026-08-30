package integration

import "testing"

// The release soak and leak assertions intentionally share one test in
// leak_test.go, ensuring the 10,000 requests cannot be replaced by a helper
// benchmark or by a separate synthetic workload.
func TestMixedRequestSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("soak disabled in short mode")
	}
	runActualMixedSoak(t, false)
}

// The race-instrumented soak is a separate gate. It keeps race overhead out of
// the ordinary memory budget and makes the two requested resource contracts
// explicit rather than selecting behavior through ambient test state.
func TestMixedRequestSoakRace(t *testing.T) {
	if testing.Short() {
		t.Skip("soak disabled in short mode")
	}
	runActualMixedSoak(t, true)
}
