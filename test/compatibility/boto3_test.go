//go:build compat

// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package compatibility

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestBotoLongLivedClientRotatesCredentials(t *testing.T) {
	requirePinnedExecutable(t, "python")
	requirePinnedPythonModule(t, "boto3")
	requirePinnedPythonModule(t, "botocore")
	if os.Getenv("KORDN_BOTO_LONG_RUN") != "1" {
		if os.Getenv("KORDN_EXTERNAL_REQUIRED") == "1" {
			t.Fatal("boto compatibility job must set KORDN_BOTO_LONG_RUN=1; the required loop is intentionally not run in ordinary local gates")
		}
		t.Skip("set KORDN_BOTO_LONG_RUN=1 to run the >=3 minute external boto3 scenario")
	}
	run := newFixtureRun(t, "GetSessionToken")
	marker := writeTemp(t, "boto-refresh-count", "0\n")
	script := writeTemp(t, "boto-long-lived.py", `import datetime, json, os, time
import boto3
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session
count_file = os.environ["BOTO_REFRESH_MARKER"]
# The child presents Kordn's run-scoped credentials. Kordn's resigner
# independently rotates the upstream generations observed by fakeAWS.
child_generation = (os.environ["AWS_ACCESS_KEY_ID"], os.environ["AWS_SECRET_ACCESS_KEY"], os.environ["AWS_SESSION_TOKEN"])
def refresh():
    try: count = int(open(count_file).read())
    except Exception: count = 0
    count += 1
    open(count_file, "w").write(str(count))
    key, secret, token = child_generation
    return {"access_key": key, "secret_key": secret, "token": token, "expiry_time": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=2)).isoformat()}
creds = RefreshableCredentials.create_from_metadata(metadata=refresh(), refresh_using=refresh, method="fixture")
session = get_session(); session._credentials = creds; session.set_config_variable("region", "us-east-1")
client = session.create_client("sts", endpoint_url=os.environ["KORDN_FIXTURE_ENDPOINT"])
started = time.monotonic()
while time.monotonic() - started < 3 * 60:
    client.get_caller_identity()
    time.sleep(1)
print(json.dumps({"refreshes": int(open(count_file).read()), "elapsed": time.monotonic()-started}))
`)
	cmd := run.command(t, "python3", script)
	cmd.Env = append(cmd.Env, "BOTO_REFRESH_MARKER="+marker, "KORDN_FIXTURE_ENDPOINT="+run.endpoint())
	output, err := runOutput(t, cmd)
	if err != nil {
		t.Fatalf("long-lived boto3 client failed: %v\n%s", err, output)
	}
	var result struct {
		Refreshes int     `json:"refreshes"`
		Elapsed   float64 `json:"elapsed"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output), &result); err != nil {
		t.Fatalf("boto3 refresh summary is not JSON: %v (%s)", err, output)
	}
	if result.Refreshes < 2 || result.Elapsed < 3*60 {
		t.Fatalf("boto3 client did not complete the required 3-minute rotation: %+v", result)
	}
	entries := run.fake.Ledger()
	generations := map[string]bool{}
	for _, entry := range entries {
		generations[entry.AccessKeyID] = true
	}
	if len(generations) < 2 {
		t.Fatalf("fakeAWS did not observe both credential generations: %+v", entries)
	}
	run.assertLedgerAtLeast(t, "GetCallerIdentity", 2)
}
