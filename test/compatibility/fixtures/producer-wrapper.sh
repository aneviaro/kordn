#!/bin/sh
# Local fake producer: child AWS and non-AWS shims inherit the proxy boundary.
set -eu
: "${HTTP_PROXY:?HTTP_PROXY was not inherited}"
: "${AWS_ACCESS_KEY_ID:?fake AWS access key was not inherited}"
: "${KORDN_AWS_SHIM:?AWS child shim was not configured}"
: "${KORDN_NONAWS_SHIM:?non-AWS child shim was not configured}"
"$KORDN_AWS_SHIM" --sts-get-caller-identity
"$KORDN_NONAWS_SHIM" https://vendor.invalid/api
printf '%s\n' wrapper-environment-ok
