# Third-party notices

Kordn's original code is Apache-2.0. This bootstrap intentionally has no
third-party Go module dependency; `go list -m all` must therefore contain only
`github.com/kordn-ai/kordn`. The `make license-check` gate rejects an
unreviewed module addition.

## iamlive — MIT

I am using the iamlive revision recorded in
`third_party/iamlive/UPSTREAM_COMMIT`. iamlive is MIT-licensed by Ian Mckay.
The exact MIT text is retained at `third_party/iamlive/LICENSE`, and the
upstream dependency notice is retained at `third_party/iamlive/NOTICE`.
