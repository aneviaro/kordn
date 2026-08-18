# SigV4 canonicalization fixtures

These bootstrap vectors are transcribed from AWS's published Signature
Version 4 examples. They are inputs for the future verifier; Task 1 does not
implement signing or forwarding.

- `iam-list-users.json` — AWS IAM header-signed `ListUsers` example:
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html>
- `s3-get-object.json` — AWS S3 header-based `GetObject` example:
  <https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html>

The expected canonical request hashes are SHA-256 values of the canonical
request strings recorded in each JSON file. The source URL and example name
are retained so future changes can verify against the published vectors rather
than silently creating local conventions.
