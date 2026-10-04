# SigV4 canonicalization fixtures

These checked-in vectors are transcribed from AWS-published Signature Version
4 examples and API references. `aws-operation-examples.json` is the attributed
catalog fixture used by the production-pipeline integration tests. Each entry
records the pinned model identifier, endpoint/API identity, independent
SigV4 signing identity and Region, wire protocol, canonical request metadata,
and the expected mapping outcome. `api_service` is the catalog endpoint/model
prefix; it must not be replaced by `signing_service` for divergent endpoints.

The current vertical cohort includes:

- IAM Query `ListUsers` — AWS IAM Signature Version 4 signing examples:
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html>
- S3 REST-XML `GetObject` — AWS S3 GetObject API reference:
  <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>
- Lambda REST-JSON `CreateFunction` — AWS Lambda CreateFunction API reference:
  <https://docs.aws.amazon.com/lambda/latest/api/API_CreateFunction.html>
- DynamoDB JSON 1.0 `BatchExecuteStatement` — DynamoDB API reference:
  <https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html>
- API Gateway REST-JSON `GetAccount` — API Gateway API reference:
  <https://docs.aws.amazon.com/apigateway/api-reference/API_GetAccount.html>
- ECR JSON 1.1 `DescribeRepositories` — ECR API reference (the endpoint
  prefix is `api.ecr`, while the SigV4 service is `ecr`):
  <https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_DescribeRepositories.html>
- CloudFront global REST-XML `ListDistributions` — CloudFront API reference:
  <https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html>
- S3 Control account-labelled REST-XML `ListAccessPoints` — S3 Control API
  reference (the endpoint prefix is `s3-control`, while the SigV4 service is
  `s3`):
  <https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_ListAccessPoints.html>

These are provenance fixtures, not a hand-maintained operation allowlist.
Operation and IAM mapping evidence continues to come from the pinned iamlive
catalog. Refresh an entry only from the cited AWS source and the reviewed
pinned model: preserve exact wire/API version, endpoint Region, signing
Region, API service, signing service, protocol, and canonical bytes. Re-run
the focused catalog integration test after a refresh; do not invent hashes or
mark a request compatible merely because its endpoint classifies. The separate
`s3-get-object.json` remains a byte-for-byte AWS canonical-request vector.
