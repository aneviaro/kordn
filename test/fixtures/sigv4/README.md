# SigV4 canonicalization fixtures

These checked-in vectors are transcribed from AWS-published Signature Version
4 examples and API references. `aws-operation-examples.json` is the mixed
catalog fixture used by the production-pipeline integration tests; every entry
contains source attribution and expected service, operation, and protocol:

- IAM Query `ListUsers` — AWS IAM Signature Version 4 signing examples:
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html>
- S3 REST-XML `GetObject` — AWS S3 GetObject API reference:
  <https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>
- Lambda REST-JSON `CreateFunction` — AWS Lambda CreateFunction API reference:
  <https://docs.aws.amazon.com/lambda/latest/api/API_CreateFunction.html>
- DynamoDB JSON 1.0 `BatchExecuteStatement` — AWS DynamoDB API reference:
  <https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html>

The existing `s3-get-object.json` remains a separate byte-for-byte AWS
canonical-request vector. Published canonical request hashes are retained when
AWS provides them; modeled examples retain their signing inputs and source URLs
without inventing canonical hashes.
