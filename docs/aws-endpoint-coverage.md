# AWS endpoint coverage

## What this matrix proves

The positive endpoint classifier is an activation boundary, not an operation
allowlist. It derives API endpoint prefixes and SigV4 signing names from the
pinned iamlive service-model catalog. A normalized commercial `amazonaws.com`
or `api.aws` host is classified only when its exact DNS shape, partition,
Region, FIPS/dual-stack labels, global scope, and any account label agree with
that catalog-derived identity. Unknown, ambiguous, lookalike, GovCloud/China,
custom, and unsupported data-plane hosts fail closed; non-AWS CONNECT is not
classified and remains an opaque TLS tunnel.

After classification, the production path independently verifies the fake
SigV4 request, identifies the wire protocol and exact model operation, maps all
IAM requirements, evaluates policy, writes audit, and re-signs only an allowed
request. Endpoint classification therefore does **not** mean that every
operation for the family is supported. Operation, resource, and dependency
evidence continues to come from the pinned iamlive catalog; absent,
ambiguous, incomplete, or unresolved evidence is denied locally.

The matrix below covers all 42 Tier 1 model identifiers from the backlog. The
endpoint status is a family-level classifier result. It is not a claim that the
model's operations have individually passed compatibility testing.

## Tier 1 endpoint matrix

`Endpoint Region` is the observed host Region. `Signing Region` is the SigV4
credential-scope Region; global endpoints intentionally have an empty endpoint
Region. `API service` is the model/endpoint prefix and is deliberately separate
from the signing service.

| Model identifier | API service | Endpoint Region | Signing service / Region | Protocol | Endpoint status | Mapping limitation | Excluded data-plane forms |
|---|---|---|---|---|---|---|---|---|
| `accessanalyzer-2019-11-01` | `access-analyzer` | `us-east-1` | `access-analyzer` / `us-east-1` | REST-JSON | classified, regional | pinned operation/resource/dependency evidence required | analyzer data-plane or private/VPC hosts |
| `acm-2015-12-08` | `acm` | `us-east-1` | `acm` / `us-east-1` | JSON 1.1 | classified, regional | catalog mapping only; unresolved resource denies | certificate/private CA data-plane hosts |
| `apigateway-2015-07-09` | `apigateway` | `us-east-1` | `apigateway` / `us-east-1` | REST-JSON | classified, shared with `apigatewayv2` | exact REST route and catalog mapping required | custom domains, invoke URLs, VPC links |
| `apigatewayv2-2018-11-29` | `apigateway` | `us-east-1` | `apigateway` / `us-east-1` | REST-JSON | classified, shared with `apigateway` | wire model/version disambiguation required | API invoke/data-plane URLs |
| `athena-2017-05-18` | `athena` | `us-east-1` | `athena` / `us-east-1` | JSON 1.1 | classified, regional | catalog resource extraction required | query result objects and workgroup data hosts |
| `autoscaling-2011-01-01` | `autoscaling` | `us-east-1` | `autoscaling` / `us-east-1` | Query | classified, regional | catalog mapping and resource evidence required | instance/launch-template data-plane hosts |
| `backup-2018-11-15` | `backup` | `us-east-1` | `backup` / `us-east-1` | REST-JSON | classified, regional | dependent permissions remain conjunctive | backup vault/data-transfer endpoints |
| `bedrock-2023-04-20` | `bedrock` | `us-east-1` | `bedrock` / `us-east-1` | REST-JSON | classified, regional | catalog mapping; model resource must resolve | model invocation/runtime hosts |
| `bedrock-runtime-2023-09-30` | `bedrock-runtime` | `us-east-1` | `bedrock` / `us-east-1` | REST-JSON | classified, regional | separate endpoint/signing identity; operation mapping required | streaming inference and model data-plane forms |
| `budgets-2016-10-20` | `budgets` | global | `budgets` / `us-east-1` | JSON 1.1 | classified, global | global signing scope does not imply wildcard IAM access | billing data exports and private endpoints |
| `ce-2017-10-25` | `ce` | global scope | `ce` / `us-east-1` | JSON 1.1 | classified, global-scope host | catalog resource/dependency evidence required | Cost and Usage data delivery endpoints |
| `cloudfront-2016-08-20` | `cloudfront` | global | `cloudfront` / `us-east-1` | REST-XML | classified, global | catalog mapping only; distribution resource must resolve | distribution edge/resource data-plane hosts |
| `cloudtrail-2013-11-01` | `cloudtrail` | `us-east-1` | `cloudtrail` / `us-east-1` | JSON 1.1 | classified, regional | event/resource mapping remains catalog-dependent | trail delivery and S3 data-plane hosts |
| `cognito-identity-2014-06-30` | `cognito-identity` | `us-east-1` | `cognito-identity` / `us-east-1` | JSON 1.1 | classified, regional | identity/resource extraction must be complete | user identity federation/data-plane URLs |
| `cognito-idp-2016-04-18` | `cognito-idp` | `us-east-1` | `cognito-idp` / `us-east-1` | JSON 1.1 | classified, regional | catalog mapping and pool resource required | hosted UI and user-pool data-plane hosts |
| `config-2014-11-12` | `config` | `us-east-1` | `config` / `us-east-1` | JSON 1.1 | classified, regional | unresolved resource/dependency denies | configuration recorder delivery endpoints |
| `ebs-2019-11-02` | `ebs` | `us-east-1` | `ebs` / `us-east-1` | REST-JSON | classified, regional | catalog mapping/resource evidence required | direct volume/block data-plane paths |
| `ecr-2015-09-21` | `api.ecr` | `us-east-1` | `ecr` / `us-east-1` | JSON 1.1 | classified, regional | API/signing identity is separate; repository mapping must resolve | ECR registry, image-layer, and token data-plane hosts |
| `eks-2017-11-01` | `eks` | `us-east-1` | `eks` / `us-east-1` | REST-JSON | classified, regional | catalog mapping/resource evidence required | Kubernetes API server and cluster endpoints |
| `elasticache-2015-02-02` | `elasticache` | `us-east-1` | `elasticache` / `us-east-1` | Query | classified, regional | catalog mapping and cache resource required | cache node/data-plane endpoints |
| `elasticfilesystem-2015-02-01` | `elasticfilesystem` | `us-east-1` | `elasticfilesystem` / `us-east-1` | REST-JSON | classified, regional | catalog mapping/resource evidence required | mount targets and NFS data-plane hosts |
| `elasticloadbalancing-2012-06-01` | `elasticloadbalancing` | `us-east-1` | `elasticloadbalancing` / `us-east-1` | Query | classified, shared with v2 | exact model evidence and all requirements required | load-balancer resource/data-plane hostnames |
| `elasticloadbalancingv2-2015-12-01` | `elasticloadbalancing` | `us-east-1` | `elasticloadbalancing` / `us-east-1` | Query | classified, shared with classic ELB | exact model evidence and all requirements required | ALB/NLB resource/data-plane hostnames |
| `elasticmapreduce-2009-03-31` | `elasticmapreduce` | `us-east-1` | `elasticmapreduce` / `us-east-1` | JSON 1.1 | classified, regional | cluster/resource mapping remains catalog-dependent | cluster nodes and application data-plane hosts |
| `firehose-2015-08-04` | `firehose` | `us-east-1` | `firehose` / `us-east-1` | JSON 1.1 | classified, regional | stream resource and dependent evidence required | delivery stream destination data-plane |
| `glue-2017-03-31` | `glue` | `us-east-1` | `glue` / `us-east-1` | JSON 1.1 | classified, regional | catalog mapping/resource evidence required | data catalog payload/data-plane services |
| `guardduty-2017-11-28` | `guardduty` | `us-east-1` | `guardduty` / `us-east-1` | REST-JSON | classified, regional | detector/resource mapping must resolve | finding export and member data-plane paths |
| `kinesis-2013-12-02` | `kinesis` | `us-east-1` | `kinesis` / `us-east-1` | JSON 1.1 | classified, regional | stream/shard resource evidence required | enhanced fan-out and stream data-plane hosts |
| `opensearch-2021-01-01` | `es` | `us-east-1` | `es` / `us-east-1` | REST-JSON | classified, regional | API endpoint is not a domain data-plane endpoint | OpenSearch domains, Dashboards, and VPC endpoints |
| `rds-2014-10-31` | `rds` | `us-east-1` | `rds` / `us-east-1` | Query | classified, regional | occurrence-sensitive catalog mapping required | database instance/cluster data-plane hosts |
| `redshift-2012-12-01` | `redshift` | `us-east-1` | `redshift` / `us-east-1` | Query | classified, regional | catalog mapping/resource evidence required | Redshift cluster/data-plane endpoints |
| `s3control-2018-08-20` | `s3-control` | `us-east-1` | `s3` / `us-east-1` | REST-XML | classified, account-labelled | exact 12-digit account label and caller/account evidence required | S3 buckets, access points, Outposts, accelerate, and virtual-hosted data-plane forms |
| `sagemaker-2017-07-24` | `api.sagemaker` | `us-east-1` | `sagemaker` / `us-east-1` | JSON 1.1 | classified, regional | API/signing identity is separate; resource mapping required | runtime, notebook, inference, and VPC endpoint hosts |
| `secretsmanager-2017-10-17` | `secretsmanager` | `us-east-1` | `secretsmanager` / `us-east-1` | JSON 1.1 | classified, regional | secret resource/dependency evidence required | secret-value delivery/data-plane forms |
| `service-quotas-2019-06-24` | `servicequotas` | `us-east-1` | `servicequotas` / `us-east-1` | JSON 1.1 | classified, regional | catalog mapping and service/resource evidence required | service-specific control/data-plane hosts |
| `sesv2-2019-09-27` | `email` | `us-east-1` | `ses` / `us-east-1` | REST-JSON | classified, regional | API/signing identity is separate; recipient/resource mapping required | SMTP, mailbox, and message data-plane endpoints |
| `ssm-2014-11-06` | `ssm` | `us-east-1` | `ssm` / `us-east-1` | JSON 1.1 | classified, regional | document/instance resource and dependencies required | Session Manager channels and managed-node data-plane |
| `sso-2019-06-10` | `portal.sso` | `us-east-1` | `awsssoportal` / `us-east-1` | REST-JSON | classified, regional | unsigned/bearer-only flows remain unsupported; API/signing identity separate | browser portal, bearer-only, and federation data-plane forms |
| `sso-admin-2020-07-20` | `sso` | `us-east-1` | `sso` / `us-east-1` | JSON 1.1 | classified, regional | permission-set/account mapping must resolve | user portal and federation data-plane forms |
| `states-2016-11-23` | `states` | `us-east-1` | `states` / `us-east-1` | JSON 1.0 | classified, regional | state-machine resource and dependent evidence required | execution callbacks and service-integrated data-plane |
| `wafv2-2019-07-29` | `wafv2` | `us-east-1` | `wafv2` / `us-east-1` | JSON 1.1 | classified, regional | scope/resource mapping must resolve | protected application traffic and WAF data-plane |
| `xray-2016-04-12` | `xray` | `us-east-1` | `xray` / `us-east-1` | REST-JSON | classified, regional | trace/group resource mapping required | daemon, segment streaming, and trace data-plane |

## Executable evidence and limits

`internal/awsrequest` tests derive these identities from the pinned catalog and
cover all 42 identifiers, including shared prefixes, divergent signing names,
global scope, and S3 Control account labels. The production-pipeline fixture
cohort in `test/fixtures/sigv4/aws-operation-examples.json` has eight attributed
requests: three allowed catalog mappings (IAM, S3, and DynamoDB), one known
Lambda dependent-evidence denial, and four additional Tier 1 representatives
that demonstrate stable local denial for mapping/resource/operation evidence
(API Gateway, ECR, CloudFront, and S3 Control). The count is an explicit
compatibility-evidence count, not a count of classified endpoint families.

Excluded across the entire matrix are GovCloud/China/ISO partitions, arbitrary
CNAMEs, PrivateLink/VPC endpoints, SigV4a, query-presigned requests, streaming
SigV4 chunks, signed event streams, unsigned or anonymous requests, CRT-only
transports without HTTP/1.1 fallback, and bodies exceeding configured safe
buffering/spooling limits. No denied, ambiguous, identity-mismatched, or
unsupported AWS-looking request is forwarded. Non-AWS HTTPS CONNECT does not
enter this matrix and remains byte-opaque.
