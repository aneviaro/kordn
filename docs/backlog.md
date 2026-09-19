# Future improvements

## Make failures actionable and protocol-correct

The unsupported-operation path and startup path currently hide information the
user needs to correct the problem:

- A decode failure is reported to AWS CLI using the fallback operation
  `Unknown`, and the fallback protocol is hardcoded to JSON. Query-protocol
  services such as IAM therefore receive an invalid response format and report
  a confusing XML parsing error.
- `kordn run` currently reduces every startup error to `kordn: startup failed`
  and exit status 78. This gives no indication whether the configuration,
  policy, credentials, audit setup, CA, or listener failed.
- A malformed policy may already have a precise validation error internally,
  but that error is not shown by the runtime startup path. Users need the
  failing policy field/rule and a concrete correction or validation command.

### Desired error behavior

- Preserve the detected or authoritative AWS protocol for every local denial.
  IAM Query failures must be valid XML; JSON-protocol failures must remain
  valid JSON.
- Report the actual operation when it can be safely recovered from the
  authenticated request. Use a distinct, stable reason for an operation that
  is valid AWS syntax but unsupported by the local model versus malformed or
  unknown operation evidence.
- Keep local denials machine-readable and compatible with the producer while
  retaining the audit event ID and stable reason code.
- Report startup failures with a phase and specific safe cause, for example:

  ```text
  kordn run: invalid policy: policy.rule[0].actions: iam:ListUsers is not permitted here
  hint: run kordn policy validate --config ~/.kordn/config.yaml
  ```

- Make policy validation errors actionable by identifying the configuration
  path, rule ID or index, invalid value where safe, and the expected form.
  Validation must remain free of credential or secret material.
- Keep exit statuses stable so scripts can distinguish invalid configuration or
  policy from runtime, credential, and upstream failures.

### Acceptance criteria

- An unsupported IAM operation produces a parseable IAM XML error containing a
  useful stable reason and request/event ID.
- `kordn run` exposes the specific invalid-policy error instead of only
  `startup failed`.
- `kordn policy validate` and `kordn run` identify the same policy validation
  failure and provide a remediation hint.
- Error output never includes access keys, secret keys, session tokens,
  external IDs, or other credential material.

## Support an explicitly guarded allow-by-default policy

The policy language currently requires `policy.default: deny`. A future
improvement should allow `policy.default: allow`, but only when the policy
contains at least one explicit deny rule. An allow-by-default policy with no
deny rules would make every successfully mapped operation broadly permitted and
must be rejected as an invalid policy rather than accepted silently.

### Desired behavior

- Accept `policy.default: allow` only when one or more rules have
  `effect: deny`.
- Reject `policy.default: allow` when there are no deny rules, with an
  actionable validation error explaining that an explicit deny rule is
  required.
- Print a clear warning to stderr during both `kordn policy validate` and
  `kordn run` whenever an allow-by-default policy is accepted.
- Emit the startup warning before launching the child process so the operator
  can see that the run is using a broad default.
- Keep unsupported, malformed, or ambiguous AWS requests fail-closed even
  under an allow-by-default policy.
- Do not include credentials or other secret material in the warning.

### Acceptance criteria

- A valid allow-by-default policy with explicit deny rules validates
  successfully and prints a warning.
- The same policy prints a warning during startup before the child is launched.
- An allow-by-default policy without any deny rule fails validation and cannot
  start a protected run.
- Default-deny policies do not print the allow-by-default warning.

## Give agents skills to work with and control policies

Agents should be able to understand and operate Kordn policies without
requiring an operator to translate every policy task into shell commands. Add a
small, explicit set of agent skills for inspecting, explaining, validating,
and safely proposing or applying policy changes.

### Desired behavior

- Expose read-only skills to list the active policy, show its hash and source,
  explain which rule would match a requested AWS operation, and report recent
  policy denials from the audit log.
- Make the agent familiar with Kordn's documented error responses, including
  stable reason codes, protocol-specific error formats, request or event IDs,
  and actionable remediation guidance, so it can accurately explain failures
  and recommend the appropriate policy or configuration change.
- Use a pinned, expanded iamlive mapping engine as the primary source for
  operation-to-IAM-action and dependent-action mappings, rather than manually
  maintaining mappings for every AWS API. Keep Kordn's decoder, resource
  validation, policy enforcement, and fail-closed boundary around it.
- Automate versioned iamlive metadata updates, provenance checks, and
  regression tests so adding a mapped AWS operation normally requires no
  hand-authored action or dependency table entry.
- Allow an agent to draft policy changes in a separate candidate policy rather
  than modifying the active policy implicitly.
- Validate and display the candidate's actionable errors, effective changes,
  affected operations/resources, and resulting policy hash before activation.
- Require explicit operator authorization for any activation, relaxation, or
  removal of policy controls. An agent must never be able to bypass the active
  policy or grant itself additional permissions.
- Apply an authorized policy change atomically to a new run (or at a clearly
  defined safe reload boundary); an in-flight run must retain the policy and
  hash with which it started.
- Record the requesting agent, authorizing operator, candidate and active
  policy hashes, change summary, timestamp, and result in the audit trail.
- Keep the control surface local to the existing `kordn` process and CLI; do
  not add a network control plane or expose policy mutation through intercepted
  AWS traffic.
- Keep policy contents, audit output, and skill responses free of credentials,
  session tokens, and unrelated secret material.

### Acceptance criteria

- An agent can inspect and explain the active policy using a documented skill
  interface without changing it.
- An agent can identify and explain Kordn error responses, distinguish policy
  denials from malformed requests, unsupported operations, configuration
  failures, and upstream failures, and provide the associated remediation
  guidance without exposing secrets.
- AWS operation and dependent-action mappings are sourced from the pinned
  iamlive integration, and adding a mapped operation does not require a
  hand-authored per-API mapping.
- Incomplete or ambiguous iamlive mapping results fail closed rather than being
  converted into broader permissions.
- A proposed policy change is validated before it can be activated, and the
  preview identifies any newly allowed or denied operations.
- Policy activation fails closed when authorization, validation, or atomic
  replacement fails.
- Unauthorized agents cannot weaken, disable, or replace the active policy.
- Every successful or rejected control attempt is auditable and includes the
  relevant policy hashes and authorization result.

## Make proxy checks easy to extend

Adding a new request-safety check currently risks coupling it directly to the
proxy's main request flow. Introduce a small, typed internal check pipeline so
new checks can be implemented, registered, tested, and audited without
rewriting the core proxy handler.

### Desired behavior

- Define a narrow check interface with typed, read-only request context and an
  explicit result: continue or deny with a stable reason code and safe detail.
- Register built-in checks in one composition point and execute them in a
  deterministic order at clearly documented request stages.
- Let checks declare the evidence they require so they cannot run against
  incomplete endpoint, authentication, decoding, mapping, or policy state.
- Stop processing on the first denial and prevent any denied request from
  reaching the upstream transport.
- Treat check errors, invalid results, and panics as local fail-closed denials,
  with enough audit context to diagnose the failing check without exposing
  credentials or request secrets.
- Provide reusable test helpers and contract tests for ordering, required
  evidence, denial responses, audit records, and fail-closed behavior.
- Keep checks compiled into the existing local Kordn binary. Do not introduce
  runtime-loaded plugins, a daemon, or a network control plane.
- Preserve the HTTPS CONNECT boundary: traffic not positively classified as
  AWS remains byte-opaque end-to-end TLS and must not be exposed to checks that
  inspect AWS request contents.

### Acceptance criteria

- A new built-in proxy check can be added and registered without modifying the
  core request-control flow.
- Check order and required inputs are explicit, deterministic, and covered by
  tests.
- A denial, error, panic, or malformed check result fails closed before any
  upstream forwarding and produces a stable, attributable audit reason.
- Existing endpoint classification, SigV4 verification, decoding, IAM mapping,
  policy, audit, and upstream-signing boundaries retain their current
  behavior.
- Non-AWS CONNECT traffic remains unintercepted and unavailable to
  AWS-request checks.

## Add a background AWS authorization mode

Add an explicitly requested background running mode that keeps Kordn active
while the operator uses normal AWS tooling. In this mode, Kordn should
intercept AWS commands routed through its local proxy boundary and perform
authorization before any request is forwarded to AWS. This must remain a single
local `kordn run` process, not a separate daemon or network control plane.

### Current endpoint boundary

The pinned iamlive catalog contains 426 API model identifiers, but the positive
commercial endpoint classifier currently recognizes only these 16 endpoint
families: `sts`, `iam`, `s3`, `ec2`, `ecs`, `monitoring` (CloudWatch), `logs`,
`lambda`, `dynamodb`, `kms`, `sqs`, `sns`, `events`, `cloudformation`,
`route53`, and `organizations`. The other 410 catalog identifiers are not yet
interceptable through the production AWS path. They are grouped below by
estimated roadmap priority, with identifiers alphabetized within each tier.
This is a prioritization, not an official AWS popularity ranking.

#### Tier 1 — highest priority

`accessanalyzer`, `acm`, `apigateway`, `apigatewayv2`, `athena`, `autoscaling`,
`backup`, `bedrock`, `bedrock-runtime`, `budgets`, `ce`, `cloudfront`,
`cloudtrail`, `cognito-identity`, `cognito-idp`, `config`, `ebs`, `ecr`, `eks`,
`elasticache`, `elasticfilesystem`, `elasticloadbalancing`,
`elasticloadbalancingv2`, `elasticmapreduce`, `firehose`, `glue`, `guardduty`,
`kinesis`, `opensearch`, `rds`, `redshift`, `s3control`, `sagemaker`,
`secretsmanager`, `service-quotas`, `sesv2`, `ssm`, `sso`, `sso-admin`, `states`,
`wafv2`, `xray`

#### Tier 2 — common production services

`account`, `acm-pca`, `amplify`, `appconfig`, `appconfigdata`, `appflow`,
`application-autoscaling`, `appmesh`, `apprunner`, `appstream`, `appsync`,
`auditmanager`, `autoscaling-plans`, `batch`, `bedrock-agent`,
`bedrock-agent-runtime`, `chatbot`, `cloudcontrol`, `codeartifact`, `codebuild`,
`codecommit`, `codeconnections`, `codedeploy`, `codepipeline`,
`compute-optimizer`, `controltower`, `cur`, `databrew`, `dataexchange`,
`datasync`, `datazone`, `dax`, `directconnect`, `dlm`, `dms`, `docdb`, `drs`,
`ds`, `ecr-public`, `eks-auth`, `elasticbeanstalk`, `emr-containers`,
`emr-serverless`, `fis`, `fms`, `fsx`, `globalaccelerator`, `grafana`,
`greengrass`, `greengrassv2`, `health`, `identitystore`, `imagebuilder`,
`inspector2`, `internetmonitor`, `iot`, `iot-data`, `iotevents`, `iotsitewise`,
`kafka`, `kafkaconnect`, `keyspaces`, `lakeformation`, `license-manager`,
`lightsail`, `macie2`, `mediaconvert`, `memorydb`, `mgn`, `mq`, `mwaa`,
`neptune`, `network-firewall`, `networkmanager`, `opensearchserverless`, `osis`,
`outposts`, `personalize`, `pinpoint`, `pipes`, `pricing`, `qbusiness`,
`quicksight`, `ram`, `rbin`, `rds-data`, `redshift-data`, `redshift-serverless`,
`rekognition`, `resiliencehub`, `resource-explorer-2`, `resource-groups`,
`resourcegroupstaggingapi`, `rolesanywhere`, `route53domains`, `route53profiles`,
`route53resolver`, `s3outposts`, `savingsplans`, `scheduler`, `schemas`,
`securityhub`, `securitylake`, `serverlessrepo`, `servicecatalog`,
`servicecatalog-appregistry`, `servicediscovery`, `shield`, `signer`, `snowball`,
`storagegateway`, `support`, `synthetics`, `textract`, `timestream-query`,
`timestream-write`, `transcribe`, `transfer`, `translate`, `trustedadvisor`,
`verifiedpermissions`, `vpc-lattice`, `waf`, `wellarchitected`, `workspaces`

#### Tier 3 — specialized or lower-frequency APIs

The remaining catalog identifiers are lower-priority specialized APIs: `aiops`,
`amp`, `amplifybackend`, `amplifyuibuilder`, `apigatewaymanagementapi`,
`appfabric`, `appintegrations`, `application-insights`, `application-signals`,
`applicationcostprofiler`, `arc-region-switch`, `arc-zonal-shift`, `artifact`,
`AWSMigrationHub`, `b2bi`, `backup-gateway`, `backupsearch`, `bcm-dashboards`,
`bcm-data-exports`, `bcm-pricing-calculator`, `bcm-recommended-actions`,
`bedrock-agentcore`, `bedrock-agentcore-control`, `bedrock-data-automation`,
`bedrock-data-automation-runtime`, `billing`, `billingconductor`, `braket`,
`chime`, `chime-sdk-identity`, `chime-sdk-media-pipelines`,
`chime-sdk-meetings`, `chime-sdk-messaging`, `chime-sdk-voice`, `cleanrooms`,
`cleanroomsml`, `cloud9`, `clouddirectory`, `cloudfront-keyvaluestore`,
`cloudhsm`, `cloudhsmv2`, `cloudsearch`, `cloudsearchdomain`, `cloudtrail-data`,
`codecatalyst`, `codeguru-reviewer`, `codeguru-security`, `codeguruprofiler`,
`codestar-connections`, `codestar-notifications`, `cognito-sync`, `comprehend`,
`comprehendmedical`, `compute-optimizer-automation`, `connect`,
`connect-contact-lens`, `connectcampaigns`, `connectcampaignsv2`, `connectcases`,
`connecthealth`, `connectparticipant`, `controlcatalog`, `cost-optimization-hub`,
`customer-profiles`, `datapipeline`, `deadline`, `detective`, `devicefarm`,
`devops-agent`, `devops-guru`, `directory-service-data`, `discovery`,
`docdb-elastic`, `dsql`, `ec2-instance-connect`, `elementalinference`, `email`,
`entitlement.marketplace`, `entityresolution`, `es`, `eventbridge`, `evs`,
`finspace`, `finspace-data`, `forecast`, `forecastquery`, `frauddetector`,
`freetier`, `gamelift`, `gameliftstreams`, `geo-maps`, `geo-places`, `geo-routes`,
`glacier`, `groundstation`, `healthlake`, `importexport`, `inspector`,
`inspector-scan`, `interconnect`, `invoicing`, `iot-jobs-data`,
`iot-managed-integrations`, `iotdeviceadvisor`, `iotevents-data`, `iotfleetwise`,
`iotsecuretunneling`, `iotthingsgraph`, `iottwinmaker`, `iotwireless`, `ivs`,
`ivs-realtime`, `ivschat`, `kendra`, `kendra-ranking`, `keyspacesstreams`,
`kinesis-video-archived-media`, `kinesis-video-media`,
`kinesis-video-signaling`, `kinesis-video-webrtc-storage`, `kinesisanalytics`,
`kinesisanalyticsv2`, `kinesisvideo`, `launch-wizard`, `lex-models`,
`license-manager-linux-subscriptions`, `license-manager-user-subscriptions`,
`location`, `lookoutequipment`, `m2`, `machinelearning`, `mailmanager`,
`managedblockchain`, `managedblockchain-query`, `marketplace-agreement`,
`marketplace-catalog`, `marketplace-deployment`, `marketplace-discovery`,
`marketplace-reporting`, `marketplacecommerceanalytics`, `mediaconnect`,
`medialive`, `mediapackage`, `mediapackage-vod`, `mediapackagev2`, `mediastore`,
`mediastore-data`, `mediatailor`, `medical-imaging`, `meteringmarketplace`,
`migration-hub-refactor-spaces`, `migrationhub-config`,
`migrationhuborchestrator`, `migrationhubstrategy`, `models.lex.v2`, `mpa`,
`mturk-requester`, `mwaa-serverless`, `neptune-graph`, `neptunedata`,
`networkflowmonitor`, `networkmonitor`, `notifications`, `notificationscontacts`,
`nova-act`, `oam`, `observabilityadmin`, `odb`, `omics`, `panorama`,
`partnercentral-account`, `partnercentral-benefits`, `partnercentral-channel`,
`partnercentral-selling`, `payment-cryptography`, `payment-cryptography-data`,
`pca-connector-ad`, `pca-connector-scep`, `pcs`, `personalize-events`,
`personalize-runtime`, `pi`, `pinpoint-email`, `pinpoint-sms-voice-v2`, `polly`,
`proton`, `qapps`, `qconnect`, `repostspace`, `route53-recovery-cluster`,
`route53-recovery-control-config`, `route53-recovery-readiness`,
`route53globalresolver`, `rtbfabric`, `rum`, `runtime.lex`, `runtime.lex.v2`,
`runtime.sagemaker`, `s3files`, `s3tables`, `s3vectors`, `sagemaker-a2i-runtime`,
`sagemaker-edge`, `sagemaker-featurestore-runtime`, `sagemaker-geospatial`,
`sagemaker-metrics`, `sagemaker-runtime-http2`, `sdb`, `security-ir`,
`securityagent`, `signer-data`, `signin`, `simpledbv2`, `simspaceweaver`,
`sms-voice`, `snow-device-management`, `socialmessaging`, `ssm-contacts`,
`ssm-guiconnect`, `ssm-incidents`, `ssm-quicksetup`, `ssm-sap`, `sso-oidc`,
`streams.dynamodb`, `supplychain`, `support-app`, `sustainability`, `swf`,
`taxsettings`, `timestream-influxdb`, `tnb`, `transcribe-streaming`, `uxc`,
`voice-id`, `waf-regional`, `wickr`, `wisdom`, `workdocs`, `workmail`,
`workmailmessageflow`, `workspaces-instances`, `workspaces-thin-client`,
`workspaces-web`

Expansion must add endpoint rules independently of iamlive operation mappings;
endpoint prefixes alone are not sufficient to safely activate TLS interception.
The endpoint model must account for partition, region, signing service, global
versus regional scope, FIPS, dual-stack, `api.aws`, account-scoped, VPC, and
service-specific endpoint variants without turning non-AWS HTTPS into inspected
traffic.

### Currently unsupported request paths

Even for a recognized endpoint family, Kordn currently rejects operations that
are absent from, ambiguous in, or incompletely mapped by the pinned catalog;
unresolved resources or dependent permissions; GovCloud and China partitions;
uncatalogued endpoint forms such as VPC endpoints and specialized S3 access,
accelerate, or virtual-hosted forms; SigV4a; query-presigned requests;
SigV4 streaming-chunk uploads; signed AWS event streams; unsigned or anonymous
requests; CRT-only transports that cannot fall back to HTTP/1.1; and bodies above
configured safe buffering/spooling limits. Lambda `CreateFunction` is a known
catalog disagreement and currently fails closed because
`lambda:PassCapacityProvider` lacks matching extraction evidence.

### Desired behavior

- Provide a clearly documented command or flag to start and stop the background
  run, with an unambiguous indication when authorization is active.
- Intercept all positively classified AWS requests that use the configured
  local proxy, rather than only the currently supported service subset.
- Authenticate and decode each request, map it to the corresponding AWS
  action and resource, and evaluate the active policy before forwarding it.
- Fail closed when authentication, operation mapping, resource validation, or
  policy evaluation is missing, malformed, ambiguous, or unavailable.
- Keep non-AWS HTTPS CONNECT traffic byte-opaque and pass it through without
  inspection or AWS authorization.
- Preserve the active policy and policy hash for the lifetime of the run, and
  record authorization decisions, denials, and startup/shutdown events in the
  audit trail without logging credentials or session tokens.
- Make child-process, signal, credential, CA, listener, and upstream failures
  visible and actionable while the background run is active.
- Ensure the mode cannot silently continue without Kordn protection after the
  process exits or loses its listener.

### Acceptance criteria

- An operator can start a background `kordn run` and use standard AWS CLI
  commands through it without additional per-command authorization steps.
- Every positively classified AWS command is authorized before upstream
  forwarding, including operations supported by the complete generated model.
- A denied or unverifiable AWS command never reaches AWS and produces a
  protocol-correct local error plus an audit record.
- Non-AWS CONNECT traffic remains end-to-end opaque and is not subject to AWS
  authorization.
- Stopping or losing the background process makes the protected AWS path
  unavailable rather than bypassing authorization.
- Background-mode logs and audit records contain no credentials or other secret
  material.

## Distribute Kordn through Homebrew

Make Kordn installable and maintainable through a Homebrew formula so macOS
users can install and upgrade the CLI using standard Homebrew workflows.

### Desired behavior

- Publish Kordn through an appropriate Homebrew tap or formula location.
- Install the `kordn` executable with the expected version and platform
  support.
- Keep formula metadata, checksums, and release updates aligned with published
  Kordn artifacts.
- Document installation, upgrade, and uninstall commands without requiring a
  separate build environment.

