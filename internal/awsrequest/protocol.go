package awsrequest

// AWSProtocol identifies one of the supported AWS wire protocols. It is a
// closed enum: unknown protocol strings must fail closed rather than being
// treated as a generic HTTP request.
type AWSProtocol string

const (
	ProtocolJSON10   AWSProtocol = "json1.0"
	ProtocolJSON11   AWSProtocol = "json1.1"
	ProtocolQuery    AWSProtocol = "query"
	ProtocolEC2Query AWSProtocol = "ec2-query"
	ProtocolRESTJSON AWSProtocol = "rest-json"
	ProtocolRESTXML  AWSProtocol = "rest-xml"

	// Descriptive aliases are retained for callers that use the names from the
	// compatibility matrix.
	AWSJSON10   = ProtocolJSON10
	AWSJSON11   = ProtocolJSON11
	AWSQuery    = ProtocolQuery
	AWSEC2Query = ProtocolEC2Query
	AWSRESTJSON = ProtocolRESTJSON
	AWSRESTXML  = ProtocolRESTXML
)

func (p AWSProtocol) Supported() bool {
	switch p {
	case ProtocolJSON10, ProtocolJSON11, ProtocolQuery, ProtocolEC2Query, ProtocolRESTJSON, ProtocolRESTXML:
		return true
	default:
		return false
	}
}

func (p AWSProtocol) Valid() bool { return p.Supported() }

// SigningScheme distinguishes the supported header signature from explicit
// fail-closed signing modes. Query presigning is not an authenticated child
// request in V0.1.
type SigningScheme string

const (
	SigningHeaderV4    SigningScheme = "header-sigv4"
	SigningV4A         SigningScheme = "sigv4a"
	SigningQueryV4     SigningScheme = "query-presign"
	SigningUnsupported SigningScheme = "unsupported"
)

func (s SigningScheme) Supported() bool { return s == SigningHeaderV4 }

// PayloadHashMode retains the distinction between a regular SHA-256 payload,
// an empty payload, unsigned payloads, and modes that cannot safely be
// replayed or re-signed by the V0.1 request path.
type PayloadHashMode string

type PayloadMode = PayloadHashMode

const (
	PayloadHashSHA256      PayloadHashMode = "sha256"
	PayloadHashEmpty       PayloadHashMode = "empty"
	PayloadHashUnsigned    PayloadHashMode = "unsigned-payload"
	PayloadHashStreaming   PayloadHashMode = "streaming"
	PayloadHashEventStream PayloadHashMode = "event-stream"
	PayloadHashUnsupported PayloadHashMode = "unsupported"

	PayloadModeSHA256      = PayloadHashSHA256
	PayloadModeEmpty       = PayloadHashEmpty
	PayloadModeUnsigned    = PayloadHashUnsigned
	PayloadModeStreaming   = PayloadHashStreaming
	PayloadModeEventStream = PayloadHashEventStream
	PayloadModeUnsupported = PayloadHashUnsupported
)

func (m PayloadHashMode) Supported() bool {
	switch m {
	case PayloadHashSHA256, PayloadHashEmpty, PayloadHashUnsigned:
		return true
	default:
		return false
	}
}

func (m PayloadHashMode) Valid() bool { return m.Supported() }
