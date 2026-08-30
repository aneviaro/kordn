package fakeaws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Failure is deterministic, per-operation fault injection. A failure is
// consumed once, so retries made by a producer are observable in the ledger.
type Failure struct {
	Latency        time.Duration
	Disconnect     bool
	Status         int
	RetryAfter     string
	Code           string
	RequestID      string
	Body           []byte
	Streaming      bool
	StreamingChunk int
	StreamingDelay time.Duration
}

type FailureScript struct {
	mu          sync.Mutex
	byOperation map[string][]Failure
}

func NewFailureScript() *FailureScript {
	return &FailureScript{byOperation: make(map[string][]Failure)}
}
func (s *FailureScript) Set(operation string, failures ...Failure) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byOperation[operation] = append([]Failure(nil), failures...)
}
func (s *FailureScript) Reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byOperation = make(map[string][]Failure)
}

// Take consumes the next scripted failure. It is exported so protocol tests
// can assert retry accounting without reaching into server internals.
func (s *FailureScript) Take(operation string) (Failure, bool) { return s.next(operation) }
func (s *FailureScript) next(operation string) (Failure, bool) {
	if s == nil {
		return Failure{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.byOperation[operation]
	if len(list) == 0 {
		return Failure{}, false
	}
	f := list[0]
	s.byOperation[operation] = list[1:]
	f.Body = append([]byte(nil), f.Body...)
	return f, true
}

// RequestRecord is the complete non-secret upstream ledger entry. It has no
// request body, credential, Authorization value, or proxy header value.
type RequestRecord struct {
	Method      string
	Host        string
	Path        string
	Query       string
	HeaderNames []string
	// Headers and BodyHash are aliases for consumers using shorter names.
	Headers     []string
	BodySHA256  string
	BodyHash    string
	Action      string
	Protocol    Protocol
	RequestID   string
	StartedAt   time.Time
	CompletedAt time.Time
	Duration    time.Duration
	Status      int
}

func (r RequestRecord) deepCopy() RequestRecord {
	r.HeaderNames = append([]string(nil), r.HeaderNames...)
	return r
}

// Server is a deterministic local upstream. Credentials are known fixture
// values and are never returned in an error or response body.
type Server struct {
	*httptest.Server
	Credentials aws.Credentials
	Host        string
	Service     string
	Region      string
	Clock       func() time.Time

	mu       sync.Mutex
	requests int
	last     *http.Request

	ledgerMu       sync.Mutex
	ledger         []RequestRecord
	ledgerCapacity int
	maxBodyBytes   int64
	failures       *FailureScript
	state          *State
	modeledHandler http.Handler
	responses      map[string]Response
	responseMu     sync.RWMutex
	requestSeq     uint64
}

// Config controls a local-only fake AWS endpoint.
type Config struct {
	Credentials aws.Credentials
	// Host, Service, and Region define the independent signing contract.
	// Empty values use the normal STS fixture defaults.
	Host           string
	Service        string
	Region         string
	Clock          func() time.Time
	LedgerCapacity int
	MaxBodyBytes   int64
	Failures       *FailureScript
	State          *State
	Handler        http.Handler
	Responses      map[string]Response
}

// NewWithConfig creates a TLS fake endpoint. It never dials the network and
// its certificate is trusted only through Client().Transport in tests.
func NewServer(config Config) *Server { return NewWithConfig(config) }

func NewWithConfig(config Config) *Server {
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.LedgerCapacity <= 0 {
		config.LedgerCapacity = 1024
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 8 << 20
	}
	if config.Failures == nil {
		config.Failures = NewFailureScript()
	}
	if config.State == nil {
		config.State = NewState()
	}
	if config.Host == "" {
		config.Host = Host
	}
	if config.Service == "" {
		config.Service = Service
	}
	if config.Region == "" {
		config.Region = Region
	}
	s := &Server{Credentials: config.Credentials, Host: config.Host, Service: config.Service, Region: config.Region, Clock: config.Clock, ledgerCapacity: config.LedgerCapacity, maxBodyBytes: config.MaxBodyBytes, failures: config.Failures, state: config.State, modeledHandler: config.Handler, responses: cloneResponses(config.Responses)}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(s.handle))
	s.Server.StartTLS()
	return s
}

// Ledger returns bounded, deep-copied records in arrival order.
func (s *Server) Ledger() []RequestRecord {
	if s == nil {
		return nil
	}
	s.ledgerMu.Lock()
	defer s.ledgerMu.Unlock()
	out := make([]RequestRecord, len(s.ledger))
	for i := range s.ledger {
		out[i] = s.ledger[i].deepCopy()
	}
	return out
}
func (s *Server) Snapshot() []RequestRecord      { return s.Ledger() }
func (s *Server) RequestLedger() []RequestRecord { return s.Ledger() }
func (s *Server) SetResponse(operation string, response Response) {
	if s == nil {
		return
	}
	response.Body = append([]byte(nil), response.Body...)
	response.Headers = response.Headers.Clone()
	s.responseMu.Lock()
	defer s.responseMu.Unlock()
	if s.responses == nil {
		s.responses = make(map[string]Response)
	}
	s.responses[operation] = response
}
func (s *Server) Reset() {
	if s == nil {
		return
	}
	s.ledgerMu.Lock()
	s.ledger = nil
	s.ledgerMu.Unlock()
	if s.failures != nil {
		s.failures.Reset()
	}
	if s.state != nil {
		s.state.Reset()
	}
}
func (s *Server) Failures() *FailureScript {
	if s == nil {
		return nil
	}
	return s.failures
}
func (s *Server) State() *State {
	if s == nil {
		return nil
	}
	return s.state
}

func cloneResponses(input map[string]Response) map[string]Response {
	result := make(map[string]Response, len(input))
	for key, response := range input {
		response.Body = append([]byte(nil), response.Body...)
		response.Headers = response.Headers.Clone()
		result[key] = response
	}
	return result
}

// dynamoDBResponse is a deliberately small stateful DynamoDB JSON fixture.
// It models only the fields needed by the A-read/B-derived-write scenario; the
// signature, endpoint, and protocol checks remain in the common server path.
func (s *Server) dynamoDBResponse(req *http.Request, body []byte, requestID string) (Response, bool) {
	var input struct {
		Key map[string]struct {
			S string `json:"S"`
		} `json:"Key"`
		Item map[string]struct {
			S string `json:"S"`
		} `json:"Item"`
	}
	if err := json.Unmarshal(body, &input); err != nil {
		return Response{}, false
	}
	id := ""
	if value, ok := input.Key["id"]; ok {
		id = value.S
	}
	switch actionFromRequest(req, body) {
	case "GetItem":
		resource, _ := s.state.Read(id)
		item := map[string]map[string]string{"id": {"S": id}}
		if resource.ID != "" {
			item["value"] = map[string]string{"S": resource.Value}
		}
		return JSONResponse(JSON10, http.StatusOK, requestID, map[string]any{"Item": item}), true
	case "PutItem":
		value := input.Item["value"].S
		if id == "" {
			id = input.Item["id"].S
		}
		if id == "" || value == "" {
			return Response{}, false
		}
		s.state.Put(id, value)
		return JSONResponse(JSON10, http.StatusOK, requestID, map[string]any{}), true
	case "DeleteItem":
		if id != "" {
			s.state.Delete(id)
		}
		return JSONResponse(JSON10, http.StatusOK, requestID, map[string]any{}), true
	default:
		return Response{}, false
	}
}
func (s *Server) record(req *http.Request, body []byte, started time.Time, status int, requestID string) {
	if s == nil || req == nil {
		return
	}
	names := make([]string, 0, len(req.Header))
	for n := range req.Header {
		names = append(names, strings.ToLower(n))
	}
	sort.Strings(names)
	query := safeQuery(req.URL.Query())
	sum := sha256.Sum256(body)
	done := s.Clock().UTC()
	bodyHash := hex.EncodeToString(sum[:])
	r := RequestRecord{Method: req.Method, Host: req.Host, Path: req.URL.EscapedPath(), Query: query, HeaderNames: names, Headers: append([]string(nil), names...), BodySHA256: bodyHash, BodyHash: bodyHash, Action: actionFromRequest(req, body), Protocol: protocolFromRequest(req, body), RequestID: requestID, StartedAt: started, CompletedAt: done, Duration: done.Sub(started), Status: status}
	s.ledgerMu.Lock()
	defer s.ledgerMu.Unlock()
	if len(s.ledger) >= s.ledgerCapacity {
		copy(s.ledger, s.ledger[1:])
		s.ledger = s.ledger[:len(s.ledger)-1]
	}
	s.ledger = append(s.ledger, r)
}
func safeQuery(values url.Values) string {
	for key := range values {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "credential") || strings.Contains(lower, "signature") || strings.Contains(lower, "security-token") || strings.Contains(lower, "authorization") {
			delete(values, key)
		}
	}
	return values.Encode()
}

// ServeFixture writes an AWS-shaped response while retaining the independent
// signature check in sigv4.go. This method is useful to custom handlers.
func (s *Server) writeModeled(w http.ResponseWriter, req *http.Request, body []byte, requestID string) int {
	if s.modeledHandler != nil {
		s.modeledHandler.ServeHTTP(w, req)
		return 0
	}
	protocol := protocolFromRequest(req, body)
	s.responseMu.RLock()
	response, ok := s.responses[actionFromRequest(req, body)]
	s.responseMu.RUnlock()
	if !ok && s.Service == "dynamodb" {
		response, ok = s.dynamoDBResponse(req, body, requestID)
	}
	if !ok {
		response = Response{Status: http.StatusOK, Headers: http.Header{"Content-Type": {"application/json"}, "X-Amzn-Requestid": {requestID}}, Body: []byte(`{"ok":true}`)}
	}
	if response.Status == 0 {
		response.Status = http.StatusOK
	}
	if response.Headers == nil {
		response.Headers = make(http.Header)
	}
	response.Headers.Set("X-Amzn-Requestid", requestID)
	if protocol == JSON10 {
		response.Headers.Set("Content-Type", "application/x-amz-json-1.0")
	}
	for k, v := range response.Headers {
		w.Header()[k] = append([]string(nil), v...)
	}
	w.WriteHeader(response.Status)
	_, _ = w.Write(response.Body)
	return response.Status
}
