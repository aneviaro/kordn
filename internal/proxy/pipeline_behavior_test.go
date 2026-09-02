package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkcredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/kordn-ai/kordn/internal/awserror"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/cache"
	"github.com/kordn-ai/kordn/internal/observe"
	"github.com/kordn-ai/kordn/internal/policy"
	"github.com/kordn-ai/kordn/internal/sigv4"
)

func pipelineTestEndpoint() awsrequest.AWSEndpoint {
	return awsrequest.AWSEndpoint{Partition: "aws", Host: "sts.amazonaws.com", Service: "sts", Region: "us-east-1", Scope: awsrequest.ScopeRegional}
}

func pipelineDecodedRequest(operation, account, region, partition string) *awsrequest.DecodedAWSRequest {
	return &awsrequest.DecodedAWSRequest{
		Partition: partition, EndpointHost: "sts.amazonaws.com", Service: "sts", Region: region,
		CallerAccountID: account, Protocol: awsrequest.ProtocolJSON11, Operation: operation,
		Method: http.MethodPost, CanonicalPath: "/", Parameters: map[string]awsrequest.Value{},
		PayloadHashMode: awsrequest.PayloadHashEmpty,
	}
}

func pipelineMapping(operation, resource string) *awsrequest.MappingResult {
	return &awsrequest.MappingResult{
		Service: "sts", Operation: operation, MapperVersion: "mapper-v1", Confidence: awsrequest.ConfidenceHigh,
		Requirements: []awsrequest.IAMRequirement{{Action: "sts:" + operation, Resources: []string{resource}, ScopeKind: awsrequest.ScopeExact}},
	}
}

type countingPipelineMapper struct {
	mapping *awsrequest.MappingResult
	calls   atomic.Int32
}

func (m *countingPipelineMapper) Map(context.Context, *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
	m.calls.Add(1)
	return m.mapping, nil
}

type mutatingPipelinePolicy struct {
	calls   atomic.Int32
	mapping *awsrequest.MappingResult
}

func (p *mutatingPipelinePolicy) Evaluate(context.Context, policy.DecisionInput) policy.Decision {
	p.calls.Add(1)
	if p.mapping != nil {
		p.mapping.Requirements[0].Resources[0] = "changed-after-cache-insert"
	}
	return policy.Decision{Result: policy.DecisionDeny, ReasonCode: "policy_no_matching_allow", MatchedRuleIDs: []string{"rule-1"}}
}

func TestRouteConflictDeniesWithUnknownOperationAndDoesNotForward(t *testing.T) {
	endpoint, err := awsrequest.DefaultEndpointClassifier.Classify("ecs.us-east-1.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://"+endpoint.Host+"/some/rest/path", strings.NewReader("{} trailing"))
	req.Host = endpoint.Host
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonEC2ContainerServiceV20141113.DescribeServices")
	verified := &awsrequest.VerifiedRequest{Request: req, Endpoint: endpoint, Protocol: awsrequest.ProtocolJSON11, SigningScheme: awsrequest.SigningHeaderV4, SigningRegion: endpoint.Region, SigningService: endpoint.Service, PayloadMode: awsrequest.PayloadHashSHA256}
	collector := &pipelineAuditCollector{}
	var forwards atomic.Int32
	server, err := NewServer(Config{
		Username: testUser, Password: testPassword, RunID: "run-route-conflict", PolicyHash: "sha256:" + strings.Repeat("0", 64),
		InboundAuthenticator: pipelineAuthenticator{verified: verified}, Decoder: awsrequest.NewDecoder(), Audit: collector,
		Upstream: roundTripFunc(func(*http.Request) (*http.Response, error) {
			forwards.Add(1)
			return nil, errors.New("unexpected forward")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	response := httptest.NewRecorder()
	server.handlePipeline(response, req, destination{Host: endpoint.Host, Port: 443}, endpoint)
	if response.Code != http.StatusForbidden || forwards.Load() != 0 {
		t.Fatalf("route conflict response=%d forwards=%d", response.Code, forwards.Load())
	}
	if len(collector.events) != 1 || collector.events[0].Request.Operation != "Unknown" || collector.events[0].Request.Protocol != awsrequest.ProtocolJSON11 {
		t.Fatalf("route conflict audit=%+v", collector.events)
	}
}

func TestPipelineCachesSuppressCallsCloneValuesAndAuditEveryRequest(t *testing.T) {
	caches, err := cache.NewRunCaches(cache.CacheOptions{EndpointCapacity: 1, OperationCapacity: 1, DecisionCapacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	decoded := pipelineDecodedRequest("GetCallerIdentity", "123456789012", "us-east-1", "aws")
	mapping := pipelineMapping(decoded.Operation, "arn:aws:iam::123456789012:role/a")
	mapper := &countingPipelineMapper{mapping: mapping}
	pol := &mutatingPipelinePolicy{mapping: mapping}
	collector := &pipelineAuditCollector{}
	server, err := NewServer(Config{
		Username: testUser, Password: testPassword, RunID: "run-cache", PolicyHash: "sha256:" + strings.Repeat("0", 64),
		InboundAuthenticator: pipelineAuthenticator{verified: &awsrequest.VerifiedRequest{Request: httptest.NewRequest(http.MethodPost, "https://sts.amazonaws.com/", nil), Endpoint: pipelineTestEndpoint(), Protocol: awsrequest.ProtocolJSON11, SigningScheme: awsrequest.SigningHeaderV4, SigningRegion: "us-east-1", SigningService: "sts", PayloadMode: awsrequest.PayloadHashEmpty}},
		Decoder:              pipelineDecoder{decoded: decoded}, Mapper: mapper, Policy: pol, Audit: collector, Caches: caches,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	request := httptest.NewRequest(http.MethodPost, "https://sts.amazonaws.com/", nil)
	request.Host = "sts.amazonaws.com"
	run := func() {
		recorder := httptest.NewRecorder()
		server.handlePipeline(recorder, request, destination{Host: "sts.amazonaws.com", Port: 443}, pipelineTestEndpoint())
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("pipeline status=%d", recorder.Code)
		}
	}

	run()
	// Mutating the event returned to the caller must not mutate the cached result.
	collector.events[0].Decision.MatchedRuleIDs[0] = "changed-after-audit"
	run()
	if mapper.calls.Load() != 1 || pol.calls.Load() != 1 {
		t.Fatalf("cache did not suppress mapper/policy: mapper=%d policy=%d", mapper.calls.Load(), pol.calls.Load())
	}
	cachedMapping, ok := caches.Operations.Snapshot()[0].(*awsrequest.MappingResult)
	if !ok || cachedMapping.Requirements[0].Resources[0] != "arn:aws:iam::123456789012:role/a" {
		t.Fatal("mapping cache was not immutable")
	}
	if len(collector.events) != 2 || collector.events[1].Decision.MatchedRuleIDs[0] != "rule-1" {
		t.Fatal("decision cache was not immutable")
	}

	// A distinct operation evicts both entries; returning to the first operation
	// proves the miss is real rather than a stale cross-request result.
	decoded.Operation, mapping.Operation = "GetSessionToken", "GetSessionToken"
	mapping.Requirements[0].Action = "sts:GetSessionToken"
	mapping.Requirements[0].Resources[0] = "arn:aws:iam::123456789012:role/b"
	run()
	decoded.Operation, mapping.Operation = "GetCallerIdentity", "GetCallerIdentity"
	mapping.Requirements[0].Action = "sts:GetCallerIdentity"
	mapping.Requirements[0].Resources[0] = "arn:aws:iam::123456789012:role/a"
	run()
	if mapper.calls.Load() != 3 || pol.calls.Load() != 3 || len(collector.events) != 4 {
		t.Fatalf("eviction did not force fresh stages: mapper=%d policy=%d audit=%d", mapper.calls.Load(), pol.calls.Load(), len(collector.events))
	}
	if _, _, err := server.classifyDestination(destination{Host: "sts.amazonaws.com", Port: 443}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.classifyDestination(destination{Host: "sts.amazonaws.com", Port: 443}); err != nil {
		t.Fatal(err)
	}
	metrics := server.MetricsSnapshot().Counters
	for name, want := range map[string]uint64{
		observe.CacheMappingHits: 1, observe.CacheMappingMisses: 3,
		observe.CacheDecisionHits: 1, observe.CacheDecisionMisses: 3,
		observe.CacheEndpointHits: 1, observe.CacheEndpointMisses: 1,
		observe.CacheEvictions: 4,
	} {
		if metrics[name] != want {
			t.Errorf("metric %s=%d, want %d", name, metrics[name], want)
		}
	}
}

func TestDecisionCacheKeySeparatesAllAuthorizationDimensions(t *testing.T) {
	caches, err := cache.NewRunCaches(cache.CacheOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{config: Config{RunID: "run-a", PolicyHash: "policy-a", MapperVersion: "mapper-a", AdapterVersion: "adapter-a", DataVersion: "data-a"}, caches: caches}
	endpoint := pipelineTestEndpoint()
	request := pipelineDecodedRequest("GetCallerIdentity", "123456789012", "us-east-1", "aws")
	mapping := pipelineMapping(request.Operation, "arn:aws:iam::123456789012:role/a")
	runID := "run-a"
	base := server.decisionCacheKey(runID, endpoint, request, mapping)
	cases := map[string]func(){
		"run":       func() { runID = "run-b" },
		"policy":    func() { server.config.PolicyHash = "policy-b" },
		"mapper":    func() { server.config.MapperVersion = "mapper-b" },
		"data":      func() { server.config.DataVersion = "data-b" },
		"region":    func() { request.Region = "us-west-2"; endpoint.Region = "us-west-2" },
		"account":   func() { request.CallerAccountID = "210987654321" },
		"partition": func() { request.Partition = "aws-us-gov"; endpoint.Partition = "aws-us-gov" },
		"resource":  func() { mapping.Requirements[0].Resources[0] = "arn:aws:iam::123456789012:role/b" },
		"requirements": func() {
			mapping.Requirements = append(mapping.Requirements, awsrequest.IAMRequirement{Action: "sts:DecodeAuthorizationMessage", Resources: []string{"*"}, ScopeKind: awsrequest.ScopeKnownGlobal})
		},
	}
	for name, change := range cases {
		runID = "run-a"
		server.config.RunID, server.config.PolicyHash = "run-a", "policy-a"
		server.config.MapperVersion, server.config.DataVersion = "mapper-a", "data-a"
		request.Region, request.CallerAccountID, request.Partition = "us-east-1", "123456789012", "aws"
		endpoint.Region, endpoint.Partition = "us-east-1", "aws"
		mapping.Requirements = []awsrequest.IAMRequirement{{Action: "sts:GetCallerIdentity", Resources: []string{"arn:aws:iam::123456789012:role/a"}, ScopeKind: awsrequest.ScopeExact}}
		change()
		if got := server.decisionCacheKey(runID, endpoint, request, mapping); got == base {
			t.Errorf("%s dimension did not change decision key", name)
		}
	}
}

func TestConnectionAndRequestBudgetsAreIndependent(t *testing.T) {
	metrics := observe.NewMetrics()
	server, err := NewServer(Config{Username: testUser, Password: testPassword, Metrics: metrics, MaxConcurrentConnections: 1, MaxConcurrentRequests: 1, AWSHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, _ := net.Pipe()
	defer client.Close()
	if !server.trackConn(client) {
		t.Fatal("first CONNECT was not admitted")
	}
	second, _ := net.Pipe()
	defer second.Close()
	if server.trackConn(second) {
		t.Fatal("second CONNECT exceeded connection budget")
	}
	// An idle CONNECT owns a connection slot but no request slot.
	if !server.acquireRequestSlot() {
		t.Fatal("idle CONNECT starved application request slot")
	}
	server.releaseRequestSlot()
	server.untrackConn(client)
	if !server.trackConn(second) {
		t.Fatal("released connection slot was not reusable")
	}
	server.untrackConn(second)

	request := httptest.NewRequest(http.MethodPost, "https://sts.amazonaws.com/", nil)
	request.Host = "sts.amazonaws.com"
	response := httptest.NewRecorder()
	server.handleIntercepted(response, request, destination{Host: "sts.amazonaws.com", Port: 443})
	if response.Code != http.StatusNoContent {
		t.Fatalf("max-requests=1 intercepted status=%d", response.Code)
	}
	snapshot := metrics.Snapshot()
	if snapshot.ActiveConnections != 0 || snapshot.PeakConnections != 1 || snapshot.ActiveRequests != 0 || snapshot.PeakRequests != 1 {
		t.Fatalf("budget accounting=%+v", snapshot)
	}
}

func TestUpstreamStatusClassificationPreservesResponses(t *testing.T) {
	for _, test := range []struct {
		status int
		metric string
	}{
		{http.StatusBadRequest, observe.UpstreamClient},
		{http.StatusUnauthorized, observe.UpstreamAuth},
		{http.StatusPaymentRequired, observe.UpstreamClient},
		{http.StatusForbidden, observe.UpstreamAuth},
		{http.StatusNotFound, observe.UpstreamClient},
		{http.StatusTooManyRequests, observe.UpstreamThrottled},
		{http.StatusInternalServerError, observe.UpstreamServer},
	} {
		t.Run(strconv.Itoa(test.status), func(t *testing.T) {
			endpoint := pipelineTestEndpoint()
			request := httptest.NewRequest(http.MethodPost, "https://sts.amazonaws.com/", nil)
			request.Host = endpoint.Host
			decoded := pipelineDecodedRequest("GetCallerIdentity", "123456789012", endpoint.Region, endpoint.Partition)
			mapping := pipelineMapping(decoded.Operation, "*")
			resigner, err := sigv4.NewResigner(sdkcredentials.NewStaticCredentialsProvider("UPSTREAMACCESS01", "upstream-secret", ""))
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewServer(Config{
				Username: testUser, Password: testPassword, RunID: "run-status",
				PolicyHash: "sha256:" + strings.Repeat("0", 64),
				InboundAuthenticator: pipelineAuthenticator{verified: &awsrequest.VerifiedRequest{
					Request: request, Endpoint: endpoint, Protocol: awsrequest.ProtocolJSON11,
					SigningScheme: awsrequest.SigningHeaderV4, SigningRegion: endpoint.Region,
					SigningService: endpoint.Service, PayloadMode: awsrequest.PayloadHashEmpty,
				}},
				Decoder: pipelineDecoder{decoded: decoded}, Mapper: pipelineMapper{mapping: mapping},
				Policy: pipelinePolicy{decision: policy.Decision{Result: policy.DecisionAllow, ReasonCode: awserror.ReasonAllRequirementsAllowed}},
				Audit:  &pipelineAuditCollector{}, Resigner: resigner,
				Upstream: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: test.status, Header: http.Header{"X-Upstream": {"preserved"}}, Body: io.NopCloser(strings.NewReader("upstream response")), Request: req}, nil
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			response := httptest.NewRecorder()
			server.handlePipeline(response, request, destination{Host: endpoint.Host, Port: 443}, endpoint)
			if response.Code != test.status || response.Body.String() != "upstream response" || response.Header().Get("X-Upstream") != "preserved" {
				t.Fatalf("response = status %d body %q headers %v", response.Code, response.Body.String(), response.Header())
			}
			if got := server.MetricsSnapshot().Counters[test.metric]; got != 1 {
				t.Fatalf("metric %s = %d, want 1", test.metric, got)
			}
		})
	}
}

func TestSpoolMetricsRequirePreparedDiskBody(t *testing.T) {
	const largeDecodedSize = int64(1 << 20)
	cases := []struct {
		name        string
		body        []byte
		capture     bool
		memoryLimit int64
		wantSpool   uint64
	}{
		{name: "no prepared body handle", body: nil, wantSpool: 0},
		{name: "in-memory body handle", body: []byte("small"), capture: true, memoryLimit: 16, wantSpool: 0},
		{name: "actual disk spool", body: bytes.Repeat([]byte("x"), 32), capture: true, memoryLimit: 8, wantSpool: 32},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			tempDir := t.TempDir()
			request := httptest.NewRequest(http.MethodPost, "https://sts.amazonaws.com/", bytes.NewReader(test.body))
			request.Host = "sts.amazonaws.com"
			if !test.capture {
				request.Body = http.NoBody
			}
			if test.capture {
				if _, err := sigv4.CaptureRequestBody(request, sigv4.BodyOptions{MaxInMemoryBytes: test.memoryLimit, MaxSpoolBytes: 64, TempDir: tempDir}); err != nil {
					t.Fatal(err)
				}
			}
			decoded := pipelineDecodedRequest("GetCallerIdentity", "123456789012", "us-east-1", "aws")
			decoded.PayloadBytes = largeDecodedSize
			server, err := NewServer(Config{
				Username: testUser, Password: testPassword, RunID: "run-spool",
				PolicyHash: "sha256:" + strings.Repeat("0", 64),
				InboundAuthenticator: pipelineAuthenticator{verified: &awsrequest.VerifiedRequest{
					Request: request, Endpoint: pipelineTestEndpoint(), Protocol: awsrequest.ProtocolJSON11,
					SigningScheme: awsrequest.SigningHeaderV4, SigningRegion: "us-east-1",
					SigningService: "sts", PayloadMode: awsrequest.PayloadHashEmpty,
				}},
				Decoder: pipelineDecoder{decoded: decoded}, Mapper: pipelineMapper{mapping: pipelineMapping(decoded.Operation, "*")},
				Policy: pipelinePolicy{decision: policy.Decision{Result: policy.DecisionDeny, ReasonCode: awserror.ReasonPolicyNoMatchingAllow}},
				Audit:  &pipelineAuditCollector{}, Limits: Limits{MaxInMemoryBodyBytes: 8, MaxSpoolBodyBytes: 64},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			response := httptest.NewRecorder()
			server.handlePipeline(response, request, destination{Host: "sts.amazonaws.com", Port: 443}, pipelineTestEndpoint())
			if got := server.MetricsSnapshot().Counters[observe.SpoolBytes]; got != test.wantSpool {
				t.Fatalf("spool metric = %d, want %d", got, test.wantSpool)
			}
			if entries, err := os.ReadDir(tempDir); err != nil {
				t.Fatal(err)
			} else if len(entries) != 0 {
				t.Fatalf("temporary spool files remain: %v", entries)
			}
		})
	}
}

func TestMaxConcurrentConnectionsAdmission(t *testing.T) {
	const host = "sts.connection-budget.test"
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	server := newTestProxy(t, Config{
		Classifier: testAWSClassifier(host), MaxConcurrentConnections: 1,
		AWSHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			enteredOnce.Do(func() { close(entered) })
			<-release
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	openTLS := func() *tls.Conn {
		raw := openProxy(t, server)
		writeConnect(t, raw, host+":443", true)
		response := readProxyResponse(t, raw)
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			t.Fatalf("CONNECT status=%d", response.StatusCode)
		}
		response.Body.Close()
		conn := tls.Client(raw, &tls.Config{RootCAs: server.CA().CertPool(), ServerName: host, MinVersion: tls.VersionTLS12})
		if err := conn.Handshake(); err != nil {
			raw.Close()
			t.Fatal(err)
		}
		return conn
	}
	first := openTLS()
	if _, err := io.WriteString(first, "POST / HTTP/1.1\r\nHost: "+host+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); err != nil {
		first.Close()
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		first.Close()
		t.Fatal("first CONNECT did not enter handler")
	}

	second := openProxy(t, server)
	defer second.Close()
	writeConnect(t, second, host+":443", true)
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	var rejected [1]byte
	if n, err := second.Read(rejected[:]); n != 0 || err == nil {
		t.Fatalf("second CONNECT was not closed by admission: n=%d err=%v", n, err)
	}

	close(release)
	firstResponse := readProxyResponse(t, first)
	if firstResponse.StatusCode != http.StatusNoContent {
		firstResponse.Body.Close()
		first.Close()
		t.Fatalf("first response status=%d", firstResponse.StatusCode)
	}
	firstResponse.Body.Close()
	first.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && server.MetricsSnapshot().ActiveConnections != 0 {
		time.Sleep(time.Millisecond)
	}
	if got := server.MetricsSnapshot().ActiveConnections; got != 0 {
		t.Fatalf("first CONNECT slot was not released: %d", got)
	}

	third := openTLS()
	if _, err := io.WriteString(third, "POST / HTTP/1.1\r\nHost: "+host+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); err != nil {
		third.Close()
		t.Fatal(err)
	}
	thirdResponse := readProxyResponse(t, third)
	if thirdResponse.StatusCode != http.StatusNoContent {
		thirdResponse.Body.Close()
		third.Close()
		t.Fatalf("third CONNECT status=%d", thirdResponse.StatusCode)
	}
	thirdResponse.Body.Close()
	third.Close()
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		snapshot := server.MetricsSnapshot()
		if snapshot.ActiveConnections == 0 && snapshot.ActiveRequests == 0 {
			if snapshot.PeakConnections != 1 {
				t.Fatalf("connection peak=%d, want 1", snapshot.PeakConnections)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("connection/request gauges leaked: %+v", server.MetricsSnapshot())
}

func TestConnectTLSInterceptionAndIndependentRequestBudget(t *testing.T) {
	const host = "sts.injected.test"
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	server := newTestProxy(t, Config{
		Classifier: testAWSClassifier(host), MaxConcurrentConnections: 4, MaxConcurrentRequests: 1,
		AWSHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			once.Do(func() { close(entered) })
			<-release
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	openTLS := func() *tls.Conn {
		raw := openProxy(t, server)
		writeConnect(t, raw, host+":443", true)
		response := readProxyResponse(t, raw)
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			t.Fatalf("CONNECT status=%d", response.StatusCode)
		}
		response.Body.Close()
		tlsConn := tls.Client(raw, &tls.Config{RootCAs: server.CA().CertPool(), ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			raw.Close()
			t.Fatal(err)
		}
		return tlsConn
	}
	first := openTLS()
	defer first.Close()
	if _, err := io.WriteString(first, "POST / HTTP/1.1\r\nHost: "+host+"\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first intercepted request did not enter handler")
	}

	second := openTLS()
	defer second.Close()
	if _, err := io.WriteString(second, "POST / HTTP/1.1\r\nHost: "+host+"\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	secondResponse := readProxyResponse(t, second)
	if secondResponse.StatusCode != http.StatusServiceUnavailable {
		secondResponse.Body.Close()
		t.Fatalf("concurrent intercepted request status=%d", secondResponse.StatusCode)
	}
	secondResponse.Body.Close()
	close(release)
	firstResponse := readProxyResponse(t, first)
	if firstResponse.StatusCode != http.StatusNoContent {
		firstResponse.Body.Close()
		t.Fatalf("held intercepted request status=%d", firstResponse.StatusCode)
	}
	firstResponse.Body.Close()

	if _, err := io.WriteString(second, "POST / HTTP/1.1\r\nHost: "+host+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	later := readProxyResponse(t, second)
	if later.StatusCode != http.StatusNoContent {
		later.Body.Close()
		t.Fatalf("released intercepted request status=%d", later.StatusCode)
	}
	later.Body.Close()
	_ = second.Close()
	_ = first.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if snapshot := server.MetricsSnapshot(); snapshot.ActiveConnections == 0 && snapshot.ActiveRequests == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("connection/request gauges leaked: %+v", server.MetricsSnapshot())
}
