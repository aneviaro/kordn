// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package audit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kordn-ai/kordn/internal/awsrequest"
)

func benchmarkDecisionEvent() Event {
	return Event{
		SchemaVersion: SchemaVersion, EventID: "evt_benchmark", RunID: "benchmark-run", Timestamp: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC), EventType: RequestDecision, ConnectionID: "connection",
		Request:         &RequestInfo{Host: "sts.us-east-1.amazonaws.com", Partition: "aws", Service: "sts", Operation: "GetCallerIdentity", Region: "us-east-1", Protocol: awsrequest.ProtocolQuery, Method: "POST"},
		IAMRequirements: []Requirement{{Action: "sts:GetCallerIdentity", Resources: []string{"*"}, ScopeKind: awsrequest.ScopeKnownGlobal}},
		Mapping:         &MappingInfo{Confidence: awsrequest.ConfidenceHigh, MapperVersion: "benchmark"}, Decision: &DecisionInfo{Result: "allow", ReasonCode: "all_requirements_allowed", PolicyHash: "sha256:" + strings.Repeat("a", 64)}, Timing: &TimingInfo{},
	}
}

func BenchmarkEventJSONL(b *testing.B) {
	event := benchmarkDecisionEvent()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(event); err != nil {
			b.Fatal(err)
		}
	}
}

const benchmarkAuditWriteChunk = 512

// benchmarkAuditWriter writes exactly b.N events. Flushes at chunk boundaries
// stay inside the timer so persistence benchmarks include their fsync work.
func benchmarkAuditWriter(b *testing.B, options Options) {
	b.Helper()
	path := filepath.Join(b.TempDir(), "events.jsonl")
	w, err := NewWriter(path, options)
	if err != nil {
		b.Fatal(err)
	}
	event := benchmarkDecisionEvent()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for offset := 0; offset < b.N; {
		end := offset + benchmarkAuditWriteChunk
		if end > b.N {
			end = b.N
		}
		for i := offset; i < end; i++ {
			if err := w.Write(ctx, event); err != nil {
				b.Fatal(err)
			}
		}
		if err := w.Flush(ctx); err != nil {
			b.Fatal(err)
		}
		offset = end
	}
	b.StopTimer()
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkAuditQueueAcceptance measures only Write's queue acceptance. A
// discard consumer drains accepted items so the bounded queue cannot fill;
// persistence is deliberately not part of this benchmark.
func BenchmarkAuditQueueAcceptance(b *testing.B) {
	path := filepath.Join(b.TempDir(), "events.jsonl")
	w, err := NewWriter(path, Options{QueueCapacity: b.N + 1, BatchSize: benchmarkAuditWriteChunk, BatchInterval: time.Hour, Fsync: Batch})
	if err != nil {
		b.Fatal(err)
	}
	close(w.stop)
	w.wg.Wait()

	drained := make(chan struct{})
	go func() {
		for range w.queue {
		}
		close(drained)
	}()
	defer func() {
		close(w.queue)
		<-drained
		if err := w.file.Close(); err != nil {
			b.Errorf("close audit writer: %v", err)
		}
	}()
	event := benchmarkDecisionEvent()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Write(ctx, event); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkAuditBatchFsync(b *testing.B) {
	benchmarkAuditWriter(b, Options{QueueCapacity: benchmarkAuditWriteChunk * 2, BatchSize: benchmarkAuditWriteChunk, BatchInterval: time.Hour, Fsync: Batch})
}

func BenchmarkAuditDecisionFsync(b *testing.B) {
	benchmarkAuditWriter(b, Options{QueueCapacity: benchmarkAuditWriteChunk * 2, BatchSize: benchmarkAuditWriteChunk, BatchInterval: time.Hour, Fsync: Decision})
}
