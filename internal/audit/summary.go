// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package audit

import (
	"sort"
)

type Summary struct {
	Total, Allowed, Denied, Unsupported int
	ByReason                            map[string]int
	RunID                               string
}

func Summarize(events []Event) Summary {
	s := Summary{ByReason: map[string]int{}}
	for _, e := range events {
		if e.EventType != RequestDecision {
			continue
		}
		s.Total++
		if e.Decision != nil {
			if e.Decision.Result == "allow" {
				s.Allowed++
			} else {
				s.Denied++
				s.ByReason[e.Decision.ReasonCode]++
			}
		}
		if s.RunID == "" {
			s.RunID = e.RunID
		}
	}
	return s
}
func Query(path, runID string) ([]Event, error) {
	events, err := ReadEvents(path)
	if err != nil {
		return nil, err
	}
	if runID == "" {
		return events, nil
	}
	out := events[:0]
	for _, e := range events {
		if e.RunID == runID {
			out = append(out, e)
		}
	}
	return out, nil
}
func Reasons(s Summary) []string {
	out := make([]string, 0, len(s.ByReason))
	for k := range s.ByReason {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
