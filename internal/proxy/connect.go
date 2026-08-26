// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/kordn-ai/kordn/internal/awsrequest"
)

type destination struct {
	Host string
	Port int
}

func (d destination) authority() string {
	return net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
}

func (d destination) equal(other destination) bool {
	return d.Host == other.Host && d.Port == other.Port
}

// NormalizeAuthority performs the proxy's independent CONNECT/Host parsing.
// An omitted port means the TLS default 443; malformed, ambiguous, or
// userinfo-bearing authorities are rejected before classification.
func NormalizeAuthority(authority string) (string, int, error) {
	if authority == "" || strings.TrimSpace(authority) != authority || strings.ContainsAny(authority, "\x00\r\n/@") {
		return "", 0, errors.New("destination authority is malformed")
	}
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 || end == 1 {
			return "", 0, errors.New("destination IPv6 authority is malformed")
		}
		host := authority[1:end]
		if strings.Contains(host, "%") || net.ParseIP(host) == nil {
			return "", 0, errors.New("destination IPv6 authority is malformed")
		}
		port := 443
		if end+1 < len(authority) {
			if authority[end+1] != ':' {
				return "", 0, errors.New("destination IPv6 authority is malformed")
			}
			port = parsePort(authority[end+2:])
			if port == 0 {
				return "", 0, errors.New("destination port is invalid")
			}
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() != nil {
			return "", 0, errors.New("destination IPv6 authority is malformed")
		}
		return ip.String(), port, nil
	}
	if strings.Count(authority, ":") > 1 {
		return "", 0, errors.New("unbracketed IPv6 authority is malformed")
	}
	if host, portText, ok := strings.Cut(authority, ":"); ok {
		if host == "" || portText == "" {
			return "", 0, errors.New("destination authority port is malformed")
		}
		port := parsePort(portText)
		if port == 0 {
			return "", 0, errors.New("destination port is invalid")
		}
		authority = host
		return normalizeHostOnly(authority, port)
	}
	return normalizeHostOnly(authority, 443)
}

func parsePort(value string) int {
	if value == "" || len(value) > 5 {
		return 0
	}
	port := 0
	for _, char := range value {
		if char < '0' || char > '9' {
			return 0
		}
		port = port*10 + int(char-'0')
		if port > 65535 {
			return 0
		}
	}
	if port < 1 || port > 65535 {
		return 0
	}
	return port
}

func normalizeHostOnly(host string, port int) (string, int, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), port, nil
	}
	normalized, _, err := awsrequest.NormalizeEndpointHost(host)
	if err != nil {
		return "", 0, errors.New("destination hostname is malformed")
	}
	return normalized, port, nil
}

func requestAuthority(req *http.Request, connect bool) string {
	if req == nil {
		return ""
	}
	if connect {
		if req.Host != "" {
			return req.Host
		}
		return req.RequestURI
	}
	if req.URL != nil && req.URL.IsAbs() && req.URL.Host != "" {
		return req.URL.Host
	}
	return req.Host
}

func parseRequestDestination(req *http.Request, connect bool) (destination, error) {
	authority := requestAuthority(req, connect)
	if !connect && req != nil && req.URL != nil && !strings.EqualFold(req.URL.Scheme, "https") && !strings.Contains(authority, ":") {
		authority += ":80"
	}
	host, port, err := NormalizeAuthority(authority)
	if err != nil {
		return destination{}, err
	}
	return destination{Host: host, Port: port}, nil
}

func classifyDestination(classifier awsrequest.EndpointClassifier, dest destination) (awsrequest.AWSEndpoint, bool, error) {
	if classifier == nil {
		classifier = awsrequest.DefaultClassifier()
	}
	endpoint, err := classifier.Classify(dest.Host)
	if err == nil {
		if dest.Port != 443 || endpoint.Host != dest.Host {
			return awsrequest.AWSEndpoint{}, false, errors.New("AWS endpoint port is not TLS")
		}
		if err := endpoint.Validate(); err != nil {
			return awsrequest.AWSEndpoint{}, false, errors.New("AWS endpoint metadata is invalid")
		}
		return endpoint, true, nil
	}
	if awsrequest.LooksLikeAWSHost(dest.Host) {
		return awsrequest.AWSEndpoint{}, false, errors.New("unsupported or unsafe AWS endpoint")
	}
	return awsrequest.AWSEndpoint{}, false, nil
}

func validateHostAgreement(connectHost string, innerHost string) error {
	connectName, connectPort, err := NormalizeAuthority(connectHost)
	if err != nil {
		return err
	}
	innerName, innerPort, err := NormalizeAuthority(innerHost)
	if err != nil {
		return err
	}
	if connectName != innerName || connectPort != innerPort {
		return fmt.Errorf("inner Host does not match CONNECT authority")
	}
	return nil
}
