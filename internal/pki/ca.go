// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

// Package pki owns the private, per-run certificate authority used only for
// recognized AWS TLS interception. It never edits operating-system trust.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultCAValidity = 24 * time.Hour
	certificateSkew   = 5 * time.Minute
)

// CA is one run's certificate authority. The private key and PEM certificate
// are kept in the supplied private directory and are removed by Cleanup.
type CA struct {
	mu         sync.RWMutex
	dir        string
	certPath   string
	keyPath    string
	cert       *x509.Certificate
	privateKey *ecdsa.PrivateKey
	certPEM    []byte
	keyPEM     []byte
	createdDir bool
	closed     bool
}

// NewCA creates a fresh P-256 CA in dir. Existing directories must already be
// private; a newly-created directory is made 0700. Existing files are never
// overwritten.
func NewCA(dir string) (*CA, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("private CA directory is required")
	}
	dir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil || dir == string(filepath.Separator) {
		return nil, errors.New("private CA directory is invalid")
	}
	created := false
	info, statErr := os.Lstat(dir)
	if errors.Is(statErr, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, errors.New("create private CA directory")
		}
		created = true
	} else if statErr != nil || !info.IsDir() {
		return nil, errors.New("private CA directory is unavailable")
	}
	if created {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, errors.New("set private CA directory mode")
		}
	}
	if err := verifyPrivateDir(dir); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("generate CA key")
	}
	now := time.Now().UTC()
	notBefore := now.Add(-certificateSkew)
	notAfter := now.Add(defaultCAValidity)
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Kordn run CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, errors.New("create CA certificate")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("parse CA certificate")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, errors.New("encode CA key")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	ca := &CA{dir: dir, certPath: filepath.Join(dir, "ca.pem"), keyPath: filepath.Join(dir, "ca.key"), cert: cert, privateKey: key, certPEM: certPEM, keyPEM: keyPEM, createdDir: created}
	if err := writeOwnedFile(ca.certPath, certPEM); err != nil {
		if created {
			_ = os.Remove(dir)
		}
		return nil, errors.New("write CA certificate")
	}
	if err := writeOwnedFile(ca.keyPath, keyPEM); err != nil {
		_ = os.Remove(ca.certPath)
		if created {
			_ = os.Remove(dir)
		}
		return nil, errors.New("write CA key")
	}
	return ca, nil
}

// GenerateCA is an alias for NewCA.
func GenerateCA(dir string) (*CA, error) { return NewCA(dir) }

// New is a short alias retained for callers constructing run state.
func New(dir string) (*CA, error) { return NewCA(dir) }

func (c *CA) Certificate() *x509.Certificate {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert
}

func (c *CA) CertificatePEM() []byte {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]byte(nil), c.certPEM...)
}

func (c *CA) KeyPath() string {
	if c == nil {
		return ""
	}
	return c.keyPath
}

func (c *CA) CertPath() string {
	if c == nil {
		return ""
	}
	return c.certPath
}

// PEMPath exposes the CA certificate path for AWS_CA_BUNDLE.
func (c *CA) PEMPath() string         { return c.CertPath() }
func (c *CA) CertificatePath() string { return c.CertPath() }

func (c *CA) CertPool() *x509.CertPool {
	if c == nil {
		return nil
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(c.CertificatePEM())
	return pool
}

// IssueLeaf creates a SAN-only server certificate for one exact normalized
// hostname. The returned tls.Certificate has no CA capability.
func (c *CA) IssueLeaf(host string) (tls.Certificate, error) {
	if c == nil {
		return tls.Certificate{}, errors.New("CA is unavailable")
	}
	host, err := normalizeDNSName(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || c.cert == nil || c.privateKey == nil {
		return tls.Certificate{}, errors.New("CA is closed")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, errors.New("generate leaf key")
	}
	now := time.Now().UTC()
	notBefore := now.Add(-time.Minute)
	if notBefore.Before(c.cert.NotBefore) {
		notBefore = c.cert.NotBefore
	}
	notAfter := now.Add(30 * time.Minute)
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	if !notAfter.After(notBefore) {
		return tls.Certificate{}, errors.New("CA validity window is exhausted")
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{host},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		Subject:               pkix.Name{},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.privateKey)
	if err != nil {
		return tls.Certificate{}, errors.New("create leaf certificate")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, errors.New("parse leaf certificate")
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// TLSConfig returns an interception server configuration which advertises
// HTTP/1.1 only. The leaf is generated by the caller/cache for the exact host.
func TLSConfig(leaf tls.Certificate) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf}, NextProtos: []string{"http/1.1"}}
}

func (c *CA) TLSConfig(host string) (*tls.Config, error) {
	leaf, err := c.IssueLeaf(host)
	if err != nil {
		return nil, err
	}
	return TLSConfig(leaf), nil
}

// Cleanup removes only the exact CA files owned by this CA. A caller-owned
// directory and unrelated files are retained.
func (c *CA) Cleanup() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if err := verifyPrivateDir(c.dir); err != nil {
		return err
	}
	c.closed = true
	var first error
	for _, path := range []string{c.keyPath, c.certPath} {
		if !pathInside(c.dir, path) {
			if first == nil {
				first = errors.New("refusing CA cleanup outside private directory")
			}
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
			first = errors.New("remove CA material")
		}
	}
	if c.createdDir {
		if err := os.Remove(c.dir); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
			first = errors.New("remove private CA directory")
		}
	}
	c.privateKey = nil
	c.cert = nil
	c.certPEM = nil
	c.keyPEM = nil
	return first
}

func (c *CA) Close() error { return c.Cleanup() }

func randomSerial() (*big.Int, error) {
	value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, errors.New("generate certificate serial")
	}
	if value.Sign() == 0 {
		value.SetInt64(1)
	}
	return value, nil
}

func writeOwnedFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func verifyPrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("private CA directory is unavailable")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("private CA directory is not mode 0700")
	}
	return nil
}

func pathInside(dir, path string) bool {
	dir = filepath.Clean(dir)
	path = filepath.Clean(path)
	return filepath.IsAbs(dir) && filepath.IsAbs(path) && filepath.Dir(path) == dir
}

func normalizeDNSName(host string) (string, error) {
	if host == "" || strings.TrimSpace(host) != host || strings.ContainsAny(host, "\x00\r\n:/@[]") || net.ParseIP(host) != nil {
		return "", errors.New("leaf hostname is malformed")
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.HasSuffix(host, ".") || len(host) > 253 {
		return "", errors.New("leaf hostname is malformed")
	}
	for _, label := range strings.Split(strings.ToLower(host), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("leaf hostname label is invalid")
		}
		for _, char := range label {
			if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
				return "", errors.New("leaf hostname must use ASCII DNS labels")
			}
		}
	}
	return strings.ToLower(host), nil
}
