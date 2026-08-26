// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package pki

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCAFileModesConstraintsAndCleanup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(dir, "keep.me")
	if err := os.WriteFile(unrelated, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fileMode(t, dir); mode != 0o700 {
		t.Fatalf("CA directory mode = %o, want 700", mode)
	}
	if mode := fileMode(t, ca.KeyPath()); mode != 0o600 {
		t.Fatalf("CA key mode = %o, want 600", mode)
	}
	if mode := fileMode(t, ca.CertPath()); mode != 0o600 {
		t.Fatalf("CA certificate mode = %o, want 600", mode)
	}
	block, _ := pem.Decode(ca.CertificatePEM())
	if block == nil {
		t.Fatal("CA PEM did not contain a certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || !cert.MaxPathLenZero || cert.MaxPathLen != 0 {
		t.Fatalf("unsafe CA constraints: IsCA=%v basic=%v maxZero=%v max=%d", cert.IsCA, cert.BasicConstraintsValid, cert.MaxPathLenZero, cert.MaxPathLen)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("CA cannot sign certificates")
	}
	if err := ca.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("cleanup removed unrelated file: %v", err)
	}
	if _, err := os.Stat(ca.KeyPath()); !os.IsNotExist(err) {
		t.Fatalf("CA key was not cleaned: %v", err)
	}
	if err := ca.Cleanup(); err != nil {
		t.Fatalf("cleanup is not idempotent: %v", err)
	}
}

func TestCANeverMakesAnExistingSharedDirectoryPrivateByMutation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if ca, err := NewCA(dir); err == nil || ca != nil {
		t.Fatalf("shared directory was accepted: ca=%v err=%v", ca, err)
	}
	if mode := fileMode(t, dir); mode != 0o755 {
		t.Fatalf("rejected directory mode changed to %o", mode)
	}
}

func TestCAIssuedLeafIsExactSANServerAuthAndShortLived(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "run"))
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Cleanup()
	leaf, err := ca.IssueLeaf("EC2.US-EAST-1.AMAZONAWS.COM")
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Leaf == nil || leaf.Leaf.IsCA || leaf.Leaf.Subject.CommonName != "" || len(leaf.Leaf.DNSNames) != 1 || leaf.Leaf.DNSNames[0] != "ec2.us-east-1.amazonaws.com" {
		t.Fatalf("leaf is not SAN-only exact-host: %+v", leaf.Leaf)
	}
	if len(leaf.Leaf.IPAddresses) != 0 || len(leaf.Leaf.DNSNames[0]) == 0 {
		t.Fatal("leaf unexpectedly contains an IP SAN")
	}
	if len(leaf.Leaf.ExtKeyUsage) != 1 || leaf.Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("leaf EKU = %v, want server auth only", leaf.Leaf.ExtKeyUsage)
	}
	if !leaf.Leaf.NotAfter.After(time.Now()) || leaf.Leaf.NotAfter.Sub(leaf.Leaf.NotBefore) > 31*time.Minute {
		t.Fatalf("leaf validity is not short: %s to %s", leaf.Leaf.NotBefore, leaf.Leaf.NotAfter)
	}
	pool := ca.CertPool()
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "ec2.us-east-1.amazonaws.com", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("leaf does not verify with run CA: %v", err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "other.amazonaws.com", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("leaf verified for a different hostname")
	}
	config := TLSConfig(leaf)
	if len(config.NextProtos) != 1 || config.NextProtos[0] != "http/1.1" || config.MinVersion != tls.VersionTLS12 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS config is not h1-only: %+v", config)
	}
	if _, err := ca.IssueLeaf("127.0.0.1"); err == nil {
		t.Fatal("IP address was accepted as a DNS leaf name")
	}
}

func TestLeafCacheConcurrentBoundedAndCanonical(t *testing.T) {
	ca, err := NewCA(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Cleanup()
	cache, err := NewLeafCache(ca, 2)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	certificates := make([][]byte, 32)
	for i := range certificates {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			leaf, err := cache.Get("EC2.US-EAST-1.AMAZONAWS.COM.")
			if err != nil {
				t.Errorf("Get: %v", err)
				return
			}
			certificates[i] = leaf.Certificate[0]
		}(i)
	}
	wg.Wait()
	for i := 1; i < len(certificates); i++ {
		if string(certificates[i]) != string(certificates[0]) {
			t.Fatal("concurrent cache misses generated duplicate leaves")
		}
	}
	if cache.Len() != 1 || cache.Capacity() != 2 {
		t.Fatalf("unexpected cache bounds: %d/%d", cache.Len(), cache.Capacity())
	}
	if _, err := cache.Get("other.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get("third.example"); err != nil {
		t.Fatal(err)
	}
	if cache.Len() > 2 {
		t.Fatalf("leaf cache exceeded capacity: %d", cache.Len())
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	if cache.Len() != 0 {
		t.Fatal("closed leaf cache retained entries")
	}
	if _, err := cache.Get("new.example"); err == nil {
		t.Fatal("closed leaf cache issued a certificate")
	}
}

func TestCACleanupDoesNotFollowReplacedSymlink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("must remain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ca.KeyPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, ca.KeyPath()); err != nil {
		t.Fatal(err)
	}
	if err := ca.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "must remain" {
		t.Fatalf("cleanup followed key symlink: %q, %v", data, err)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func leafFingerprint(leaf tls.Certificate) [32]byte {
	return sha256.Sum256(leaf.Certificate[0])
}
