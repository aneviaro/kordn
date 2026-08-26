// Copyright 2026 Kordn AI contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package credentials owns credentials held by Kordn. FakeCredential is kept
// separate from aws.Credentials so provider values cannot be accidentally
// serialized into child files or arguments.
package credentials

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

const (
	randomMaterialBytes   = 32
	randomMaterialEncoded = 43 // base64.RawURLEncoding.EncodedLen(32)
	accessKeyIDPrefix     = "KORDN"
	accessKeyIDMinLength  = 16
	accessKeyIDMaxLength  = 128
)

// FakeCredential is the one AWS-compatible identity exposed to a protected
// process. It has no AWS authority and is accepted only by Kordn's verifier.
type FakeCredential struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	CreatedAt       time.Time
}

// String intentionally never includes credential identifiers, secrets, or
// session tokens. Keeping this safe is useful when a credential is included in
// a test failure, debugger, or accidentally formatted diagnostic.
func (f FakeCredential) String() string {
	return "FakeCredential{AccessKeyID:[REDACTED] SecretAccessKey:[REDACTED] SessionToken:[REDACTED]}"
}

// RunSecrets contains stable per-run authentication material. It is generated
// once and retained only for the lifetime of a run.
type RunSecrets struct {
	RunID         string
	Fake          FakeCredential
	ProxyUsername string
	ProxySecret   string
}

// String keeps accidental formatting of the complete run state non-sensitive.
func (r RunSecrets) String() string {
	return fmt.Sprintf("RunSecrets{RunID:%q ProxyUsername:%q Fake:%s ProxySecret:[REDACTED]}", r.RunID, r.ProxyUsername, r.Fake.String())
}

func (r RunSecrets) GoString() string     { return r.String() }
func (f FakeCredential) GoString() string { return f.String() }

// Generate creates cryptographically random, stable credentials for one run.
// Every generated value contains 32 independent random bytes. Raw URL-safe
// base64 preserves all 256 bits without padding and uses only characters safe
// in environment values, INI files, SigV4 headers, and proxy passwords.
//
// AWS access-key identifiers accept 16 through 128 characters. KORDN plus the
// 43-character encoding is 48 characters, with a recognizable local prefix
// while remaining inside that range.
func Generate() (RunSecrets, error) {
	runID, err := randomMaterial()
	if err != nil {
		return RunSecrets{}, errors.New("generate run identity")
	}
	accessSuffix, err := randomMaterial()
	if err != nil {
		return RunSecrets{}, errors.New("generate fake access identity")
	}
	secret, err := randomMaterial()
	if err != nil {
		return RunSecrets{}, errors.New("generate fake secret")
	}
	sessionToken, err := randomMaterial()
	if err != nil {
		return RunSecrets{}, errors.New("generate fake session token")
	}
	proxySecret, err := randomMaterial()
	if err != nil {
		return RunSecrets{}, errors.New("generate proxy credential")
	}

	accessKeyID := accessKeyIDPrefix + accessSuffix
	if len(accessKeyID) < accessKeyIDMinLength || len(accessKeyID) > accessKeyIDMaxLength {
		return RunSecrets{}, errors.New("generated fake access identity is outside AWS limits")
	}

	return RunSecrets{
		RunID: "run-" + runID,
		Fake: FakeCredential{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secret,
			SessionToken:    sessionToken,
			CreatedAt:       time.Now().UTC(),
		},
		ProxyUsername: "kordn",
		ProxySecret:   proxySecret,
	}, nil
}

func GenerateFakeCredential() (FakeCredential, error) {
	secrets, err := Generate()
	if err != nil {
		return FakeCredential{}, err
	}
	return secrets.Fake, nil
}

func GenerateRunSecrets() (RunSecrets, error) { return Generate() }

func randomMaterial() (string, error) {
	material := make([]byte, randomMaterialBytes)
	if _, err := rand.Read(material); err != nil {
		return "", errors.New("read cryptographic random source")
	}
	encoded := base64.RawURLEncoding.EncodeToString(material)
	if len(encoded) != randomMaterialEncoded {
		return "", errors.New("encode cryptographic random source")
	}
	return encoded, nil
}
