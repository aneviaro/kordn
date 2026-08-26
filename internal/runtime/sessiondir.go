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

// Package runtime owns private state and child-process lifecycle. It never
// writes the user's ~/.aws files.
package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kordn-ai/kordn/internal/credentials"
)

const (
	defaultStaleRuntimeAge = 24 * time.Hour
	runDirectoryPrefix     = "run-"
)

var runIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// AWSFiles identifies synthetic shared-config files and the CA path handed to
// the child. Only the first two files are written by this package.
type AWSFiles struct {
	CredentialsPath string
	ConfigPath      string
	CABundlePath    string
}

// SessionDir is a private, per-run directory. Its path is not derived from a
// child-controlled value.
type SessionDir struct {
	Path  string
	RunID string
	root  string
}

func DefaultRuntimeRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve Kordn home")
	}
	return filepath.Join(home, ".kordn", "runs"), nil
}

// NewSessionDir creates a unique 0700 directory under root. An empty root
// selects DefaultRuntimeRoot. The caller owns cleanup and should use defer.
func NewSessionDir(root, runID string) (*SessionDir, error) {
	if strings.TrimSpace(root) == "" {
		var err error
		root, err = DefaultRuntimeRoot()
		if err != nil {
			return nil, err
		}
	}
	root, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, errors.New("resolve runtime root")
	}
	if err := ensurePrivateDirectory(root); err != nil {
		return nil, fmt.Errorf("runtime root: %w", err)
	}
	if !runIDPattern.MatchString(runID) || strings.ContainsAny(runID, "/\\\x00") {
		return nil, errors.New("invalid run identity")
	}
	// Reap only abandoned, old runs before allocating this run. The cleanup
	// routine uses Lstat and a private-root check, so startup never follows a
	// replaced symlink or removes an entry outside this runtime root.
	if err := cleanupStaleAt(root, defaultStaleRuntimeAge, time.Now()); err != nil {
		return nil, errors.New("clean up abandoned runtime state")
	}
	path := filepath.Join(root, runDirectoryPrefix+runID)
	if filepath.Dir(path) != root {
		return nil, errors.New("runtime path escapes root")
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, errors.New("create private run directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		_ = os.Remove(path)
		return nil, errors.New("set private run directory mode")
	}
	return &SessionDir{Path: path, RunID: runID, root: root}, nil
}

func CreateSessionDir(root, runID string) (*SessionDir, error) {
	return NewSessionDir(root, runID)
}

// WriteSyntheticAWSFiles writes only the fake credential, selected Region, and
// CA reference. O_EXCL prevents a symlink or accidental overwrite from
// turning this into a write to another file.
func (s *SessionDir) WriteSyntheticAWSFiles(fake credentials.FakeCredential, region, caPath string) (AWSFiles, error) {
	if s == nil || s.Path == "" || s.RunID == "" || s.root == "" {
		return AWSFiles{}, errors.New("session directory is not initialized")
	}
	if err := verifyPrivateDirectory(s.root); err != nil || !ownedRunPath(s) {
		return AWSFiles{}, errors.New("private runtime root is unavailable")
	}
	if err := verifyPrivateDirectory(s.Path); err != nil {
		return AWSFiles{}, errors.New("private run directory is unavailable")
	}
	if !safeINIValue(fake.AccessKeyID) || !safeINIValue(fake.SecretAccessKey) || !safeINIValue(fake.SessionToken) {
		return AWSFiles{}, errors.New("fake credential is incomplete")
	}
	if !safeINIValue(region) || !safeINIValue(caPath) || strings.TrimSpace(region) == "" || strings.TrimSpace(caPath) == "" {
		return AWSFiles{}, errors.New("synthetic AWS settings are incomplete")
	}
	files := AWSFiles{
		CredentialsPath: filepath.Join(s.Path, "credentials"),
		ConfigPath:      filepath.Join(s.Path, "config"),
		CABundlePath:    caPath,
	}
	credentialData := "[kordn]\n" +
		"aws_access_key_id = " + fake.AccessKeyID + "\n" +
		"aws_secret_access_key = " + fake.SecretAccessKey + "\n" +
		"aws_session_token = " + fake.SessionToken + "\n"
	configData := "[profile kordn]\n" +
		"region = " + region + "\n" +
		"ca_bundle = " + caPath + "\n"
	if err := writePrivateFile(files.CredentialsPath, []byte(credentialData)); err != nil {
		return AWSFiles{}, errors.New("write synthetic credentials")
	}
	if err := writePrivateFile(files.ConfigPath, []byte(configData)); err != nil {
		_ = os.Remove(files.CredentialsPath)
		return AWSFiles{}, errors.New("write synthetic AWS config")
	}
	return files, nil
}

// Cleanup removes only this run directory. It is idempotent, rejects a
// replaced run directory, and does not walk outside the private runtime root.
func (s *SessionDir) Cleanup() error {
	if s == nil || s.Path == "" {
		return nil
	}
	if s.root == "" || !ownedRunPath(s) {
		return errors.New("refusing runtime cleanup without a private root")
	}
	if err := verifyPrivateDirectory(s.root); err != nil {
		return errors.New("runtime root is unavailable")
	}
	info, err := os.Lstat(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("inspect run directory for cleanup")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("run directory is not a directory")
	}
	if err := os.RemoveAll(s.Path); err != nil {
		return errors.New("remove run directory")
	}
	return nil
}

// CleanupStale removes abandoned, old run directories directly below root. It
// never follows symlink entries and never removes names outside the run prefix.
func CleanupStale(root string, olderThan time.Duration) error {
	if olderThan < time.Hour {
		return errors.New("stale runtime age is too short")
	}
	return cleanupStaleAt(root, olderThan, time.Now())
}

func CleanupStaleRuntime(root string) error { return CleanupStale(root, defaultStaleRuntimeAge) }

func cleanupStaleAt(root string, olderThan time.Duration, now time.Time) error {
	if strings.TrimSpace(root) == "" {
		var err error
		root, err = DefaultRuntimeRoot()
		if err != nil {
			return err
		}
	}
	root, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return errors.New("resolve runtime root")
	}
	if err := verifyPrivateDirectory(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("runtime root is unavailable")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return errors.New("list runtime root")
	}
	cutoff := now.Add(-olderThan)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), runDirectoryPrefix) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			continue
		}
		if info.ModTime().Before(cutoff) {
			// RemoveAll does not follow symlink children; the Lstat check above
			// additionally prevents a replaced top-level entry from being used.
			if err := os.RemoveAll(path); err != nil {
				return errors.New("remove stale runtime")
			}
		}
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		return verifyPrivateDirectory(path)
	}
	if err != nil {
		return err
	}
	if err := verifyPrivateInfo(info); err != nil {
		// A caller-created temporary root may have conventional 0755 mode.
		// Narrowing it to 0700 is safe and ensures its run children cannot be
		// discovered by other users; symlinks and non-directories still fail.
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return err
		}
		if chmodErr := os.Chmod(path, 0o700); chmodErr != nil {
			return err
		}
		return verifyPrivateDirectory(path)
	}
	return nil
}

func verifyPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := verifyPrivateInfo(info); err != nil {
		return err
	}
	return nil
}

func verifyPrivateInfo(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path is not a private directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("directory is accessible by group or other users")
	}
	return nil
}

func ownedRunPath(s *SessionDir) bool {
	if s == nil || s.root == "" || s.Path == "" || s.RunID == "" {
		return false
	}
	path := filepath.Clean(s.Path)
	root := filepath.Clean(s.root)
	return filepath.IsAbs(path) && filepath.IsAbs(root) && filepath.Dir(path) == root && filepath.Base(path) == runDirectoryPrefix+s.RunID
}

func writePrivateFile(path string, data []byte) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func safeINIValue(value string) bool {
	return value != "" && !strings.ContainsAny(value, "\x00\r\n")
}
