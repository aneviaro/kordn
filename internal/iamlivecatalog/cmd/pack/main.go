// Command pack creates the deterministic offline iamlive catalog bundle.
package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxEntryBytes = 64 << 20

var fixedEntries = []string{
	"LICENSE",
	"NOTICE",
	"iamlivecore/map.json",
	"iamlivecore/iam_definition.json",
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "iamlive catalog pack: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	source := flag.String("source", "", "sparse iamlive checkout")
	output := flag.String("output", "", "catalog bundle path")
	flag.Parse()
	if *source == "" || *output == "" || flag.NArg() != 0 {
		return errors.New("usage: pack --source PATH --output PATH")
	}
	root, err := filepath.Abs(*source)
	if err != nil {
		return fmt.Errorf("resolve source: %w", err)
	}
	if err := validateSource(root); err != nil {
		return err
	}
	apiPaths, err := selectedPaths(root)
	if err != nil {
		return err
	}
	entries := append([]string{}, fixedEntries...)
	entries = append(entries, apiPaths...)
	return writeBundle(root, *output, entries)
}

func validateSource(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("source is not a real directory")
	}
	gitInfo, err := os.Lstat(filepath.Join(root, ".git"))
	if err != nil {
		return errors.New("source is missing .git marker")
	}
	if gitInfo.Mode()&os.ModeSymlink != 0 || (!gitInfo.IsDir() && !gitInfo.Mode().IsRegular()) {
		return errors.New("source has an invalid .git marker")
	}
	expected, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve source top-level: %w", err)
	}
	actualBytes, err := exec.Command("git", "-C", root, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return fmt.Errorf("verify source repository top-level: %w", err)
	}
	actual, err := filepath.EvalSymlinks(strings.TrimSpace(string(actualBytes)))
	if err != nil {
		return fmt.Errorf("resolve source repository top-level: %w", err)
	}
	if actual != expected {
		return fmt.Errorf("source repository top-level %q does not match source %q", actual, expected)
	}
	return nil
}

func selectedPaths(root string) ([]string, error) {
	seen := make(map[string]bool)
	var apiPaths []string
	err := filepath.WalkDir(root, func(file string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, file)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ".git" {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source contains symlink %q", rel)
		}
		if entry.IsDir() {
			return nil
		}
		if !isSelectedPath(rel) {
			return fmt.Errorf("unexpected source path %q", rel)
		}
		canonical := pathClean(rel)
		if canonical != rel || seen[canonical] {
			return fmt.Errorf("duplicate canonical source path %q", rel)
		}
		seen[canonical] = true
		if strings.HasPrefix(rel, "iamlivecore/apis/") {
			apiPaths = append(apiPaths, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, name := range fixedEntries {
		if !seen[name] {
			return nil, fmt.Errorf("missing selected source path %q", name)
		}
	}
	if len(apiPaths) == 0 {
		return nil, errors.New("missing selected API models")
	}
	sort.Strings(apiPaths)
	return apiPaths, nil
}

func isSelectedPath(name string) bool {
	for _, fixed := range fixedEntries {
		if name == fixed {
			return true
		}
	}
	parts := strings.Split(name, "/")
	return len(parts) == 5 && parts[0] == "iamlivecore" && parts[1] == "apis" &&
		parts[2] != "" && parts[3] != "" && parts[4] == "api-2.json"
}

func pathClean(name string) string {
	return filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
}

func writeBundle(root, output string, entries []string) (err error) {
	output, err = filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(output), ".iamlive-catalog-bundle-*")
	if err != nil {
		return fmt.Errorf("create bundle: %w", err)
	}
	tmp := file.Name()
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	gz := gzip.NewWriter(file)
	gz.Header.ModTime = time.Unix(0, 0)
	gz.Header.Name = ""
	gz.Header.Comment = ""
	tarWriter := tar.NewWriter(gz)
	for _, name := range entries {
		data, readErr := readBounded(filepath.Join(root, filepath.FromSlash(name)), name)
		if readErr != nil {
			return readErr
		}
		if (name == "LICENSE" || name == "NOTICE") && len(data) == 0 {
			return fmt.Errorf("selected source path %q is empty", name)
		}
		header := &tar.Header{
			Name:     name,
			Mode:     0600,
			Size:     int64(len(data)),
			ModTime:  time.Unix(0, 0),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("write %q header: %w", name, err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			return fmt.Errorf("write %q: %w", name, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync bundle: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close bundle: %w", err)
	}
	closed = true
	if err := os.Rename(tmp, output); err != nil {
		return fmt.Errorf("install bundle: %w", err)
	}
	return nil
}

func readBounded(file, name string) ([]byte, error) {
	info, err := os.Lstat(file)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("selected source path %q is not a regular file", name)
	}
	if info.Size() > maxEntryBytes {
		return nil, fmt.Errorf("selected source path %q exceeds size limit", name)
	}
	input, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", name, err)
	}
	defer input.Close()
	data, err := io.ReadAll(io.LimitReader(input, maxEntryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", name, err)
	}
	if int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("selected source path %q was truncated while reading", name)
	}
	if len(data) > maxEntryBytes {
		return nil, fmt.Errorf("selected source path %q exceeds size limit", name)
	}
	return data, nil
}
