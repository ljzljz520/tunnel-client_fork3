// Package credrotation implements optional hot rotation of file-backed
// credentials: mTLS client certificate/key pairs and static authentication
// headers.
//
// A rotation generation is the complete credential set of one channel. Files
// are re-read together and the whole generation is validated before it is
// published, so a caller can never observe a new certificate paired with an
// old key or headers from a different generation. Failed reloads retain the
// last validated generation, which continues to serve in-flight traffic.
package credrotation

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
)

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Spec describes the file-backed credential set watched for one channel.
//
// CertPath and KeyPath must either both be empty or both be set. Header
// reference values preserve the operator spelling from configuration: literal
// values, "env:NAME" references, or "file:/path" references. Only file:
// references and the certificate/key paths are watched on disk; env and
// literal references are re-resolved as part of every generation validation.
type Spec struct {
	// Channel is the diagnostic label of the owning channel.
	Channel string
	// CertPath and KeyPath are the PEM client certificate and private key.
	CertPath string
	KeyPath  string
	// HeaderReferences maps canonical header names to raw reference values.
	HeaderReferences map[string]string
	// DiscoveryHeaderReferences is the discovery-only counterpart.
	DiscoveryHeaderReferences map[string]string
	// LookupEnv resolves "env:" references. nil means os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

// WatchedFiles returns the de-duplicated, sorted set of files that make up a
// reloadable generation: the certificate and key plus every file: header
// reference.
func (s Spec) WatchedFiles() []string {
	paths := make([]string, 0, 2+len(s.HeaderReferences)+len(s.DiscoveryHeaderReferences))
	if s.CertPath != "" {
		paths = append(paths, s.CertPath)
	}
	if s.KeyPath != "" {
		paths = append(paths, s.KeyPath)
	}
	for _, refs := range []map[string]string{s.HeaderReferences, s.DiscoveryHeaderReferences} {
		for _, raw := range refs {
			if path, ok := fileReferencePath(raw); ok {
				paths = append(paths, path)
			}
		}
	}
	slices.Sort(paths)
	return slices.Compact(paths)
}

// Validate reports structural errors in the spec. It never reads the
// referenced files; callers run an initial Load to fail on invalid contents.
func (s Spec) Validate() error {
	certPath := strings.TrimSpace(s.CertPath)
	keyPath := strings.TrimSpace(s.KeyPath)
	switch {
	case certPath == "" && keyPath == "":
	case certPath == "":
		return errors.New("credential rotation: client certificate path is required when key path is set")
	case keyPath == "":
		return errors.New("credential rotation: client key path is required when certificate path is set")
	}
	if err := validateHeaderReferences("auth header", s.HeaderReferences); err != nil {
		return err
	}
	if err := validateHeaderReferences("discovery auth header", s.DiscoveryHeaderReferences); err != nil {
		return err
	}
	return nil
}

// Snapshot is one validated, immutable credential generation. Callers must not
// mutate the header maps. Obtain a fresh snapshot per logical request so the
// certificate and headers presented on that request always belong to the same
// generation.
type Snapshot struct {
	// Certificate is the validated mTLS pair, or nil when mTLS is unused.
	Certificate *tls.Certificate
	// ExtraHeaders and DiscoveryExtraHeaders are canonical and fully resolved.
	ExtraHeaders          map[string]string
	DiscoveryExtraHeaders map[string]string

	generation uint64
	// certIdentity is a non-reversible fingerprint used only in diagnostics.
	certIdentity string
}

// Generation returns the monotonically increasing generation number.
func (s *Snapshot) Generation() uint64 {
	if s == nil {
		return 0
	}
	return s.generation
}

// CertIdentity returns a short non-reversible fingerprint of the leaf
// certificate for diagnostic logging, or "" when mTLS is unused.
func (s *Snapshot) CertIdentity() string {
	if s == nil {
		return ""
	}
	return s.certIdentity
}

// Loader re-reads and validates a complete generation from a Spec.
type Loader struct {
	spec      Spec
	lookupEnv func(string) (string, bool)
}

// NewLoader validates the spec structurally and returns a generation loader.
func NewLoader(spec Spec) (*Loader, error) {
	spec.CertPath = strings.TrimSpace(spec.CertPath)
	spec.KeyPath = strings.TrimSpace(spec.KeyPath)
	spec.Channel = strings.TrimSpace(spec.Channel)
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	lookupEnv := spec.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	return &Loader{spec: spec, lookupEnv: lookupEnv}, nil
}

// Spec returns the loader's spec.
func (l *Loader) Spec() Spec {
	if l == nil {
		return Spec{}
	}
	return l.spec
}

// Load reads every file-backed credential and validates the resulting set as
// one generation. It is all-or-nothing: any unreadable file, mismatched
// certificate/key pair, or invalid header aborts the load and returns an
// error without producing a partial snapshot.
//
// The returned fingerprints contain content hashes of every watched file; a
// caller skips generation publication when fingerprints are unchanged.
func (l *Loader) Load() (*Snapshot, map[string]string, error) {
	if l == nil {
		return nil, nil, errors.New("credential rotation: nil loader")
	}

	// Resolve and validate both header sets before touching the certificate
	// so a rejected generation never exposes half-checked material.
	headers, err := l.resolveHeaders("mcp auth headers", l.spec.HeaderReferences)
	if err != nil {
		return nil, nil, err
	}
	discoveryHeaders, err := l.resolveHeaders("mcp discovery auth headers", l.spec.DiscoveryHeaderReferences)
	if err != nil {
		return nil, nil, err
	}

	var certificate *tls.Certificate
	var identity string
	if l.spec.CertPath != "" {
		pair, err := tls.LoadX509KeyPair(l.spec.CertPath, l.spec.KeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("load client certificate/key pair: %w", err)
		}
		identity = certificateIdentity(pair)
		certificate = &pair
	}

	fingerprints, err := l.fingerprintFiles()
	if err != nil {
		return nil, nil, err
	}

	return &Snapshot{
		Certificate:           certificate,
		ExtraHeaders:          headers,
		DiscoveryExtraHeaders: discoveryHeaders,
		certIdentity:          identity,
	}, fingerprints, nil
}

func (l *Loader) resolveHeaders(source string, refs map[string]string) (map[string]string, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	headers := make(map[string]string, len(refs))
	for name, raw := range refs {
		value, err := resolveReference(source+"."+name, raw, l.lookupEnv)
		if err != nil {
			return nil, err
		}
		headers[name] = value
	}
	return normalizeHeaders(source, headers)
}

func (l *Loader) fingerprintFiles() (map[string]string, error) {
	fingerprints := make(map[string]string)
	for _, path := range l.spec.WatchedFiles() {
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read credential file %q: %w", path, err)
		}
		sum := sha256.Sum256(contents)
		fingerprints[path] = hex.EncodeToString(sum[:])
	}
	return fingerprints, nil
}

func certificateIdentity(pair tls.Certificate) string {
	if len(pair.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(pair.Certificate[0])
	return hex.EncodeToString(sum[:8])
}

func fileReferencePath(raw string) (string, bool) {
	if path, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(raw)), "file:"); ok {
		path = strings.TrimSpace(raw[len("file:"):])
		if path == "" {
			return "", false
		}
		return path, true
	}
	return "", false
}

// resolveReference resolves a literal, "env:NAME", or "file:/path" reference
// with the same non-empty and CR/LF guards used by runtime configuration.
func resolveReference(source, raw string, lookupEnv func(string) (string, bool)) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%s cannot be empty", source)
	}
	lower := strings.ToLower(raw)
	var value string
	switch {
	case strings.HasPrefix(lower, "env:"):
		name := strings.TrimSpace(raw[len("env:"):])
		if name == "" {
			return "", fmt.Errorf("invalid %s reference: environment variable name is required", source)
		}
		envValue, ok := lookupEnv(name)
		if !ok {
			return "", fmt.Errorf("invalid %s reference: environment variable %q is not set", source, name)
		}
		value = strings.TrimSpace(envValue)
	case strings.HasPrefix(lower, "file:"):
		path := strings.TrimSpace(raw[len("file:"):])
		if path == "" {
			return "", fmt.Errorf("invalid %s reference: file path is required", source)
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s value file %q: %w", source, path, err)
		}
		value = trimOneTrailingLineEnding(string(contents))
	default:
		value = raw
	}
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("invalid %s reference: resolved value is empty", source)
	}
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("invalid %s reference: resolved value cannot contain CR or LF", source)
	}
	return value, nil
}

func trimOneTrailingLineEnding(value string) string {
	switch {
	case strings.HasSuffix(value, "\r\n"):
		return strings.TrimSuffix(value, "\r\n")
	case strings.HasSuffix(value, "\n"):
		return strings.TrimSuffix(value, "\n")
	case strings.HasSuffix(value, "\r"):
		return strings.TrimSuffix(value, "\r")
	default:
		return value
	}
}

func validateHeaderReferences(kind string, refs map[string]string) error {
	for name, raw := range refs {
		if !validHTTPHeaderFieldName(name) {
			return fmt.Errorf("credential rotation: %s has invalid HTTP header name %q", kind, name)
		}
		canonical := http.CanonicalHeaderKey(name)
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return fmt.Errorf("credential rotation: %s %q cannot be empty", kind, canonical)
		}
		lower := strings.ToLower(raw)
		if strings.HasPrefix(lower, "env:") {
			envName := strings.TrimSpace(raw[len("env:"):])
			if envName == "" || !envNamePattern.MatchString(envName) {
				return fmt.Errorf("credential rotation: %s %q has an invalid environment reference", kind, canonical)
			}
			continue
		}
		if strings.HasPrefix(lower, "file:") {
			if strings.TrimSpace(raw[len("file:"):]) == "" {
				return fmt.Errorf("credential rotation: %s %q requires a file path", kind, canonical)
			}
			continue
		}
		if !validHTTPHeaderFieldValue(raw) {
			return fmt.Errorf("credential rotation: %s %q has an invalid static value", kind, canonical)
		}
	}
	return nil
}

// normalizeHeaders validates resolved headers and rejects conflicting
// case-variant names. It never includes values in error messages.
func normalizeHeaders(source string, headers map[string]string) (map[string]string, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	normalized := make(map[string]string, len(headers))
	for name, value := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if !validHTTPHeaderFieldValue(value) {
			return nil, fmt.Errorf("%s contains invalid HTTP header value for %q", source, canonical)
		}
		if existing, ok := normalized[canonical]; ok && existing != value {
			return nil, fmt.Errorf("%s contains conflicting values for case-insensitive HTTP header %q", source, canonical)
		}
		normalized[canonical] = value
	}
	return normalized, nil
}

func validHTTPHeaderFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func validHTTPHeaderFieldValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < ' ' && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}
