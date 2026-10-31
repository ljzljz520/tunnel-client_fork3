package runtimeconfig

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/openai/tunnel-client/pkg/credrotation"
)

const (
	// DefaultMCPCredentialRotationPollInterval is the default cadence of
	// optional MCP credential file hot rotation checks.
	DefaultMCPCredentialRotationPollInterval = 30 * time.Second
	minMCPCredentialRotationPollInterval     = time.Second
)

// CredentialRotationConfig controls optional hot rotation of file-backed MCP
// credentials (client certificate/key pairs and file: auth headers).
//
// When enabled, every watched file change reloads the complete channel
// credential set as one generation: certificate, key, and authentication
// headers validate together and switch atomically. Invalid generations keep
// the last validated version; new requests use the new identity while
// in-flight requests continue with the generation they started with.
type CredentialRotationConfig struct {
	Enabled      bool
	PollInterval time.Duration
}

// registerCredentialRotationFlags attaches the opt-in MCP credential rotation
// flags to the shared runtime flag set.
func registerCredentialRotationFlags(fs *pflag.FlagSet) {
	if fs == nil {
		return
	}
	fs.Bool("mcp.credential-rotation", false, "Hot-reload file-backed MCP credentials (client cert/key, file: auth headers) as atomically validated generations (env.MCP_CREDENTIAL_ROTATION)")
	fs.Duration("mcp.credential-rotation-interval", DefaultMCPCredentialRotationPollInterval, "Interval between MCP credential file checks when mcp.credential-rotation is enabled (env.MCP_CREDENTIAL_ROTATION_INTERVAL)")
}

func buildCredentialRotationConfig(fs *pflag.FlagSet, lookupEnv func(string) (string, bool)) (CredentialRotationConfig, error) {
	enabled, err := getBool(fs, lookupEnv, "mcp.credential-rotation", "MCP_CREDENTIAL_ROTATION")
	if err != nil {
		return CredentialRotationConfig{}, err
	}
	interval := DefaultMCPCredentialRotationPollInterval
	raw := firstSet(
		getValue(fs, "mcp.credential-rotation-interval"),
		envOrDefault(lookupEnv, "MCP_CREDENTIAL_ROTATION_INTERVAL", ""),
	)
	if strings.TrimSpace(raw) != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return CredentialRotationConfig{}, fmt.Errorf("invalid mcp.credential-rotation-interval: %w", err)
		}
		if parsed < minMCPCredentialRotationPollInterval {
			return CredentialRotationConfig{}, fmt.Errorf("mcp.credential-rotation-interval must be at least %s", minMCPCredentialRotationPollInterval)
		}
		interval = parsed
	}
	return CredentialRotationConfig{Enabled: enabled, PollInterval: interval}, nil
}

// buildExtraHeaderSets returns both the resolved header values and the raw
// operator references (literal, env:, file:). The raw map feeds credential
// hot rotation so file-backed header values can be re-read without restart.
func buildExtraHeaderSets(fs *pflag.FlagSet, lookupEnv func(string) (string, bool), flagName, envName string) (map[string]string, map[string]string, error) {
	var raw []string
	if flag := fs.Lookup(flagName); flag != nil && flag.Changed {
		values, err := fs.GetStringArray(flagName)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid value for --%s: %w", flagName, err)
		}
		raw = append(raw, values...)
	} else if envVal, ok := lookupEnv(envName); ok && envVal != "" {
		if strings.HasPrefix(envVal, encodedExtraHeaderMapPrefix) {
			references, err := decodeExtraHeaderReferenceMap(flagName, envVal)
			if err != nil {
				return nil, nil, err
			}
			resolved, err := resolveHeaderReferenceMap(flagName, references, lookupEnv)
			if err != nil {
				return nil, nil, err
			}
			return resolved, references, nil
		}
		raw = splitHeaderList(envVal)
	}
	if len(raw) == 0 {
		return nil, nil, nil
	}
	return parseHeaderListWithReferences(raw, lookupEnv, flagName)
}

func parseHeaderListWithReferences(values []string, lookupEnv func(string) (string, bool), source string) (map[string]string, map[string]string, error) {
	resolved := make(map[string]string, len(values))
	references := make(map[string]string, len(values))
	for _, value := range values {
		key, rawValue, err := parseHeader(value)
		if err != nil {
			return nil, nil, err
		}
		if key == "" {
			continue
		}
		canonical := http.CanonicalHeaderKey(key)
		references[canonical] = rawValue
		parsed, err := resolveHeaderValue(source+"."+canonical, rawValue, lookupEnv)
		if err != nil {
			return nil, nil, err
		}
		resolved[canonical] = parsed
	}
	normalized, err := NormalizeExtraHeaders(source, resolved)
	if err != nil {
		return nil, nil, err
	}
	rawNormalized, err := NormalizeExtraHeaders(source, references)
	if err != nil {
		return nil, nil, err
	}
	return normalized, rawNormalized, nil
}

func resolveHeaderReferenceMap(source string, references map[string]string, lookupEnv func(string) (string, bool)) (map[string]string, error) {
	resolved := make(map[string]string, len(references))
	for name, value := range references {
		parsed, err := resolveHeaderValue(source+"."+name, value, lookupEnv)
		if err != nil {
			return nil, err
		}
		resolved[name] = parsed
	}
	return NormalizeExtraHeaders(source, resolved)
}

// decodeExtraHeaderReferenceMap decodes the internal structured header map
// produced by YAML/profile parsing without resolving env:/file: references.
func decodeExtraHeaderReferenceMap(source, raw string) (map[string]string, error) {
	encoded := make(map[string][]byte)
	if err := json.Unmarshal([]byte(strings.TrimPrefix(raw, encodedExtraHeaderMapPrefix)), &encoded); err != nil {
		return nil, fmt.Errorf("decode %s: invalid internal header map", source)
	}
	references := make(map[string]string, len(encoded))
	for name, value := range encoded {
		references[http.CanonicalHeaderKey(name)] = string(value)
	}
	return NormalizeExtraHeaders(source, references)
}

// CredentialRotationSpec builds the watched credential generation spec for
// one channel binding. ok is false when the binding has no file-backed
// credentials and therefore nothing to rotate.
func (c *MCPConfig) CredentialRotationSpec(binding MCPChannelBinding) (spec credrotation.Spec, ok bool) {
	if c == nil || !c.CredentialRotation.Enabled {
		return credrotation.Spec{}, false
	}
	spec = credrotation.Spec{
		Channel:                   string(binding.Channel.Canonical()),
		HeaderReferences:          cloneHeaderReferences(c.ExtraHeaderReferences),
		DiscoveryHeaderReferences: cloneHeaderReferences(c.DiscoveryExtraHeaderReferences),
	}
	if binding.ClientCertificate != nil {
		spec.CertPath = binding.ClientCertificate.CertPath
		spec.KeyPath = binding.ClientCertificate.KeyPath
	}
	return spec, len(spec.WatchedFiles()) > 0
}

func cloneHeaderReferences(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

// validateCredentialRotation verifies that enabled rotation has at least one
// file-backed credential to watch on an http-streamable binding.
func (c *MCPConfig) validateCredentialRotation() error {
	if c == nil || !c.CredentialRotation.Enabled {
		return nil
	}
	if c.CredentialRotation.PollInterval < minMCPCredentialRotationPollInterval {
		return fmt.Errorf("mcp.credential-rotation-interval must be at least %s", minMCPCredentialRotationPollInterval)
	}
	for i := range c.ChannelBindings {
		binding := &c.ChannelBindings[i]
		if binding.TransportKind != MCPTransportHTTPStreamable {
			continue
		}
		if _, ok := c.CredentialRotationSpec(*binding); ok {
			return nil
		}
	}
	return fmt.Errorf("mcp.credential-rotation requires at least one file-backed credential (client cert/key or file: auth header) on an http-streamable binding")
}
