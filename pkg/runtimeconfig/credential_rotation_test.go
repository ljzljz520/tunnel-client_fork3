package runtimeconfig

import (
	"strings"
	"testing"
	"time"

	"github.com/openai/tunnel-client/pkg/types"
)

func rotationBaseConfig(certPath, keyPath, headerPath string) string {
	return `
config_version: 2
control_plane:
  tunnel_id: tunnel_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  api_key: env:CONTROL_PLANE_API_KEY
mcp:
  server_urls:
    - url: https://mcp.example.invalid/mcp
  client_cert: ` + certPath + `
  client_key: ` + keyPath + `
  extra_headers:
    Authorization: file:` + headerPath + `
`
}

func loadRotationConfig(t *testing.T, yamlConfig string, env map[string]string, args ...string) *MCPConfig {
	t.Helper()
	configPath := writeRuntimeConfig(t, yamlConfig)
	fs := runtimeFlagSet(t, FlavorRuntime, append([]string{"--config", configPath}, args...)...)
	cfg, err := LoadFromFlagSet(fs, lookupEnvMap(env))
	if err != nil {
		t.Fatalf("LoadFromFlagSet: %v", err)
	}
	return &cfg.MCP
}

func TestCredentialRotationYAMLBuildsSpec(t *testing.T) {
	t.Parallel()
	certPath, keyPath := writeTempClientCertPair(t)
	headerPath := writeTempSecretFile(t, "yaml-secret\n")
	config := rotationBaseConfig(certPath, keyPath, headerPath) + `
  credential_rotation:
    enabled: true
    poll_interval: 5s
`
	mcp := loadRotationConfig(t, config, map[string]string{"CONTROL_PLANE_API_KEY": testAPIKey})

	if !mcp.CredentialRotation.Enabled {
		t.Fatal("credential rotation not enabled from YAML")
	}
	if mcp.CredentialRotation.PollInterval != 5*time.Second {
		t.Fatalf("poll interval = %s, want 5s", mcp.CredentialRotation.PollInterval)
	}
	if got := mcp.ExtraHeaders["Authorization"]; got != "yaml-secret" {
		t.Fatalf("resolved auth header = %q, want yaml-secret", got)
	}
	if got := mcp.ExtraHeaderReferences["Authorization"]; got != "file:"+headerPath {
		t.Fatalf("raw auth header reference = %q, want file:%s", got, headerPath)
	}

	binding := mcp.MainChannelBinding()
	if binding == nil {
		t.Fatal("missing main channel binding")
	}
	spec, ok := mcp.CredentialRotationSpec(*binding)
	if !ok {
		t.Fatal("expected watchable credential rotation spec")
	}
	if spec.CertPath != certPath || spec.KeyPath != keyPath {
		t.Fatalf("spec cert/key = %q,%q", spec.CertPath, spec.KeyPath)
	}
	watched := strings.Join(spec.WatchedFiles(), ",")
	for _, path := range []string{certPath, keyPath, headerPath} {
		if !strings.Contains(watched, path) {
			t.Fatalf("watched files %q missing %q", watched, path)
		}
	}
}

func TestCredentialRotationEnvironmentAndFlag(t *testing.T) {
	t.Parallel()
	certPath, keyPath := writeTempClientCertPair(t)
	headerPath := writeTempSecretFile(t, "env-secret\n")
	fs := runtimeFlagSet(t, FlavorRuntime,
		"--control-plane.tunnel-id", testTunnelID,
		"--mcp.server-url", "https://mcp.example.invalid/mcp",
		"--mcp.client-cert", certPath,
		"--mcp.client-key", keyPath,
		"--mcp.extra-headers", "Authorization: file:"+headerPath,
		"--mcp.credential-rotation",
		"--mcp.credential-rotation-interval", "2s",
	)
	cfg, err := LoadFromFlagSet(fs, lookupEnvMap(map[string]string{"CONTROL_PLANE_API_KEY": testAPIKey}))
	if err != nil {
		t.Fatalf("LoadFromFlagSet: %v", err)
	}
	if !cfg.MCP.CredentialRotation.Enabled || cfg.MCP.CredentialRotation.PollInterval != 2*time.Second {
		t.Fatalf("rotation config = %+v", cfg.MCP.CredentialRotation)
	}
	spec, ok := cfg.MCP.CredentialRotationSpec(*cfg.MCP.MainChannelBinding())
	if !ok || len(spec.WatchedFiles()) != 3 {
		t.Fatalf("rotation spec = %+v ok=%v", spec, ok)
	}
}

func TestCredentialRotationEnvironmentVariables(t *testing.T) {
	t.Parallel()
	certPath, keyPath := writeTempClientCertPair(t)
	headerPath := writeTempSecretFile(t, "env-secret\n")
	fs := runtimeFlagSet(t, FlavorRuntime)
	env := map[string]string{
		"CONTROL_PLANE_API_KEY":            testAPIKey,
		"CONTROL_PLANE_TUNNEL_ID":          testTunnelID,
		"MCP_SERVER_URL":                   "https://mcp.example.invalid/mcp",
		"MCP_CLIENT_CERT":                  certPath,
		"MCP_CLIENT_KEY":                   keyPath,
		"MCP_EXTRA_HEADERS":                "Authorization: file:" + headerPath,
		"MCP_CREDENTIAL_ROTATION":          "true",
		"MCP_CREDENTIAL_ROTATION_INTERVAL": "3s",
	}
	cfg, err := LoadFromFlagSet(fs, lookupEnvMap(env))
	if err != nil {
		t.Fatalf("LoadFromFlagSet: %v", err)
	}
	if !cfg.MCP.CredentialRotation.Enabled || cfg.MCP.CredentialRotation.PollInterval != 3*time.Second {
		t.Fatalf("rotation config = %+v", cfg.MCP.CredentialRotation)
	}
}

func TestCredentialRotationRequiresFileBackedCredential(t *testing.T) {
	t.Parallel()

	t.Run("literal headers only", func(t *testing.T) {
		t.Parallel()
		config := `
config_version: 2
control_plane:
  tunnel_id: tunnel_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  api_key: env:CONTROL_PLANE_API_KEY
mcp:
  server_urls:
    - url: https://mcp.example.invalid/mcp
  extra_headers:
    Authorization: static-token
  credential_rotation:
    enabled: true
`
		configPath := writeRuntimeConfig(t, config)
		fs := runtimeFlagSet(t, FlavorRuntime, "--config", configPath)
		_, err := LoadFromFlagSet(fs, lookupEnvMap(map[string]string{"CONTROL_PLANE_API_KEY": testAPIKey}))
		if err == nil || !strings.Contains(err.Error(), "file-backed credential") {
			t.Fatalf("error = %v, want file-backed credential requirement", err)
		}
	})

	t.Run("stdio only binding", func(t *testing.T) {
		t.Parallel()
		headerPath := writeTempSecretFile(t, "s\n")
		fs := runtimeFlagSet(t, FlavorRuntime,
			"--control-plane.tunnel-id", testTunnelID,
			"--mcp.command", "channel=main,command=/bin/true",
			"--mcp.extra-headers", "Authorization: file:"+headerPath,
			"--mcp.credential-rotation",
		)
		_, err := LoadFromFlagSet(fs, lookupEnvMap(map[string]string{"CONTROL_PLANE_API_KEY": testAPIKey}))
		if err == nil || !strings.Contains(err.Error(), "file-backed credential") {
			t.Fatalf("error = %v, want file-backed credential requirement", err)
		}
	})
}

func TestCredentialRotationRejectsInvalidInterval(t *testing.T) {
	t.Parallel()
	certPath, keyPath := writeTempClientCertPair(t)

	t.Run("below minimum flag", func(t *testing.T) {
		t.Parallel()
		fs := runtimeFlagSet(t, FlavorRuntime,
			"--control-plane.tunnel-id", testTunnelID,
			"--mcp.server-url", "https://mcp.example.invalid/mcp",
			"--mcp.client-cert", certPath,
			"--mcp.client-key", keyPath,
			"--mcp.credential-rotation",
			"--mcp.credential-rotation-interval", "500ms",
		)
		if _, err := LoadFromFlagSet(fs, lookupEnvMap(map[string]string{"CONTROL_PLANE_API_KEY": testAPIKey})); err == nil {
			t.Fatal("expected sub-second interval to be rejected")
		}
	})

	t.Run("malformed environment", func(t *testing.T) {
		t.Parallel()
		fs := runtimeFlagSet(t, FlavorRuntime,
			"--control-plane.tunnel-id", testTunnelID,
			"--mcp.server-url", "https://mcp.example.invalid/mcp",
			"--mcp.client-cert", certPath,
			"--mcp.client-key", keyPath,
		)
		env := map[string]string{
			"CONTROL_PLANE_API_KEY":            testAPIKey,
			"MCP_CREDENTIAL_ROTATION":          "true",
			"MCP_CREDENTIAL_ROTATION_INTERVAL": "not-a-duration",
		}
		if _, err := LoadFromFlagSet(fs, lookupEnvMap(env)); err == nil {
			t.Fatal("expected malformed interval to be rejected")
		}
	})
}

func TestCredentialRotationDisabledLeavesSpecUnavailable(t *testing.T) {
	t.Parallel()
	certPath, keyPath := writeTempClientCertPair(t)
	headerPath := writeTempSecretFile(t, "env-secret\n")
	mcp := loadRotationConfig(t, rotationBaseConfig(certPath, keyPath, headerPath),
		map[string]string{"CONTROL_PLANE_API_KEY": testAPIKey})
	if mcp.CredentialRotation.Enabled {
		t.Fatal("rotation must be opt-in")
	}
	if mcp.CredentialRotation.PollInterval != DefaultMCPCredentialRotationPollInterval {
		t.Fatalf("default poll interval = %s", mcp.CredentialRotation.PollInterval)
	}
	if _, ok := mcp.CredentialRotationSpec(*mcp.MainChannelBinding()); ok {
		t.Fatal("rotation spec must be unavailable when disabled")
	}
}

func TestCredentialRotationSpecIsolatedPerChannel(t *testing.T) {
	t.Parallel()
	certA, keyA := writeTempClientCertPair(t)
	certB, keyB := writeTempClientCertPair(t)
	fs := runtimeFlagSet(t, FlavorRuntime,
		"--control-plane.tunnel-id", testTunnelID,
		"--mcp.server-url", "https://mcp.example.invalid/mcp",
		"--mcp.server-url", "channel=alpha,url=https://mcp-a.example.invalid/mcp,client-cert="+certA+",client-key="+keyA,
		"--mcp.server-url", "channel=bravo,url=https://mcp-b.example.invalid/mcp,client-cert="+certB+",client-key="+keyB,
		"--mcp.credential-rotation",
	)
	cfg, err := LoadFromFlagSet(fs, lookupEnvMap(map[string]string{"CONTROL_PLANE_API_KEY": testAPIKey}))
	if err != nil {
		t.Fatalf("LoadFromFlagSet: %v", err)
	}
	bindingA := cfg.MCP.ChannelBindingFor(types.Channel("alpha"))
	bindingB := cfg.MCP.ChannelBindingFor(types.Channel("bravo"))
	if bindingA == nil || bindingB == nil {
		t.Fatal("missing channel bindings")
	}
	specA, ok := cfg.MCP.CredentialRotationSpec(*bindingA)
	if !ok {
		t.Fatal("spec A unavailable")
	}
	specB, ok := cfg.MCP.CredentialRotationSpec(*bindingB)
	if !ok {
		t.Fatal("spec B unavailable")
	}
	if specA.CertPath != certA || specA.KeyPath != keyA {
		t.Fatalf("spec A cert = %q,%q want %q,%q", specA.CertPath, specA.KeyPath, certA, keyA)
	}
	if specB.CertPath != certB || specB.KeyPath != keyB {
		t.Fatalf("spec B cert = %q,%q want %q,%q", specB.CertPath, specB.KeyPath, certB, keyB)
	}
	if specA.CertPath == specB.CertPath {
		t.Fatal("channel credential specs share a certificate path")
	}
}

func TestBuildExtraHeaderSetsPreservesReferences(t *testing.T) {
	t.Parallel()
	headerPath := writeTempSecretFile(t, "file-token\n")

	t.Run("flags", func(t *testing.T) {
		t.Parallel()
		fs := runtimeFlagSet(t, FlavorRuntime,
			"--mcp.extra-headers", "Authorization: file:"+headerPath,
			"--mcp.extra-headers", "X-Static: literal",
		)
		resolved, references, err := buildExtraHeaderSets(fs, func(string) (string, bool) { return "", false }, "mcp.extra-headers", "MCP_EXTRA_HEADERS")
		if err != nil {
			t.Fatalf("buildExtraHeaderSets: %v", err)
		}
		if resolved["Authorization"] != "file-token" {
			t.Fatalf("resolved = %v", resolved)
		}
		if references["Authorization"] != "file:"+headerPath || references["X-Static"] != "literal" {
			t.Fatalf("references = %v", references)
		}
	})

	t.Run("yaml encoded env map", func(t *testing.T) {
		t.Parallel()
		encoded, err := encodeExtraHeaderMap("mcp.extra_headers", map[string]string{
			"Authorization": "file:" + headerPath,
		})
		if err != nil {
			t.Fatalf("encodeExtraHeaderMap: %v", err)
		}
		fs := runtimeFlagSet(t, FlavorRuntime)
		resolved, references, err := buildExtraHeaderSets(fs, lookupEnvMap(map[string]string{"MCP_EXTRA_HEADERS": encoded}), "mcp.extra-headers", "MCP_EXTRA_HEADERS")
		if err != nil {
			t.Fatalf("buildExtraHeaderSets: %v", err)
		}
		if resolved["Authorization"] != "file-token" {
			t.Fatalf("resolved = %v", resolved)
		}
		if references["Authorization"] != "file:"+headerPath {
			t.Fatalf("references = %v", references)
		}
	})
}
