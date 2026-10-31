package credrotation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type rotationFixtures struct {
	dir        string
	cert1Path  string
	key1Path   string
	cert2Path  string
	key2Path   string
	headerPath string
	cert1PEM   []byte
	key1PEM    []byte
	cert2PEM   []byte
	key2PEM    []byte
}

var writeClock struct {
	sync.Mutex
	t time.Time
}

func nextWriteTime() time.Time {
	writeClock.Lock()
	defer writeClock.Unlock()
	if writeClock.t.IsZero() {
		writeClock.t = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	writeClock.t = writeClock.t.Add(time.Second)
	return writeClock.t
}

func writeWatchedFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chtimes(path, nextWriteTime(), nextWriteTime()); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

func newRotationFixtures(t *testing.T) rotationFixtures {
	t.Helper()
	dir := t.TempDir()
	cert1, key1 := generateClientPair(t, 101)
	cert2, key2 := generateClientPair(t, 202)
	fx := rotationFixtures{
		dir:        dir,
		cert1Path:  filepath.Join(dir, "client1.crt"),
		key1Path:   filepath.Join(dir, "client1.key"),
		cert2Path:  filepath.Join(dir, "client2.crt"),
		key2Path:   filepath.Join(dir, "client2.key"),
		headerPath: filepath.Join(dir, "auth-header.txt"),
		cert1PEM:   cert1,
		key1PEM:    key1,
		cert2PEM:   cert2,
		key2PEM:    key2,
	}
	writeWatchedFile(t, fx.cert1Path, cert1)
	writeWatchedFile(t, fx.key1Path, key1)
	writeWatchedFile(t, fx.headerPath, []byte("token-generation-1\n"))
	return fx
}

func generateClientPair(t *testing.T, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if _, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey); err != nil {
		t.Fatalf("create ca: %v", err)
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(serial + 1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("generated pair is invalid: %v", err)
	}
	return certPEM, keyPEM
}

func newTestManager(t *testing.T, logger *slog.Logger, spec Spec) *Manager {
	t.Helper()
	loader, err := NewLoader(spec)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	manager, err := NewManager(logger, loader, WithPollInterval(time.Second))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return manager
}

func mtlsSpec(fx rotationFixtures) Spec {
	return Spec{
		Channel:  "main",
		CertPath: fx.cert1Path,
		KeyPath:  fx.key1Path,
		HeaderReferences: map[string]string{
			"Authorization": "file:" + fx.headerPath,
		},
	}
}

func TestSpecValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{name: "cert without key", spec: Spec{CertPath: "a.crt"}, want: "key path is required"},
		{name: "key without cert", spec: Spec{KeyPath: "a.key"}, want: "certificate path is required"},
		{name: "bad header name", spec: Spec{HeaderReferences: map[string]string{"bad name": "v"}}, want: "invalid HTTP header name"},
		{name: "empty file reference", spec: Spec{HeaderReferences: map[string]string{"Authorization": "file:"}}, want: "requires a file path"},
		{name: "empty env reference", spec: Spec{HeaderReferences: map[string]string{"Authorization": "env:"}}, want: "invalid environment reference"},
		{name: "valid empty", spec: Spec{}},
		{name: "valid pair", spec: Spec{CertPath: "a.crt", KeyPath: "a.key"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.spec.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate: unexpected error %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate error = %v, want contains %q", err, tc.want)
			}
		})
	}
}

func TestWatchedFilesDeduplicatesAndSorts(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	spec := Spec{
		CertPath:                  fx.cert1Path,
		KeyPath:                   fx.key1Path,
		HeaderReferences:          map[string]string{"Authorization": "file:" + fx.headerPath},
		DiscoveryHeaderReferences: map[string]string{"X-Discovery": "file:" + fx.headerPath},
	}
	got := spec.WatchedFiles()
	want := []string{fx.headerPath, fx.cert1Path, fx.key1Path}
	if len(got) != len(want) {
		t.Fatalf("WatchedFiles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("WatchedFiles = %v, want %v", got, want)
		}
	}
}

func TestNewManagerFailsClosedOnInvalidInitialGeneration(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	// Certificate 1 paired with key 2 cannot be the first generation.
	spec := Spec{Channel: "main", CertPath: fx.cert1Path, KeyPath: fx.key2Path}
	loader, err := NewLoader(spec)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if _, err := NewManager(slog.Default(), loader); err == nil {
		t.Fatal("NewManager succeeded with mismatched initial pair, want error")
	}
}

func TestRefreshPublishesCompleteGeneration(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	manager := newTestManager(t, discardLogger(), mtlsSpec(fx))

	first := manager.Current()
	if first.Generation() != 1 {
		t.Fatalf("initial generation = %d, want 1", first.Generation())
	}
	if first.Certificate == nil {
		t.Fatal("initial snapshot missing client certificate")
	}
	if got := first.ExtraHeaders["Authorization"]; got != "token-generation-1" {
		t.Fatalf("initial auth header = %q, want token-generation-1", got)
	}

	// Rewrite the full generation: certificate, key, and auth header.
	writeWatchedFile(t, fx.cert1Path, fx.cert2PEM)
	writeWatchedFile(t, fx.key1Path, fx.key2PEM)
	writeWatchedFile(t, fx.headerPath, []byte("token-generation-2\n"))

	var seenDuringCallback uint64
	manager.OnRotated(func(generation uint64) {
		// The new generation must not be observable yet when callbacks run.
		seenDuringCallback = manager.Generation()
	})

	changed, err := manager.Refresh(context.Background())
	if err != nil || !changed {
		t.Fatalf("Refresh changed=%v err=%v, want changed=true", changed, err)
	}
	second := manager.Current()
	if second.Generation() != 2 {
		t.Fatalf("generation after refresh = %d, want 2", second.Generation())
	}
	if seenDuringCallback != 1 {
		t.Fatalf("generation visible during callback = %d, want 1", seenDuringCallback)
	}
	if second.CertIdentity() == first.CertIdentity() {
		t.Fatal("certificate identity did not change after rotation")
	}
	if got := second.ExtraHeaders["Authorization"]; got != "token-generation-2" {
		t.Fatalf("rotated auth header = %q, want token-generation-2", got)
	}
	// Cert and header must come from the same snapshot object: no mix.
	if second.Certificate == nil {
		t.Fatal("rotated snapshot missing client certificate")
	}
}

func TestRefreshWithoutFileChangesIsNoop(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	manager := newTestManager(t, discardLogger(), mtlsSpec(fx))

	for range 2 {
		changed, err := manager.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if changed {
			t.Fatal("Refresh reported change without file updates")
		}
	}
	if manager.Generation() != 1 {
		t.Fatalf("generation = %d, want 1", manager.Generation())
	}
}

func TestBadGenerationRetainsLastGoodVersion(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	manager := newTestManager(t, discardLogger(), mtlsSpec(fx))
	good := manager.Current()

	// New certificate with an invalid key: pair validation must fail.
	writeWatchedFile(t, fx.cert1Path, fx.cert2PEM)
	writeWatchedFile(t, fx.key1Path, []byte("not-a-private-key-BADKEYSECRET"))
	changed, err := manager.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh with invalid key succeeded, want validation error")
	}
	if changed {
		t.Fatal("Refresh reported change for invalid generation")
	}
	retained := manager.Current()
	if retained != good || retained.Generation() != 1 {
		t.Fatal("last good generation was not retained")
	}
	if got := retained.ExtraHeaders["Authorization"]; got != "token-generation-1" {
		t.Fatalf("retained auth header = %q, want token-generation-1", got)
	}

	// Complete the staged update: matching key and new header.
	writeWatchedFile(t, fx.key1Path, fx.key2PEM)
	writeWatchedFile(t, fx.headerPath, []byte("token-generation-2\n"))
	changed, err = manager.Refresh(context.Background())
	if err != nil || !changed {
		t.Fatalf("completed generation Refresh changed=%v err=%v", changed, err)
	}
	if manager.Generation() != 2 {
		t.Fatalf("generation = %d, want 2", manager.Generation())
	}
}

func TestBadHeaderFileRetainsLastGoodVersion(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	manager := newTestManager(t, discardLogger(), mtlsSpec(fx))
	first := manager.Current()

	// A CR/LF in a header value makes the whole generation invalid; the
	// certificate rewrite that ships with it must also stay unpublished.
	writeWatchedFile(t, fx.cert1Path, fx.cert2PEM)
	writeWatchedFile(t, fx.key1Path, fx.key2PEM)
	writeWatchedFile(t, fx.headerPath, []byte("token-generation-2\nExtra: leak"))
	changed, err := manager.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh with multi-line header succeeded, want error")
	}
	if changed {
		t.Fatal("Refresh reported change for invalid generation")
	}
	current := manager.Current()
	if current.Generation() != 1 || current.CertIdentity() != first.CertIdentity() {
		t.Fatal("generation changed after a rejected header update")
	}
	if got := current.ExtraHeaders["Authorization"]; got != "token-generation-1" {
		t.Fatalf("header after rejected update = %q, want token-generation-1", got)
	}
}

func TestStagedWritesRecoverAfterCompletion(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	manager := newTestManager(t, discardLogger(), mtlsSpec(fx))

	// Step 1 of a staged deploy: only the certificate lands. The old key does
	// not match, so the generation is rejected and traffic keeps generation 1.
	writeWatchedFile(t, fx.cert1Path, fx.cert2PEM)
	if changed, err := manager.Refresh(context.Background()); err == nil || changed {
		t.Fatalf("partial cert update: changed=%v err=%v", changed, err)
	}
	if manager.Generation() != 1 {
		t.Fatal("generation advanced during staged cert-only write")
	}

	// Step 2: key and header finish the generation.
	writeWatchedFile(t, fx.key1Path, fx.key2PEM)
	writeWatchedFile(t, fx.headerPath, []byte("token-generation-2\n"))
	changed, err := manager.Refresh(context.Background())
	if err != nil || !changed {
		t.Fatalf("completed staged update: changed=%v err=%v", changed, err)
	}
	if manager.Generation() != 2 {
		t.Fatalf("generation = %d, want 2", manager.Generation())
	}
}

func TestIdenticalContentDoesNotBumpGeneration(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	manager := newTestManager(t, discardLogger(), mtlsSpec(fx))
	first := manager.Current()

	// Rewrite identical bytes with a new mtime (touch, atomic rename of the
	// same content): no new generation.
	writeWatchedFile(t, fx.headerPath, []byte("token-generation-1\n"))
	changed, err := manager.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if changed || manager.Generation() != first.Generation() {
		t.Fatalf("identical content changed generation: changed=%v gen=%d", changed, manager.Generation())
	}
}

func TestEnvAndLiteralHeaderReferences(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	env := map[string]string{"ROTATING_TOKEN": "env-token-1"}
	spec := Spec{
		Channel:   "main",
		CertPath:  fx.cert1Path,
		KeyPath:   fx.key1Path,
		LookupEnv: func(name string) (string, bool) { v, ok := env[name]; return v, ok },
		HeaderReferences: map[string]string{
			"Authorization": "env:ROTATING_TOKEN",
			"X-Static":      "static-value",
		},
	}
	manager := newTestManager(t, discardLogger(), spec)
	snap := manager.Current()
	if snap.ExtraHeaders["Authorization"] != "env-token-1" || snap.ExtraHeaders["X-Static"] != "static-value" {
		t.Fatalf("initial headers = %v", snap.ExtraHeaders)
	}

	env["ROTATING_TOKEN"] = "env-token-2"
	// Only file writes trigger polls; touch the cert pair's stat with the
	// same content to force a generation rebuild that re-resolves env.
	writeWatchedFile(t, fx.cert1Path, fx.cert1PEM)
	writeWatchedFile(t, fx.key1Path, fx.key1PEM)
	changed, err := manager.Refresh(context.Background())
	if err != nil || !changed {
		t.Fatalf("Refresh changed=%v err=%v, want env-driven generation", changed, err)
	}
	snap = manager.Current()
	if snap.ExtraHeaders["Authorization"] != "env-token-2" {
		t.Fatalf("env header = %q, want env-token-2", snap.ExtraHeaders["Authorization"])
	}
	if snap.ExtraHeaders["X-Static"] != "static-value" {
		t.Fatalf("static header = %q, want static-value", snap.ExtraHeaders["X-Static"])
	}
}

func TestDiscoveryHeadersRotateWithSameGeneration(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	discoveryPath := filepath.Join(fx.dir, "discovery.txt")
	writeWatchedFile(t, discoveryPath, []byte("discovery-token-1\n"))
	spec := Spec{
		Channel:                   "main",
		CertPath:                  fx.cert1Path,
		KeyPath:                   fx.key1Path,
		HeaderReferences:          map[string]string{"Authorization": "file:" + fx.headerPath},
		DiscoveryHeaderReferences: map[string]string{"X-Discovery": "file:" + discoveryPath},
	}
	manager := newTestManager(t, discardLogger(), spec)

	writeWatchedFile(t, fx.cert1Path, fx.cert2PEM)
	writeWatchedFile(t, fx.key1Path, fx.key2PEM)
	writeWatchedFile(t, fx.headerPath, []byte("token-generation-2\n"))
	writeWatchedFile(t, discoveryPath, []byte("discovery-token-2\n"))
	if changed, err := manager.Refresh(context.Background()); err != nil || !changed {
		t.Fatalf("Refresh changed=%v err=%v", changed, err)
	}
	snap := manager.Current()
	if snap.ExtraHeaders["Authorization"] != "token-generation-2" {
		t.Fatalf("auth header = %q", snap.ExtraHeaders["Authorization"])
	}
	if snap.DiscoveryExtraHeaders["X-Discovery"] != "discovery-token-2" {
		t.Fatalf("discovery header = %q", snap.DiscoveryExtraHeaders["X-Discovery"])
	}
}

func TestFailedReloadLogsNeverContainSecrets(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	manager := newTestManager(t, logger, mtlsSpec(fx))

	secretHeader := "SECRET-TOKEN-VALUE-9f3e"
	writeWatchedFile(t, fx.headerPath, []byte(secretHeader+"\n"))
	writeWatchedFile(t, fx.key1Path, []byte("-----BEGIN PRIVATE KEY-----\nPRIVATE-KEY-SECRET-MATERIAL-xyz\n-----END PRIVATE KEY-----\n"))
	writeWatchedFile(t, fx.cert1Path, fx.cert2PEM)
	if _, err := manager.Refresh(context.Background()); err == nil {
		t.Fatal("expected invalid generation to fail")
	}
	output := logs.String()
	for _, secret := range []string{secretHeader, "PRIVATE-KEY-SECRET-MATERIAL-xyz"} {
		if strings.Contains(output, secret) {
			t.Fatalf("rotation log output leaked %q: %s", secret, output)
		}
	}

	// Successful rotation logs counts/fingerprints but never header values.
	logs.Reset()
	writeWatchedFile(t, fx.cert1Path, fx.cert2PEM)
	writeWatchedFile(t, fx.key1Path, fx.key2PEM)
	if _, err := manager.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if strings.Contains(logs.String(), secretHeader) {
		t.Fatal("successful rotation log leaked header secret")
	}
}

func TestConcurrentSnapshotReadsDuringRefresh(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	manager := newTestManager(t, discardLogger(), mtlsSpec(fx))

	ctx, cancel := context.WithCancel(context.Background())
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					snap := manager.Current()
					if snap == nil || snap.Certificate == nil {
						t.Error("observed nil snapshot or certificate")
						return
					}
					_ = snap.ExtraHeaders["Authorization"]
				}
			}
		}()
	}

	for i := range 3 {
		if i%2 == 0 {
			writeWatchedFile(t, fx.cert1Path, fx.cert2PEM)
			writeWatchedFile(t, fx.key1Path, fx.key2PEM)
		} else {
			writeWatchedFile(t, fx.cert1Path, fx.cert1PEM)
			writeWatchedFile(t, fx.key1Path, fx.key1PEM)
		}
		writeWatchedFile(t, fx.headerPath, []byte("token-concurrent\n"))
		if _, err := manager.Refresh(context.Background()); err != nil {
			t.Fatalf("Refresh %d: %v", i, err)
		}
	}
	cancel()
	readers.Wait()
}

func TestRunStopsOnContextCancellation(t *testing.T) {
	t.Parallel()
	fx := newRotationFixtures(t)
	manager := newTestManager(t, discardLogger(), mtlsSpec(fx))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		manager.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}
