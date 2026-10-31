package mcpclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/openai/tunnel-client/pkg/headerscope"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/tlsconfig"
	"github.com/openai/tunnel-client/pkg/types"
)

// rotationWriteClock guarantees strictly increasing mtimes across files and
// tests so the manager's stat pre-check always observes rewrites, even when
// two writes land inside one filesystem timestamp tick.
var rotationWriteClock struct {
	sync.Mutex
	t time.Time
}

func nextRotationWriteTime() time.Time {
	rotationWriteClock.Lock()
	defer rotationWriteClock.Unlock()
	if rotationWriteClock.t.IsZero() {
		rotationWriteClock.t = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	rotationWriteClock.t = rotationWriteClock.t.Add(time.Second)
	return rotationWriteClock.t
}

func writeRotationFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	written := nextRotationWriteTime()
	if err := os.Chtimes(path, written, written); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

func mintClientCertificatePEM(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: fmt.Sprintf("test-client-%d", serial)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
	if certPEM == nil || keyPEM == nil {
		t.Fatalf("encode client certificate PEM")
	}
	return certPEM, keyPEM
}

func newRotationTestFactory(t *testing.T, cfg *runtimeconfig.MCPConfig, bundle *tlsconfig.Bundle) *ChannelTransportFactory {
	t.Helper()
	factory, err := newChannelTransportFactory(channelTransportFactoryParams{
		Config:        cfg,
		Logging:       &runtimeconfig.LoggingConfig{},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		MeterProvider: sdkmetric.NewMeterProvider(),
		TLSBundle:     bundle,
	})
	if err != nil {
		t.Fatalf("newChannelTransportFactory: %v", err)
	}
	t.Cleanup(factory.stopCredentialRotation)
	return factory
}

func newRotationMTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, *x509.Certificate, *rsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	caCert, caKey, caPEM := generateCA(t)
	serverCert := generateSignedLeaf(t, caCert, caKey, "mcp-server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	server := httptest.NewUnstartedServer(handler)
	// Force HTTP/1.1 so per-generation connection pools are observable through
	// stable client-side RemoteAddr values.
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    mustPool(t, caPEM),
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, caCert, caKey, mustPool(t, caPEM)
}

func mustPool(t *testing.T, caPEM []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("append CA PEM")
	}
	return pool
}

func rotationBinding(channel types.Channel, serverURL *url.URL, certPath, keyPath string) runtimeconfig.MCPChannelBinding {
	return runtimeconfig.MCPChannelBinding{
		Channel:       channel,
		TransportKind: runtimeconfig.MCPTransportHTTPStreamable,
		ServerURL:     serverURL,
		ClientCertificate: &tlsconfig.ClientCertificate{
			CertPath: certPath,
			KeyPath:  keyPath,
		},
	}
}

func rotationConfig(bindings []runtimeconfig.MCPChannelBinding, extra, discovery map[string]string) *runtimeconfig.MCPConfig {
	return &runtimeconfig.MCPConfig{
		ChannelBindings:                bindings,
		ExtraHeaderReferences:          extra,
		DiscoveryExtraHeaderReferences: discovery,
		CredentialRotation: runtimeconfig.CredentialRotationConfig{
			Enabled:      true,
			PollInterval: time.Second,
		},
	}
}

func (f *ChannelTransportFactory) rotatorForTest(t *testing.T, channel string) *credentialRotator {
	t.Helper()
	f.mu.Lock()
	rotator := f.rotators[channel]
	f.mu.Unlock()
	if rotator == nil {
		t.Fatalf("no credential rotator for channel %q", channel)
	}
	return rotator
}

func refreshRotation(t *testing.T, rotator *credentialRotator) bool {
	t.Helper()
	changed, err := rotator.manager.Refresh(context.Background())
	if err != nil {
		t.Fatalf("credential refresh: %v", err)
	}
	return changed
}

func expectRefreshError(t *testing.T, rotator *credentialRotator, want string) {
	t.Helper()
	changed, err := rotator.manager.Refresh(context.Background())
	if err == nil {
		t.Fatalf("expected refresh error containing %q, got nil", want)
	}
	if got := err.Error(); !bytes.Contains([]byte(got), []byte(want)) {
		t.Fatalf("refresh error = %q, want substring %q", got, want)
	}
	if changed {
		t.Fatalf("failed refresh must not publish a generation")
	}
}

// identityRecord is one server-side observation of a request's credentials.
type identityRecord struct {
	remoteAddr string
	serial     int64
	auth       string
	discovery  string
}

type identityRecorder struct {
	mu      sync.Mutex
	records []identityRecord
}

func (r *identityRecorder) snapshot() []identityRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]identityRecord, len(r.records))
	copy(out, r.records)
	return out
}

func (r *identityRecorder) record(req *http.Request) {
	record := identityRecord{
		remoteAddr: req.RemoteAddr,
		auth:       req.Header.Get("Authorization"),
		discovery:  req.Header.Get("X-Discovery-Auth"),
	}
	if len(req.TLS.PeerCertificates) > 0 {
		record.serial = req.TLS.PeerCertificates[0].SerialNumber.Int64()
	}
	r.mu.Lock()
	r.records = append(r.records, record)
	r.mu.Unlock()
}

func doRotationRequest(t *testing.T, client *http.Client, target string, discovery bool) {
	t.Helper()
	ctx := context.Background()
	if discovery {
		ctx = headerscope.WithMCPDiscovery(ctx)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// TestCredentialRotationReusesConnectionWithinGeneration verifies that two
// requests of the same generation share one authenticated connection, while a
// new generation dials a fresh connection presenting the new certificate and
// header, and that the retired generation's transport is dropped.
func TestCredentialRotationReusesConnectionWithinGeneration(t *testing.T) {
	t.Parallel()

	recorder := &identityRecorder{}
	server, caCert, caKey, caPool := newRotationMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.record(r)
		w.WriteHeader(http.StatusOK)
	}))

	_, certPath, keyPath := writeSignedClientCertificate(t, caCert, caKey, 101, "alpha")
	authPath := filepath.Join(filepath.Dir(certPath), "auth.txt")
	writeRotationFile(t, authPath, []byte("Bearer gen-1"))

	binding := rotationBinding(types.Channel("alpha"), mustParseURLFactoryTest(t, server.URL), certPath, keyPath)
	cfg := rotationConfig(
		[]runtimeconfig.MCPChannelBinding{binding},
		map[string]string{"Authorization": "file:" + authPath},
		nil,
	)
	factory := newRotationTestFactory(t, cfg, &tlsconfig.Bundle{RootCAs: caPool})
	client, err := factory.HTTPClientForBinding(binding)
	if err != nil {
		t.Fatalf("HTTPClientForBinding: %v", err)
	}
	rotator := factory.rotatorForTest(t, "alpha")

	doRotationRequest(t, client, server.URL, false)
	doRotationRequest(t, client, server.URL, false)
	first := recorder.snapshot()
	if len(first) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(first))
	}
	if first[0].serial != 101 || first[1].serial != 101 {
		t.Fatalf("generation 1 requests presented serials %d/%d, want 101", first[0].serial, first[1].serial)
	}
	if first[0].auth != "Bearer gen-1" || first[1].auth != "Bearer gen-1" {
		t.Fatalf("generation 1 requests presented auth %q/%q", first[0].auth, first[1].auth)
	}
	if first[0].remoteAddr != first[1].remoteAddr {
		t.Fatalf("same-generation requests did not reuse one connection: %q vs %q", first[0].remoteAddr, first[1].remoteAddr)
	}

	// Staged rewrite: certificate, then key, then header land independently,
	// but no reload happens until all three are in place.
	certPEM, keyPEM := mintClientCertificatePEM(t, caCert, caKey, 202)
	writeRotationFile(t, certPath, certPEM)
	writeRotationFile(t, keyPath, keyPEM)
	writeRotationFile(t, authPath, []byte("Bearer gen-2"))
	if !refreshRotation(t, rotator) {
		t.Fatalf("expected rotation to publish generation 2")
	}

	doRotationRequest(t, client, server.URL, false)
	doRotationRequest(t, client, server.URL, false)
	second := recorder.snapshot()[2:]
	if second[0].serial != 202 || second[1].serial != 202 {
		t.Fatalf("generation 2 requests presented serials %d/%d, want 202", second[0].serial, second[1].serial)
	}
	if second[0].auth != "Bearer gen-2" || second[1].auth != "Bearer gen-2" {
		t.Fatalf("generation 2 requests presented auth %q/%q", second[0].auth, second[1].auth)
	}
	if second[0].remoteAddr != second[1].remoteAddr {
		t.Fatalf("generation 2 requests did not reuse one connection: %q vs %q", second[0].remoteAddr, second[1].remoteAddr)
	}
	if second[0].remoteAddr == first[0].remoteAddr {
		t.Fatalf("generation 2 reused the previous generation's connection")
	}

	rotator.mu.Lock()
	_, hasGeneration1 := rotator.entries[1]
	entry2, hasGeneration2 := rotator.entries[2]
	rotator.mu.Unlock()
	if hasGeneration1 {
		t.Fatalf("retired generation 1 transport was not removed")
	}
	if !hasGeneration2 {
		t.Fatalf("generation 2 transport missing")
	}
	if entry2.inFlight != 0 || entry2.retired {
		t.Fatalf("generation 2 entry state = inFlight:%d retired:%v", entry2.inFlight, entry2.retired)
	}
}

// TestCredentialRotationInFlightRequestNotReplayed verifies that a request in
// flight when rotation publishes finishes on its original generation without
// retry, while subsequent requests use the new identity.
func TestCredentialRotationInFlightRequestNotReplayed(t *testing.T) {
	t.Parallel()

	entered := make(chan identityRecord, 1)
	release := make(chan struct{})
	recorder := &identityRecorder{}
	server, caCert, caKey, caPool := newRotationMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record := identityRecord{}
		if len(r.TLS.PeerCertificates) > 0 {
			record.serial = r.TLS.PeerCertificates[0].SerialNumber.Int64()
		}
		recorder.record(r)
		entered <- record
		<-release
		w.WriteHeader(http.StatusOK)
	}))

	_, certPath, keyPath := writeSignedClientCertificate(t, caCert, caKey, 101, "alpha")
	binding := rotationBinding(types.Channel("alpha"), mustParseURLFactoryTest(t, server.URL), certPath, keyPath)
	cfg := rotationConfig([]runtimeconfig.MCPChannelBinding{binding}, nil, nil)
	factory := newRotationTestFactory(t, cfg, &tlsconfig.Bundle{RootCAs: caPool})
	client, err := factory.HTTPClientForBinding(binding)
	if err != nil {
		t.Fatalf("HTTPClientForBinding: %v", err)
	}
	rotator := factory.rotatorForTest(t, "alpha")

	resultErr := make(chan error, 1)
	go func() {
		resp, err := client.Get(server.URL)
		if err == nil {
			_ = resp.Body.Close()
		}
		resultErr <- err
	}()

	var inFlight identityRecord
	select {
	case inFlight = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("in-flight request never reached the server")
	}
	if inFlight.serial != 101 {
		t.Fatalf("in-flight request serial = %d, want 101", inFlight.serial)
	}

	certPEM, keyPEM := mintClientCertificatePEM(t, caCert, caKey, 202)
	writeRotationFile(t, certPath, certPEM)
	writeRotationFile(t, keyPath, keyPEM)
	if !refreshRotation(t, rotator) {
		t.Fatalf("expected rotation to publish while request is in flight")
	}

	rotator.mu.Lock()
	entry1 := rotator.entries[1]
	_, hasGeneration2 := rotator.entries[2]
	rotator.mu.Unlock()
	if entry1 == nil || !entry1.retired || entry1.inFlight != 1 {
		t.Fatalf("generation 1 entry should be retired with one in-flight request, got %+v", entry1)
	}
	if hasGeneration2 {
		t.Fatalf("generation 2 transport must be created lazily by a new request")
	}
	if got := len(recorder.snapshot()); got != 1 {
		t.Fatalf("in-flight request was replayed %d times during rotation", got)
	}

	close(release)
	select {
	case err := <-resultErr:
		if err != nil {
			t.Fatalf("in-flight request failed after rotation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("in-flight request did not complete after release")
	}

	rotator.mu.Lock()
	_, stillRetained := rotator.entries[1]
	rotator.mu.Unlock()
	if stillRetained {
		t.Fatalf("retired generation was not removed once its response closed")
	}

	doRotationRequest(t, client, server.URL, false)
	last := recorder.snapshot()[len(recorder.snapshot())-1]
	if last.serial != 202 {
		t.Fatalf("post-rotation request serial = %d, want 202", last.serial)
	}
	if got := len(recorder.snapshot()); got != 2 {
		t.Fatalf("expected exactly 2 server requests, got %d", got)
	}
}

// TestCredentialRotationIsolatesChannels verifies that rotating one channel
// never changes another channel's certificate, headers, manager generation,
// or connection pool.
func TestCredentialRotationIsolatesChannels(t *testing.T) {
	t.Parallel()

	recorder := &identityRecorder{}
	server, caCert, caKey, caPool := newRotationMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.record(r)
		w.WriteHeader(http.StatusOK)
	}))

	_, alphaCert, alphaKey := writeSignedClientCertificate(t, caCert, caKey, 101, "alpha")
	_, bravoCert, bravoKey := writeSignedClientCertificate(t, caCert, caKey, 303, "bravo")
	dir := t.TempDir()
	alphaAuth := filepath.Join(dir, "alpha-auth.txt")
	bravoAuth := filepath.Join(dir, "bravo-auth.txt")
	writeRotationFile(t, alphaAuth, []byte("Bearer alpha-1"))
	writeRotationFile(t, bravoAuth, []byte("Bearer bravo-1"))

	alphaBinding := rotationBinding(types.Channel("alpha"), mustParseURLFactoryTest(t, server.URL), alphaCert, alphaKey)
	bravoBinding := rotationBinding(types.Channel("bravo"), mustParseURLFactoryTest(t, server.URL), bravoCert, bravoKey)
	// Header references are MCP-level configuration; channel-specific values
	// therefore need per-channel header files. Both channels watch their own
	// file through their own independent manager.
	alphaCfg := rotationConfig(
		[]runtimeconfig.MCPChannelBinding{alphaBinding},
		map[string]string{"Authorization": "file:" + alphaAuth},
		nil,
	)
	bravoCfg := rotationConfig(
		[]runtimeconfig.MCPChannelBinding{bravoBinding},
		map[string]string{"Authorization": "file:" + bravoAuth},
		nil,
	)
	alphaFactory := newRotationTestFactory(t, alphaCfg, &tlsconfig.Bundle{RootCAs: caPool})
	bravoFactory := newRotationTestFactory(t, bravoCfg, &tlsconfig.Bundle{RootCAs: caPool})
	alphaClient, err := alphaFactory.HTTPClientForBinding(alphaBinding)
	if err != nil {
		t.Fatalf("alpha client: %v", err)
	}
	bravoClient, err := bravoFactory.HTTPClientForBinding(bravoBinding)
	if err != nil {
		t.Fatalf("bravo client: %v", err)
	}

	doRotationRequest(t, alphaClient, server.URL, false)
	doRotationRequest(t, bravoClient, server.URL, false)

	certPEM, keyPEM := mintClientCertificatePEM(t, caCert, caKey, 202)
	writeRotationFile(t, alphaCert, certPEM)
	writeRotationFile(t, alphaKey, keyPEM)
	writeRotationFile(t, alphaAuth, []byte("Bearer alpha-2"))
	if !refreshRotation(t, alphaFactory.rotatorForTest(t, "alpha")) {
		t.Fatalf("alpha rotation did not publish")
	}
	changed, err := bravoFactory.rotatorForTest(t, "bravo").manager.Refresh(context.Background())
	if err != nil {
		t.Fatalf("bravo refresh: %v", err)
	}
	if changed {
		t.Fatalf("bravo generation changed without touching its files")
	}

	before := recorder.snapshot()
	doRotationRequest(t, alphaClient, server.URL, false)
	doRotationRequest(t, bravoClient, server.URL, false)
	after := recorder.snapshot()[len(before):]
	if after[0].serial != 202 || after[0].auth != "Bearer alpha-2" {
		t.Fatalf("alpha after rotation = serial:%d auth:%q", after[0].serial, after[0].auth)
	}
	if after[1].serial != 303 || after[1].auth != "Bearer bravo-1" {
		t.Fatalf("bravo drifted after alpha rotation = serial:%d auth:%q", after[1].serial, after[1].auth)
	}
	if after[0].remoteAddr == after[1].remoteAddr {
		t.Fatalf("isolated channels unexpectedly shared a connection")
	}
	if gen := bravoFactory.rotatorForTest(t, "bravo").manager.Generation(); gen != 1 {
		t.Fatalf("bravo generation = %d, want 1", gen)
	}
}

// TestCredentialRotationDiscoveryTrafficUsesNewHeaders verifies that OAuth
// discovery requests use discovery headers of the current generation and that
// runtime traffic never receives them.
func TestCredentialRotationDiscoveryHeaders(t *testing.T) {
	t.Parallel()

	recorder := &identityRecorder{}
	caCert, caKey, caPEM := generateCA(t)
	serverCert := generateSignedLeaf(t, caCert, caKey, "mcp-server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.record(r)
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	dir := t.TempDir()
	discoveryPath := filepath.Join(dir, "discovery-auth.txt")
	writeRotationFile(t, discoveryPath, []byte("disc-1"))

	binding := runtimeconfig.MCPChannelBinding{
		Channel:       types.Channel("alpha"),
		TransportKind: runtimeconfig.MCPTransportHTTPStreamable,
		ServerURL:     mustParseURLFactoryTest(t, server.URL),
	}
	cfg := rotationConfig(
		[]runtimeconfig.MCPChannelBinding{binding},
		nil,
		map[string]string{"X-Discovery-Auth": "file:" + discoveryPath},
	)
	factory := newRotationTestFactory(t, cfg, &tlsconfig.Bundle{RootCAs: mustPool(t, caPEM)})
	client, err := factory.HTTPClientForBinding(binding)
	if err != nil {
		t.Fatalf("HTTPClientForBinding: %v", err)
	}
	rotator := factory.rotatorForTest(t, "alpha")

	doRotationRequest(t, client, server.URL+"/mcp", false)
	doRotationRequest(t, client, server.URL+"/.well-known/oauth-protected-resource", true)
	writeRotationFile(t, discoveryPath, []byte("disc-2"))
	if !refreshRotation(t, rotator) {
		t.Fatalf("discovery header rotation did not publish")
	}
	doRotationRequest(t, client, server.URL+"/.well-known/oauth-protected-resource", true)
	doRotationRequest(t, client, server.URL+"/mcp", false)

	records := recorder.snapshot()
	if len(records) != 4 {
		t.Fatalf("expected 4 records, got %d", len(records))
	}
	if records[0].discovery != "" {
		t.Fatalf("runtime request leaked discovery header %q", records[0].discovery)
	}
	if records[1].discovery != "disc-1" {
		t.Fatalf("discovery request v1 = %q, want disc-1", records[1].discovery)
	}
	if records[2].discovery != "disc-2" {
		t.Fatalf("discovery request v2 = %q, want disc-2", records[2].discovery)
	}
	if records[3].discovery != "" {
		t.Fatalf("post-rotation runtime request leaked discovery header %q", records[3].discovery)
	}
}

// TestCredentialRotationNeverMixesGenerations hammers one channel with
// concurrent requests while rotating certificate and auth header together
// (including rejected intermediate generations). Every observed
// (certificate, header) pair must belong to the same published generation.
func TestCredentialRotationNeverMixesGenerations(t *testing.T) {
	t.Parallel()

	const generations = 6
	recorder := &identityRecorder{}
	server, caCert, caKey, caPool := newRotationMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.record(r)
		w.WriteHeader(http.StatusOK)
	}))

	_, certPath, keyPath := writeSignedClientCertificate(t, caCert, caKey, 101, "alpha")
	authPath := filepath.Join(filepath.Dir(certPath), "auth.txt")
	writeRotationFile(t, authPath, []byte("Bearer gen-1"))

	type generationIdentity struct {
		serial int64
		token  string
	}
	identities := []generationIdentity{{serial: 101, token: "Bearer gen-1"}}

	binding := rotationBinding(types.Channel("alpha"), mustParseURLFactoryTest(t, server.URL), certPath, keyPath)
	cfg := rotationConfig(
		[]runtimeconfig.MCPChannelBinding{binding},
		map[string]string{"Authorization": "file:" + authPath},
		nil,
	)
	factory := newRotationTestFactory(t, cfg, &tlsconfig.Bundle{RootCAs: caPool})
	client, err := factory.HTTPClientForBinding(binding)
	if err != nil {
		t.Fatalf("HTTPClientForBinding: %v", err)
	}
	rotator := factory.rotatorForTest(t, "alpha")

	stop := make(chan struct{})
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, err := http.NewRequest(http.MethodGet, server.URL, nil)
				if err != nil {
					continue
				}
				if resp, err := client.Do(req); err == nil {
					_ = resp.Body.Close()
				}
			}
		}()
	}

	for gen := 2; gen <= generations; gen++ {
		time.Sleep(2 * time.Millisecond)
		if gen == 4 {
			// A corrupted key must reject the whole generation and retain
			// generation 3 while requests continue to succeed.
			writeRotationFile(t, certPath, []byte("not a certificate"))
			expectRefreshError(t, rotator, "load client certificate/key pair")
		}
		identity := generationIdentity{
			serial: 100 + int64(gen),
			token:  fmt.Sprintf("Bearer gen-%d", gen),
		}
		certPEM, keyPEM := mintClientCertificatePEM(t, caCert, caKey, identity.serial)
		writeRotationFile(t, certPath, certPEM)
		writeRotationFile(t, keyPath, keyPEM)
		writeRotationFile(t, authPath, []byte(identity.token))
		if !refreshRotation(t, rotator) {
			t.Fatalf("generation %d did not publish", gen)
		}
		identities = append(identities, identity)
	}

	close(stop)
	workers.Wait()

	serialByToken := make(map[string]int64)
	for _, identity := range identities {
		serialByToken[identity.token] = identity.serial
	}
	for _, record := range recorder.snapshot() {
		if record.serial == 0 {
			t.Fatalf("request reached server without a client certificate")
		}
		wantSerial, ok := serialByToken[record.auth]
		if !ok {
			t.Fatalf("request presented unknown auth header %q", record.auth)
		}
		if record.serial != wantSerial {
			t.Fatalf("mixed generations: certificate serial %d paired with %q (want serial %d)", record.serial, record.auth, wantSerial)
		}
	}
	if len(recorder.snapshot()) < generations {
		t.Fatalf("expected traffic across generations, got %d requests", len(recorder.snapshot()))
	}
}

// TestCredentialRotationFailsClosedOnInvalidInitialGeneration verifies that a
// channel whose initial credential set is unreadable does not serve.
func TestCredentialRotationFailsClosedOnInvalidInitialGeneration(t *testing.T) {
	t.Parallel()

	server, caCert, caKey, caPool := newRotationMTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	_, certPath, keyPath := writeSignedClientCertificate(t, caCert, caKey, 101, "alpha")
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove key: %v", err)
	}

	binding := rotationBinding(types.Channel("alpha"), mustParseURLFactoryTest(t, server.URL), certPath, keyPath)
	cfg := rotationConfig([]runtimeconfig.MCPChannelBinding{binding}, nil, nil)
	factory := newRotationTestFactory(t, cfg, &tlsconfig.Bundle{RootCAs: caPool})
	if _, err := factory.HTTPClientForBinding(binding); err == nil {
		t.Fatalf("expected invalid initial generation to fail closed")
	}
}

// TestCredentialRotationRetainsLastGoodGeneration verifies end-to-end that a
// bad rewrite keeps serving the previous generation and a subsequent complete
// rewrite activates the new one.
func TestCredentialRotationRetainsLastGoodGeneration(t *testing.T) {
	t.Parallel()

	recorder := &identityRecorder{}
	server, caCert, caKey, caPool := newRotationMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.record(r)
		w.WriteHeader(http.StatusOK)
	}))

	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	authPath := filepath.Join(dir, "auth.txt")
	certPEM1, keyPEM1 := mintClientCertificatePEM(t, caCert, caKey, 101)
	writeRotationFile(t, certPath, certPEM1)
	writeRotationFile(t, keyPath, keyPEM1)
	writeRotationFile(t, authPath, []byte("Bearer gen-1"))

	binding := rotationBinding(types.Channel("alpha"), mustParseURLFactoryTest(t, server.URL), certPath, keyPath)
	cfg := rotationConfig(
		[]runtimeconfig.MCPChannelBinding{binding},
		map[string]string{"Authorization": "file:" + authPath},
		nil,
	)
	factory := newRotationTestFactory(t, cfg, &tlsconfig.Bundle{RootCAs: caPool})
	client, err := factory.HTTPClientForBinding(binding)
	if err != nil {
		t.Fatalf("HTTPClientForBinding: %v", err)
	}
	rotator := factory.rotatorForTest(t, "alpha")

	doRotationRequest(t, client, server.URL, false)

	// A foreign key pairs with the generation 1 certificate: the keypair
	// mismatch rejects the generation as a unit.
	_, foreignKeyPEM := mintClientCertificatePEM(t, caCert, caKey, 202)
	writeRotationFile(t, keyPath, foreignKeyPEM)
	expectRefreshError(t, rotator, "load client certificate/key pair")
	doRotationRequest(t, client, server.URL, false)

	// Restore the generation 1 key, then reject an injected header value.
	writeRotationFile(t, keyPath, keyPEM1)
	writeRotationFile(t, authPath, []byte("Bearer bad\ninjection"))
	expectRefreshError(t, rotator, "cannot contain CR or LF")
	doRotationRequest(t, client, server.URL, false)

	for _, record := range recorder.snapshot() {
		if record.serial != 101 || record.auth != "Bearer gen-1" {
			t.Fatalf("retained generation drifted to serial:%d auth:%q", record.serial, record.auth)
		}
	}
	if gen := rotator.manager.Generation(); gen != 1 {
		t.Fatalf("generation = %d, want 1 after rejected rewrites", gen)
	}

	// Complete generation 2 restores rotation.
	certPEM, keyPEM := mintClientCertificatePEM(t, caCert, caKey, 202)
	writeRotationFile(t, certPath, certPEM)
	writeRotationFile(t, keyPath, keyPEM)
	writeRotationFile(t, authPath, []byte("Bearer gen-2"))
	if !refreshRotation(t, rotator) {
		t.Fatalf("generation 2 did not publish after recovery")
	}
	doRotationRequest(t, client, server.URL, false)
	last := recorder.snapshot()[len(recorder.snapshot())-1]
	if last.serial != 202 || last.auth != "Bearer gen-2" {
		t.Fatalf("recovered generation = serial:%d auth:%q", last.serial, last.auth)
	}
}
