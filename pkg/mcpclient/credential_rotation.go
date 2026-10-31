package mcpclient

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"

	"github.com/openai/tunnel-client/pkg/credrotation"
	"github.com/openai/tunnel-client/pkg/mcpclient/internal"
	"github.com/openai/tunnel-client/pkg/tlsconfig"
	tctransport "github.com/openai/tunnel-client/pkg/transport"
)

// credentialRotator owns one channel's generation manager and the
// generation-keyed HTTP transport pool used to present that generation's
// client certificate.
//
// Each validated generation gets its own *http.Transport (and therefore its
// own connection pool). A request pins exactly one snapshot at the outermost
// credential round tripper; the selector here routes it to the transport of
// that same generation, so the TLS handshake cert and the request auth headers
// can never come from different generations. In-flight requests keep using
// their generation's transport until their response body closes; generations
// are retired only after their last in-flight request completes, at which
// point their idle connections are closed rather than pooled for newer
// generations.
type credentialRotator struct {
	logger    *slog.Logger
	manager   *credrotation.Manager
	serverURL *url.URL

	// base carries the CA bundle, proxy, and Unix-socket settings and never
	// holds a client certificate. It serves cross-origin redirect hops and
	// certificate-free generations.
	base *http.Transport

	mu      sync.Mutex
	entries map[uint64]*generationTransportEntry
}

type generationTransportEntry struct {
	generation uint64
	transport  *http.Transport

	// inFlight counts requests that selected this generation and have not
	// yet released their response. Retired entries with in-flight requests
	// stay open until the last release.
	inFlight int
	retired  bool
}

func newCredentialRotator(logger *slog.Logger, manager *credrotation.Manager, base *http.Transport, serverURL *url.URL) *credentialRotator {
	rotator := &credentialRotator{
		logger:    logger,
		manager:   manager,
		serverURL: serverURL,
		base:      base,
		entries:   make(map[uint64]*generationTransportEntry),
	}
	// The manager invokes callbacks after the new generation validates but
	// before it publishes, so no request can observe the new snapshot while
	// a previous generation's idle connections are still being retired.
	manager.OnRotated(rotator.onRotated)
	return rotator
}

// selector is the innermost credential-aware round tripper. It replaces the
// static origin-scoped mTLS wrapper on rotation-enabled channels.
type credentialTransportSelector struct {
	rotator *credentialRotator
}

func (s *credentialTransportSelector) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return s.rotator.base.RoundTrip(req)
	}
	snapshot := internal.CredentialSnapshotFromContext(req.Context())
	// The client certificate stays scoped to the configured MCP origin;
	// cross-origin redirect hops use the certificate-less base transport.
	if snapshot == nil || snapshot.Certificate == nil || !sameURLOrigin(req.URL, s.rotator.serverURL) {
		return s.rotator.base.RoundTrip(req)
	}
	entry, err := s.rotator.acquire(snapshot)
	if err != nil {
		return nil, err
	}
	resp, err := entry.transport.RoundTrip(req)
	if err != nil {
		s.rotator.release(entry)
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		s.rotator.release(entry)
		return resp, nil
	}
	resp.Body = &generationReleaseBody{body: resp.Body, entry: entry, rotator: s.rotator}
	return resp, nil
}

// generationReleaseBody keeps a generation transport in use until the
// response body closes, which is exactly when net/http returns the
// underlying connection to the generation's idle pool.
type generationReleaseBody struct {
	body    io.ReadCloser
	entry   *generationTransportEntry
	rotator *credentialRotator
	once    sync.Once
}

func (b *generationReleaseBody) Read(p []byte) (int, error) {
	return b.body.Read(p)
}

func (b *generationReleaseBody) Close() error {
	err := b.body.Close()
	b.once.Do(func() { b.rotator.release(b.entry) })
	return err
}

func (r *credentialRotator) acquire(snapshot *credrotation.Snapshot) (*generationTransportEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.entries[snapshot.Generation()]; ok {
		entry.inFlight++
		return entry, nil
	}
	certificate := *snapshot.Certificate
	transport, err := tctransport.ApplyClientCertificate(r.base, &tlsconfig.ClientCertificate{Certificate: certificate})
	if err != nil {
		return nil, err
	}
	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("mcpclient: credential rotation base transport has unsupported type %T", transport)
	}
	entry := &generationTransportEntry{
		generation: snapshot.Generation(),
		transport:  httpTransport,
		inFlight:   1,
	}
	r.entries[entry.generation] = entry
	return entry, nil
}

func (r *credentialRotator) release(entry *generationTransportEntry) {
	r.mu.Lock()
	entry.inFlight--
	retire := entry.retired && entry.inFlight == 0
	if retire {
		delete(r.entries, entry.generation)
	}
	transport := entry.transport
	r.mu.Unlock()
	if retire {
		// The response body has already returned the connection to the
		// pool; drop it so this retired generation cannot lend an
		// old-identity connection to a newer request.
		transport.CloseIdleConnections()
	}
}

// onRotated retires every generation older than generation. Idle generations
// close immediately; generations with in-flight requests close once their
// last response finishes.
func (r *credentialRotator) onRotated(generation uint64) {
	r.mu.Lock()
	var idle []*http.Transport
	for gen, entry := range r.entries {
		if gen >= generation {
			continue
		}
		entry.retired = true
		if entry.inFlight == 0 {
			delete(r.entries, gen)
			idle = append(idle, entry.transport)
		}
	}
	r.mu.Unlock()
	for _, transport := range idle {
		transport.CloseIdleConnections()
	}
}

// closeAll retires every generation and the base transport. It runs on
// shutdown; in-flight requests are left to finish on their own connections.
func (r *credentialRotator) closeAll() {
	r.mu.Lock()
	entries := r.entries
	r.entries = make(map[uint64]*generationTransportEntry)
	r.mu.Unlock()
	for _, entry := range entries {
		entry.transport.CloseIdleConnections()
	}
	r.base.CloseIdleConnections()
}
