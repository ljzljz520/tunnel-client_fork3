package internal

import (
	"context"
	"maps"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/openai/tunnel-client/pkg/credrotation"
	"github.com/openai/tunnel-client/pkg/headerscope"
)

// StaticHeadersRoundTripper adds operator-configured MCP headers only for the
// configured MCP server origin. Discovery headers are additionally gated by a
// request context marker so they do not leak to normal runtime traffic.
type StaticHeadersRoundTripper struct {
	base                  http.RoundTripper
	scope                 headerScope
	extraHeaders          map[string]string
	discoveryExtraHeaders map[string]string
}

// NewStaticHeadersRoundTripper constructs a scoped static-header round tripper.
func NewStaticHeadersRoundTripper(base http.RoundTripper, serverURL *url.URL, extraHeaders, discoveryExtraHeaders map[string]string) http.RoundTripper {
	if base == nil {
		panic("nil base RoundTripper")
	}
	if serverURL == nil || (len(extraHeaders) == 0 && len(discoveryExtraHeaders) == 0) {
		return base
	}
	return &StaticHeadersRoundTripper{
		base:                  base,
		scope:                 newHeaderScope(serverURL),
		extraHeaders:          cloneStringMap(extraHeaders),
		discoveryExtraHeaders: cloneStringMap(discoveryExtraHeaders),
	}
}

func (s *StaticHeadersRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return s.base.RoundTrip(req)
	}
	discovery := headerscope.IsMCPDiscovery(req.Context())
	if s.scope.applies(req.URL, discovery) {
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		applyHeaderMap(req.Header, s.extraHeaders)
		if discovery {
			applyHeaderMap(req.Header, s.discoveryExtraHeaders)
		}
	}
	return s.base.RoundTrip(req)
}

// DynamicCredentialRoundTripper is the outermost credential-rotation layer.
// For every request it loads the current validated generation exactly once,
// pins that snapshot to the request context, and applies only that
// generation's headers. The matching credential transport selector further
// down the chain reads the same pinned snapshot, so the client certificate
// presented on the TLS handshake can never belong to a different generation
// than the authentication headers on that request.
type DynamicCredentialRoundTripper struct {
	base    http.RoundTripper
	scope   headerScope
	current func() *credrotation.Snapshot
}

// NewDynamicCredentialRoundTripper constructs the outermost rotation layer.
// current must return the active validated snapshot; the round tripper still
// applies when the snapshot carries no headers so certificate-only
// generations remain pinned for the transport selector.
func NewDynamicCredentialRoundTripper(base http.RoundTripper, serverURL *url.URL, current func() *credrotation.Snapshot) http.RoundTripper {
	if base == nil {
		panic("nil base RoundTripper")
	}
	if current == nil || serverURL == nil {
		return base
	}
	return &DynamicCredentialRoundTripper{
		base:    base,
		scope:   newHeaderScope(serverURL),
		current: current,
	}
}

// credentialSnapshotKey pins one validated credential generation to a request.
type credentialSnapshotKey struct{}

// WithCredentialSnapshot returns a context carrying a pinned credential
// generation.
func WithCredentialSnapshot(ctx context.Context, snapshot *credrotation.Snapshot) context.Context {
	if snapshot == nil {
		return ctx
	}
	return context.WithValue(ctx, credentialSnapshotKey{}, snapshot)
}

// CredentialSnapshotFromContext returns the generation pinned to ctx, or nil.
func CredentialSnapshotFromContext(ctx context.Context) *credrotation.Snapshot {
	if ctx == nil {
		return nil
	}
	snapshot, _ := ctx.Value(credentialSnapshotKey{}).(*credrotation.Snapshot)
	return snapshot
}

func (d *DynamicCredentialRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return d.base.RoundTrip(req)
	}
	snapshot := d.current()
	if snapshot != nil {
		req = req.WithContext(WithCredentialSnapshot(req.Context(), snapshot))
		discovery := headerscope.IsMCPDiscovery(req.Context())
		if d.scope.applies(req.URL, discovery) {
			if req.Header == nil {
				req.Header = make(http.Header)
			}
			applyHeaderMap(req.Header, snapshot.ExtraHeaders)
			if discovery {
				applyHeaderMap(req.Header, snapshot.DiscoveryExtraHeaders)
			}
		}
	}
	return d.base.RoundTrip(req)
}

// headerScope restricts credential application to the configured MCP origin.
// Discovery requests are origin-scoped regardless of path; runtime requests
// must additionally hit the configured endpoint path.
type headerScope struct {
	origin string
	path   string
}

func newHeaderScope(serverURL *url.URL) headerScope {
	return headerScope{
		origin: originKey(serverURL),
		path:   cleanPath(serverURL.EscapedPath()),
	}
}

func (s headerScope) applies(reqURL *url.URL, discovery bool) bool {
	if reqURL == nil || s.origin == "" {
		return false
	}
	if originKey(reqURL) != s.origin {
		return false
	}
	return discovery || cleanPath(reqURL.EscapedPath()) == s.path
}

func applyHeaderMap(dst http.Header, headers map[string]string) {
	if len(headers) == 0 {
		return
	}
	if dst == nil {
		return
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		dst.Set(key, headers[key])
	}
}

func originKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if scheme == "" || host == "" {
		return ""
	}
	if (scheme == "http" && u.Port() == "80") || (scheme == "https" && u.Port() == "443") {
		host = strings.TrimSuffix(host, ":"+u.Port())
	}
	return scheme + "://" + host
}

func cleanPath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	trimmed := strings.TrimRight(path, "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	maps.Copy(out, src)
	return out
}
