package credrotation

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultPollInterval is the default interval between credential file checks.
const DefaultPollInterval = 30 * time.Second

// minPollInterval bounds operator-configured intervals so a tight poll loop
// cannot turn into a busy loop.
const minPollInterval = time.Second

// ErrNoLoader is returned when a manager is used without a loader.
var ErrNoLoader = errors.New("credential rotation: no credential loader configured")

// RotatedCallback runs after a new generation validates but before it becomes
// visible to Current. Callbacks close idle connections here so a request that
// observes the new snapshot cannot reuse a connection authenticated with the
// previous generation. A callback must not block on request traffic.
type RotatedCallback func(generation uint64)

// statSignature is the cheap pre-check compared on every poll. Contents are
// hashed only after a stat change.
type statSignature struct {
	size    int64
	modTime time.Time
	missing bool
}

// Manager watches one channel's credential files and atomically swaps
// validated generations. The zero value is not usable; use NewManager.
type Manager struct {
	logger   *slog.Logger
	loader   *Loader
	interval time.Duration
	channel  string

	current atomic.Pointer[Snapshot]

	// refreshMu serializes reloads and guards the stat baseline.
	refreshMu    sync.Mutex
	statBaseline map[string]statSignature

	callbackMu sync.Mutex
	callbacks  []RotatedCallback
}

// Option configures a Manager.
type Option func(*Manager)

// WithPollInterval overrides the default poll interval. Values below the
// minimum are clamped.
func WithPollInterval(interval time.Duration) Option {
	return func(m *Manager) {
		if interval >= minPollInterval {
			m.interval = interval
		}
	}
}

// NewManager performs the initial all-or-nothing load. Startup fails closed:
// an invalid initial generation returns an error instead of serving with no
// credentials.
func NewManager(logger *slog.Logger, loader *Loader, options ...Option) (*Manager, error) {
	if loader == nil {
		return nil, ErrNoLoader
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	manager := &Manager{
		logger:   logger,
		loader:   loader,
		interval: DefaultPollInterval,
		channel:  loader.spec.Channel,
	}
	for _, option := range options {
		option(manager)
	}
	if manager.interval < minPollInterval {
		manager.interval = minPollInterval
	}

	snapshot, _, err := loader.Load()
	if err != nil {
		return nil, err
	}
	snapshot.generation = 1
	manager.current.Store(snapshot)
	// An empty stat baseline forces the first Refresh to stat and rebuild a
	// candidate even when a rewrite preserves the initial modtime.
	manager.statBaseline = map[string]statSignature{}
	return manager, nil
}

// Current returns the active validated generation. It is safe for concurrent
// use. The returned snapshot and its maps must not be mutated.
func (m *Manager) Current() *Snapshot {
	if m == nil {
		return nil
	}
	return m.current.Load()
}

// Generation returns the active generation number.
func (m *Manager) Generation() uint64 {
	return m.Current().Generation()
}

// OnRotated registers a callback invoked before a new generation is published.
// Registrations after a rotation only apply to subsequent generations.
func (m *Manager) OnRotated(callback RotatedCallback) {
	if m == nil || callback == nil {
		return
	}
	m.callbackMu.Lock()
	m.callbacks = append(m.callbacks, callback)
	m.callbackMu.Unlock()
}

// Refresh re-checks the watched files. It returns changed=true only when a
// complete new generation validated and published. A failed reload preserves
// the last good generation, logs a redacted warning, and returns its error so
// callers can observe the failure.
func (m *Manager) Refresh(ctx context.Context) (changed bool, err error) {
	if m == nil || m.loader == nil {
		return false, ErrNoLoader
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}

	// Serialize reloads so two concurrent polls can never interleave a
	// certificate-only update with a header-only publication.
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	previous := m.current.Load()
	watched := m.loader.Spec().WatchedFiles()

	signatures, statChanged := m.pollStats(watched)
	if !statChanged {
		return false, nil
	}

	candidate, _, err := m.loader.Load()
	if err != nil {
		m.logger.Warn("credential rotation: invalid credential generation; retaining last good generation",
			slog.String("channel", m.channel),
			slog.Uint64("retained_generation", previous.Generation()),
			slog.String("error", err.Error()),
		)
		return false, err
	}

	if snapshotIdentity(candidate) == snapshotIdentity(previous) {
		// A stat changed (touch, rename of identical bytes, or an env
		// reference whose value did not move) but the effective identity is
		// unchanged: refresh the stat baseline without bumping the generation.
		m.statBaseline = signatures
		return false, nil
	}

	candidate.generation = previous.Generation() + 1
	for _, callback := range m.snapshotCallbacks() {
		callback(candidate.generation)
	}
	m.current.Store(candidate)
	m.statBaseline = signatures

	m.logger.Info("credential rotation: activated new credential generation",
		slog.String("channel", m.channel),
		slog.Uint64("generation", candidate.generation),
		slog.String("previous_cert", previous.CertIdentity()),
		slog.String("cert", candidate.CertIdentity()),
		slog.Bool("mtls", candidate.Certificate != nil),
		slog.Int("auth_headers", len(candidate.ExtraHeaders)),
		slog.Int("discovery_auth_headers", len(candidate.DiscoveryExtraHeaders)),
	)
	return true, nil
}

// Run polls until ctx is cancelled. It is typically run in its own goroutine.
func (m *Manager) Run(ctx context.Context) {
	if m == nil {
		return
	}
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := m.Refresh(ctx); err != nil && ctx.Err() != nil {
				return
			}
		}
	}
}

func (m *Manager) snapshotCallbacks() []RotatedCallback {
	m.callbackMu.Lock()
	defer m.callbackMu.Unlock()
	callbacks := make([]RotatedCallback, len(m.callbacks))
	copy(callbacks, m.callbacks)
	return callbacks
}

// pollStats stats every watched file and reports whether any signature
// differs from the baseline. A missing file is a distinct signature so a
// transient delete triggers a validation attempt that rejects the generation
// and retains the current one.
func (m *Manager) pollStats(paths []string) (map[string]statSignature, bool) {
	signatures := make(map[string]statSignature, len(paths))
	changed := len(m.statBaseline) != len(paths)
	for _, path := range paths {
		info, err := os.Stat(path)
		switch {
		case err == nil:
			signatures[path] = statSignature{size: info.Size(), modTime: info.ModTime()}
		case os.IsNotExist(err):
			signatures[path] = statSignature{missing: true}
		default:
			// Other stat errors are handled like a missing file: force a
			// reload, whose read fails validation and retains the snapshot.
			signatures[path] = statSignature{missing: true}
		}
		if prev, ok := m.statBaseline[path]; !ok || prev != signatures[path] {
			changed = true
		}
	}
	return signatures, changed
}

// snapshotIdentity is the effective identity of a generation: the leaf
// certificate fingerprint plus every resolved header value. Two generations
// with the same identity need no publication and no connection drain.
func snapshotIdentity(s *Snapshot) string {
	if s == nil {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("cert=")
	builder.WriteString(s.certIdentity)
	writeHeaderIdentity(&builder, "auth", s.ExtraHeaders)
	writeHeaderIdentity(&builder, "discovery", s.DiscoveryExtraHeaders)
	return builder.String()
}

func writeHeaderIdentity(builder *strings.Builder, scope string, headers map[string]string) {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		builder.WriteString("|")
		builder.WriteString(scope)
		builder.WriteString(":")
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(headers[key])
	}
}
