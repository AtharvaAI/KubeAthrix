package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/auth"
	"go.opentelemetry.io/otel/trace"
)

type apiMetrics struct {
	startedAt   time.Time
	inFlight    atomic.Int64
	mu          sync.Mutex
	requests    map[int]uint64
	durationSum time.Duration
}

func newAPIMetrics() *apiMetrics {
	return &apiMetrics{startedAt: time.Now().UTC(), requests: map[int]uint64{}}
}

const defaultMaxRequestBodyBytes int64 = 1 << 20

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(payload []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(payload)
}

type rateWindow struct {
	started time.Time
	count   int
	seen    time.Time
}

type requestLimiter struct {
	mu       sync.Mutex
	windows  map[string]rateWindow
	limit    int
	interval time.Duration
	clock    func() time.Time
}

func newRequestLimiter(limit int) *requestLimiter {
	if limit <= 0 {
		limit = 120
	}
	return &requestLimiter{windows: map[string]rateWindow{}, limit: limit, interval: time.Minute, clock: time.Now}
}

func (l *requestLimiter) allow(key string) (bool, time.Duration) {
	now := l.clock().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	window := l.windows[key]
	if window.started.IsZero() || now.Sub(window.started) >= l.interval {
		window = rateWindow{started: now}
	}
	window.count++
	window.seen = now
	l.windows[key] = window
	if len(l.windows) > 4096 {
		for candidate, item := range l.windows {
			if now.Sub(item.seen) > 5*l.interval {
				delete(l.windows, candidate)
			}
		}
	}
	if window.count > l.limit {
		return false, maxDuration(l.interval-now.Sub(window.started), time.Second)
	}
	return true, 0
}

func (s *Server) withAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		var principal auth.Principal
		if s.config.InsecureDevAuth {
			principal = auth.DevelopmentPrincipal()
		} else {
			if s.config.Authenticator == nil {
				writeError(w, http.StatusServiceUnavailable, errors.New("authentication is not configured"))
				return
			}
			authorization := strings.TrimSpace(r.Header.Get("Authorization"))
			parts := strings.Fields(authorization)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="kubeathrix"`)
				writeError(w, http.StatusUnauthorized, auth.ErrUnauthenticated)
				return
			}
			verified, err := s.config.Authenticator.Verify(r.Context(), parts[1])
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="kubeathrix", error="invalid_token"`)
				writeError(w, http.StatusUnauthorized, auth.ErrUnauthenticated)
				return
			}
			principal = verified
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	})
}

func requireRole(role auth.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, auth.ErrUnauthenticated)
			return
		}
		if !principal.HasRole(role) {
			writeError(w, http.StatusForbidden, auth.ErrUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) withRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := remoteAddress(r.RemoteAddr)
		if principal, ok := auth.PrincipalFromContext(r.Context()); ok {
			key = "subject:" + principal.Subject
		}
		allowed, retryAfter := s.limiter.allow(key)
		if !allowed {
			seconds := int((retryAfter + time.Second - 1) / time.Second)
			w.Header().Set("Retry-After", strconv.Itoa(max(seconds, 1)))
			writeError(w, http.StatusTooManyRequests, errors.New("request rate limit exceeded"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		s.metrics.inFlight.Add(1)
		defer s.metrics.inFlight.Add(-1)
		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		attributes := []any{
			"request_id", w.Header().Get("X-Request-ID"),
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"duration_ms", time.Since(started).Milliseconds(),
		}
		if spanContext := trace.SpanContextFromContext(r.Context()); spanContext.IsValid() {
			attributes = append(attributes, "trace_id", spanContext.TraceID().String(), "span_id", spanContext.SpanID().String())
		}
		if principal, ok := auth.PrincipalFromContext(r.Context()); ok {
			attributes = append(attributes, "subject", principal.Subject)
		}
		s.metrics.mu.Lock()
		s.metrics.requests[status]++
		s.metrics.durationSum += time.Since(started)
		s.metrics.mu.Unlock()
		s.logger.Log(r.Context(), slog.LevelInfo, "http request", attributes...)
	})
}

func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if !validRequestID(requestID) {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r)
	})
}

func withRequestBodyLimit(limit int64, next http.Handler) http.Handler {
	if limit <= 0 {
		limit = defaultMaxRequestBodyBytes
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

func withRecovery(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Error("panic while serving request", "request_id", w.Header().Get("X-Request-ID"), "panic", recovered)
				writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func remoteAddress(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil && host != "" {
		return host
	}
	if address == "" {
		return "unknown"
	}
	return address
}

func validRequestID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character == '-' || character == '_' || character == '.' || character >= '0' && character <= '9' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z') {
			return false
		}
	}
	return true
}

func newRequestID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "request-unknown"
	}
	return hex.EncodeToString(bytes)
}

func maxDuration(left, minimum time.Duration) time.Duration {
	if left < minimum {
		return minimum
	}
	return left
}
