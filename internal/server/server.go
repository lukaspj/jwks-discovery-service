package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/lukaspj/jwks-discovery-service/internal/jwks"
	"github.com/lukaspj/jwks-discovery-service/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// New builds the HTTP handler with all routes:
//
//	GET /{name}/.well-known/jwks.json  – RFC 7517 key set for the service
//	GET /{name}/.well-known            – alias of the above
//	GET /healthz                       – liveness probe
//	GET /readyz                        – readiness probe (has loaded services)
//	GET /metrics                       – Prometheus metrics
func New(reg *jwks.Registry, ready *Ready, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready.IsReady() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		http.Error(w, "not ready\n", http.StatusServiceUnavailable)
	})

	mux.Handle("GET /metrics", promhttp.Handler())

	jwksHandler := func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		set := reg.Get(name)
		if set == nil {
			writeJSONError(w, http.StatusNotFound, "unknown service: "+name)
			return
		}
		body, err := set.Marshal()
		if err != nil {
			logger.Error("marshal jwks", "service", name, "err", err)
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
	mux.HandleFunc("GET /{name}/.well-known/jwks.json", jwksHandler)
	mux.HandleFunc("GET /{name}/.well-known", jwksHandler)

	return withMetrics(mux)
}

// Ready reports whether the first successful rescan has completed.
type Ready struct{ flag atomic.Int32 }

func NewReady() *Ready { return &Ready{} }

func (r *Ready) Set(v bool) {
	if v {
		r.flag.Store(1)
	} else {
		r.flag.Store(0)
	}
}

func (r *Ready) IsReady() bool { return r.flag.Load() == 1 }

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

type recorder struct {
	http.ResponseWriter
	code int
}

func (r *recorder) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

func withMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &recorder{ResponseWriter: w, code: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		metrics.HTTPRequests.WithLabelValues(routeLabel(r), strconv.Itoa(rec.code)).Inc()
		_ = start
	})
}

func routeLabel(r *http.Request) string {
	switch r.URL.Path {
	case "/healthz":
		return "healthz"
	case "/readyz":
		return "readyz"
	case "/metrics":
		return "metrics"
	}
	if len(r.URL.Path) > 1 {
		return "jwks"
	}
	return "other"
}
