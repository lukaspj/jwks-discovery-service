package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lukaspj/jwks-discovery-service/internal/jwks"
	"github.com/lukaspj/jwks-discovery-service/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// OIDCDiscovery is the OpenID Connect Discovery 1.0 metadata document
// served at /<name>/.well-known/openid-configuration.
type OIDCDiscovery struct {
	Issuer             string   `json:"issuer"`
	JWKSURI            string   `json:"jwks_uri"`
	ResponseTypes      []string `json:"response_types_supported"`
	SubjectTypes       []string `json:"subject_types_supported"`
	IDTokenSigningAlgs []string `json:"id_token_signing_alg_values_supported"`
	Claims             []string `json:"claims_supported"`
}

// New builds the HTTP handler with all routes:
//
//	GET /{name}/.well-known/jwks.json  – RFC 7517 key set for the service
//	GET /{name}/.well-known            – alias of the above
//	GET /{name}/.well-known/openid-configuration – OIDC discovery metadata
//	GET /healthz                       – liveness probe
//	GET /readyz                        – readiness probe (has loaded services)
//	GET /metrics                       – Prometheus metrics
//
// publicURL is the externally reachable base URL used to build issuer and
// jwks_uri values; when empty it is derived from the incoming request.
func New(reg *jwks.Registry, ready *Ready, logger *slog.Logger, publicURL string) http.Handler {
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
		svc := reg.Get(name)
		if svc == nil {
			writeJSONError(w, http.StatusNotFound, "unknown service: "+name)
			return
		}
		body, err := svc.Set.Marshal()
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

	mux.HandleFunc("GET /{name}/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		svc := reg.Get(name)
		if svc == nil {
			writeJSONError(w, http.StatusNotFound, "unknown service: "+name)
			return
		}
		base := publicURL
		if base == "" {
			scheme := "http"
			if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
				scheme = proto
			} else if r.TLS != nil {
				scheme = "https"
			}
			base = scheme + "://" + r.Host
		}
		base = strings.TrimSuffix(base, "/")
		issuer := svc.Issuer
		if issuer == "" {
			issuer = base + "/" + name
		}
		doc := OIDCDiscovery{
			Issuer:             issuer,
			JWKSURI:            base + "/" + name + "/.well-known/jwks.json",
			ResponseTypes:      []string{"id_token"},
			SubjectTypes:       []string{"public"},
			IDTokenSigningAlgs: svc.Set.SigningAlgs(),
			Claims:             []string{"iss", "sub", "aud", "exp", "iat"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(doc)
	})

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
