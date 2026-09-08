package refresher

import (
	"context"
	"log/slog"
	"time"

	"github.com/lukaspj/jwks-discovery-service/internal/jwks"
	"github.com/lukaspj/jwks-discovery-service/internal/metrics"
	"github.com/lukaspj/jwks-discovery-service/internal/server"
	"github.com/lukaspj/jwks-discovery-service/internal/store"
)

// Rescan enumerates manifests from the store, converts each to a JWK
// Set, and atomically swaps the registry. A full failure (e.g. S3
// unreachable) keeps the previous registry intact.
type Rescan struct {
	Store    *store.Client
	Registry *jwks.Registry
	Ready    *server.Ready
	Logger   *slog.Logger
}

// RunOnce performs a single rescan. Returns error only when the whole
// enumeration failed; per-manifest problems are logged and skipped.
func (r *Rescan) RunOnce(ctx context.Context) error {
	manifests, errs := r.Store.List(ctx)
	for _, err := range errs {
		r.Logger.Warn("skipping manifest", "err", err)
	}

	sets := make(map[string]*jwks.JWKSet, len(manifests))
	for name, m := range manifests {
		set, err := jwks.Set(m.CertPEM)
		if err != nil {
			r.Logger.Warn("skipping service: bad certificate", "service", name, "err", err)
			continue
		}
		sets[name] = set
	}

	if len(manifests) == 0 && len(errs) > 0 {
		metrics.RescansTotal.WithLabelValues("error").Inc()
		return errs[0]
	}

	r.Registry.Swap(sets)
	r.Ready.Set(true)
	metrics.ServicesLoaded.Set(float64(len(sets)))
	metrics.RescansTotal.WithLabelValues("ok").Inc()
	metrics.LastRescanSeconds.SetToCurrentTime()
	r.Logger.Info("rescan complete", "services", len(sets), "warnings", len(errs))
	return nil
}

// Start runs RunOnce immediately and then on every tick of interval
// until ctx is cancelled.
func (r *Rescan) Start(ctx context.Context, interval time.Duration) {
	if err := r.RunOnce(ctx); err != nil {
		r.Logger.Error("initial rescan failed", "err", err)
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := r.RunOnce(ctx); err != nil {
					r.Logger.Error("rescan failed", "err", err)
				}
			}
		}
	}()
}
