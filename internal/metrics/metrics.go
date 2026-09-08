package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ServicesLoaded = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "jwks_services_loaded",
		Help: "Number of services currently exposed.",
	})
	RescansTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "jwks_rescans_total",
		Help: "Store rescans by outcome.",
	}, []string{"outcome"})
	LastRescanSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "jwks_last_rescan_timestamp_seconds",
		Help: "Unix timestamp of the last completed rescan.",
	})
	HTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "jwks_http_requests_total",
		Help: "HTTP requests by route and status.",
	}, []string{"route", "code"})
)
