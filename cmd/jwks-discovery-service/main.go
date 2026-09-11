package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/lukaspj/jwks-discovery-service/internal/config"
	"github.com/lukaspj/jwks-discovery-service/internal/jwks"
	"github.com/lukaspj/jwks-discovery-service/internal/refresher"
	"github.com/lukaspj/jwks-discovery-service/internal/server"
	"github.com/lukaspj/jwks-discovery-service/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg, err := config.FromEnv()
	if err != nil {
		logger.Error("configuration error", "err", err)
		os.Exit(1)
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(cfg.Region))
	if err != nil {
		logger.Error("load AWS config", "err", err)
		os.Exit(1)
	}

	s3Opts := []func(*s3.Options){}
	if cfg.Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = cfg.PathStyle
		})
	}
	s3Client := s3.NewFromConfig(awsCfg, s3Opts...)

	registry := jwks.NewRegistry()
	ready := server.NewReady()
	resc := &refresher.Rescan{
		Store:    store.New(s3Client, cfg.Bucket, cfg.Prefix),
		Registry: registry,
		Ready:    ready,
		Logger:   logger,
		KidStyle: jwks.KidStyle(cfg.KidStyle),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	resc.Start(ctx, cfg.RescanEvery)

	handler := server.New(registry, ready, logger, cfg.PublicURL)
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("listening", "addr", cfg.Addr, "bucket", cfg.Bucket, "prefix", cfg.Prefix)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
	}
}
