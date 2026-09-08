package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr          string
	Bucket        string
	Prefix        string
	Region        string
	Endpoint      string
	PathStyle     bool
	RescanEvery   time.Duration
	CacheMaxAge   time.Duration
	PublicURL     string
	LogJSONFormat bool
}

func FromEnv() (*Config, error) {
	c := &Config{
		Addr:        getEnv("LISTEN_ADDR", ":8080"),
		Bucket:      os.Getenv("MANIFEST_BUCKET"),
		Prefix:      getEnv("MANIFEST_PREFIX", ""),
		Region:      getEnv("AWS_REGION", getEnv("AWS_DEFAULT_REGION", "us-east-1")),
		Endpoint:    os.Getenv("S3_ENDPOINT"),
		PathStyle:   getEnvBool("S3_PATH_STYLE", false),
		RescanEvery: getEnvDuration("RESCAN_INTERVAL", 60*time.Second),
		CacheMaxAge: getEnvDuration("CACHE_MAX_AGE", 0),
		PublicURL:   strings.TrimSuffix(os.Getenv("PUBLIC_URL"), "/"),
	}
	if c.Bucket == "" {
		return nil, fmt.Errorf("MANIFEST_BUCKET is required")
	}
	if c.RescanEvery <= 0 {
		return nil, fmt.Errorf("RESCAN_INTERVAL must be positive")
	}
	if c.CacheMaxAge < 0 {
		return nil, fmt.Errorf("CACHE_MAX_AGE must not be negative")
	}
	if c.CacheMaxAge == 0 {
		c.CacheMaxAge = c.RescanEvery * 3
	}
	return c, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func getEnvDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
