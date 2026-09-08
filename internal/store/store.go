package store

import (
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"gopkg.in/yaml.v3"
)

// Manifest is a single service definition stored as YAML in the bucket.
// The PEM certificate(s) are embedded inline; a PEM blob may contain a
// leaf certificate followed by intermediates.
type Manifest struct {
	Name    string            `yaml:"name"`
	CertPEM string            `yaml:"cert"`
	Config  map[string]string `yaml:"config"`
}

type Client struct {
	s3     *s3.Client
	bucket string
	prefix string
}

func New(s3c *s3.Client, bucket, prefix string) *Client {
	return &Client{s3: s3c, bucket: bucket, prefix: prefix}
}

// List returns every valid manifest found under the configured prefix.
// Invalid manifests are reported per key via the returned error list and
// skipped so one bad file does not take down discovery for all services.
func (c *Client) List(ctx context.Context) (map[string]Manifest, []error) {
	manifests := make(map[string]Manifest)
	var errs []error

	paginator := s3.NewListObjectsV2Paginator(c.s3, &s3.ListObjectsV2Input{
		Bucket: aws.String(c.bucket),
		Prefix: aws.String(c.prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, append(errs, fmt.Errorf("list objects: %w", err))
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			m, merr := c.fetch(ctx, key)
			if merr != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, merr))
				continue
			}
			if _, dup := manifests[m.Name]; dup {
				errs = append(errs, fmt.Errorf("%s: duplicate service name %q", key, m.Name))
				continue
			}
			manifests[m.Name] = m
		}
	}
	return manifests, errs
}

func (c *Client) fetch(ctx context.Context, key string) (Manifest, error) {
	var m Manifest
	if !strings.HasSuffix(key, ".yaml") && !strings.HasSuffix(key, ".yml") {
		return m, fmt.Errorf("not a manifest file")
	}

	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return m, fmt.Errorf("get object: %w", err)
	}
	defer out.Body.Close()

	body, err := io.ReadAll(out.Body)
	if err != nil {
		return m, fmt.Errorf("read body: %w", err)
	}

	if err := yaml.Unmarshal(body, &m); err != nil {
		return m, fmt.Errorf("parse yaml: %w", err)
	}
	if m.Name == "" {
		m.Name = strings.TrimSuffix(path.Base(key), path.Ext(key))
	}
	if strings.TrimSpace(m.CertPEM) == "" {
		return m, fmt.Errorf("manifest %q has no cert", m.Name)
	}
	return m, nil
}

// SortedNames is a convenience helper for stable debug output.
func SortedNames(m map[string]Manifest) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
