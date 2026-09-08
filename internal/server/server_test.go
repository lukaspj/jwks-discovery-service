package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lukaspj/jwks-discovery-service/internal/jwks"
)

func testRegistry() (*jwks.Registry, *Ready) {
	reg := jwks.NewRegistry()
	reg.Swap(map[string]*jwks.Service{
		"payments": {
			Set:    &jwks.JWKSet{Keys: []jwks.JWK{{Kty: "RSA", Kid: "abc", Alg: "RS256"}}},
			Issuer: "https://payments.example.com",
		},
	})
	ready := NewReady()
	ready.Set(true)
	return reg, ready
}

func TestJWKSEndpoint(t *testing.T) {
	reg, ready := testRegistry()
	h := New(reg, ready, nil, "https://keys.example.com")

	req := httptest.NewRequest("GET", "/payments/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type = %q", ct)
	}
	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(body.Keys) != 1 || body.Keys[0]["kid"] != "abc" {
		t.Errorf("unexpected body: %s", rec.Body.String())
	}
}

func TestWellKnownAlias(t *testing.T) {
	reg, ready := testRegistry()
	h := New(reg, ready, nil, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/payments/.well-known", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("alias endpoint: want 200, got %d", rec.Code)
	}
}

func TestUnknownService(t *testing.T) {
	reg, ready := testRegistry()
	h := New(reg, ready, nil, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/nope/.well-known/jwks.json", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestReadyz(t *testing.T) {
	reg, _ := testRegistry()
	ready := NewReady()
	h := New(reg, ready, nil, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("before ready: want 503, got %d", rec.Code)
	}

	ready.Set(true)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("after ready: want 200, got %d", rec.Code)
	}
}

func TestOpenIDConfiguration(t *testing.T) {
	reg, ready := testRegistry()
	h := New(reg, ready, nil, "https://keys.example.com/")

	req := httptest.NewRequest("GET", "/payments/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var doc OIDCDiscovery
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if doc.Issuer != "https://payments.example.com" {
		t.Errorf("issuer = %q", doc.Issuer)
	}
	if doc.JWKSURI != "https://keys.example.com/payments/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %q", doc.JWKSURI)
	}
	if len(doc.IDTokenSigningAlgs) != 1 || doc.IDTokenSigningAlgs[0] != "RS256" {
		t.Errorf("signing algs = %v", doc.IDTokenSigningAlgs)
	}
}

func TestOpenIDConfigurationDerivedURL(t *testing.T) {
	reg := jwks.NewRegistry()
	reg.Swap(map[string]*jwks.Service{
		"s1": {Set: &jwks.JWKSet{Keys: []jwks.JWK{{Kty: "RSA", Alg: "RS256"}}}},
	})
	ready := NewReady()
	ready.Set(true)
	h := New(reg, ready, nil, "")

	req := httptest.NewRequest("GET", "http://srv.example.com/s1/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var doc OIDCDiscovery
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if doc.Issuer != "http://srv.example.com/s1" {
		t.Errorf("issuer = %q", doc.Issuer)
	}
	if doc.JWKSURI != "http://srv.example.com/s1/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %q", doc.JWKSURI)
	}
}
