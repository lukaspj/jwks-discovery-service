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
	reg.Swap(map[string]*jwks.JWKSet{
		"payments": {Keys: []jwks.JWK{{Kty: "RSA", Kid: "abc"}}},
	})
	ready := NewReady()
	ready.Set(true)
	return reg, ready
}

func TestJWKSEndpoint(t *testing.T) {
	reg, ready := testRegistry()
	h := New(reg, ready, nil)

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
	h := New(reg, ready, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/payments/.well-known", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("alias endpoint: want 200, got %d", rec.Code)
	}
}

func TestUnknownService(t *testing.T) {
	reg, ready := testRegistry()
	h := New(reg, ready, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/nope/.well-known/jwks.json", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestReadyz(t *testing.T) {
	reg, _ := testRegistry()
	ready := NewReady()
	h := New(reg, ready, nil)

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
