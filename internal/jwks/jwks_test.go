package jwks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func makeCert(t *testing.T, pub any, priv any) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func encodePEM(certs ...*x509.Certificate) string {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return string(out)
}

func TestSetRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeCert(t, &key.PublicKey, key)
	set, err := Set(encodePEM(cert))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" {
		t.Errorf("unexpected key header: %+v", k)
	}
	if k.N == "" || k.E != "AQAB" {
		t.Errorf("unexpected RSA params: e=%q n.len=%d", k.E, len(k.N))
	}
	if k.Kid == "" {
		t.Error("missing kid")
	}
}

func TestSetECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeCert(t, &key.PublicKey, key)
	set, err := Set(encodePEM(cert))
	if err != nil {
		t.Fatal(err)
	}
	k := set.Keys[0]
	if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" {
		t.Errorf("unexpected EC key: %+v", k)
	}
	if len(k.X) == 0 || len(k.Y) == 0 {
		t.Error("missing EC coordinates")
	}
}

func TestSetEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeCert(t, pub, priv)
	set, err := Set(encodePEM(cert))
	if err != nil {
		t.Fatal(err)
	}
	k := set.Keys[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" {
		t.Errorf("unexpected OKP key: %+v", k)
	}
}

func TestSetDeduplicatesSameKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c1 := makeCert(t, &key.PublicKey, key)
	c2 := makeCert(t, &key.PublicKey, key)
	set, err := Set(encodePEM(c1, c2))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want deduplicated 1 key, got %d", len(set.Keys))
	}
}

func TestSetRejectsNoCertificates(t *testing.T) {
	if _, err := Set("not a pem"); err == nil {
		t.Fatal("want error for non-PEM input")
	}
}

func encodePublicKeyPEM(pub any) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestSetPKIXPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemData := encodePublicKeyPEM(&rsaKey.PublicKey) + encodePublicKeyPEM(&ecKey.PublicKey) + encodePublicKeyPEM(edPub)
	set, err := Set(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 3 {
		t.Fatalf("want 3 keys, got %d", len(set.Keys))
	}
	types := map[string]bool{}
	for _, k := range set.Keys {
		types[k.Kty] = true
		if k.Kid == "" || k.Use != "sig" || k.Alg == "" {
			t.Errorf("missing header fields: %+v", k)
		}
	}
	if !types["RSA"] || !types["EC"] || !types["OKP"] {
		t.Errorf("want RSA, EC, OKP keys, got %v", types)
	}
}

func TestSetCertAndPKIXDeduplicated(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeCert(t, &key.PublicKey, key)
	pemData := encodePEM(cert) + encodePublicKeyPEM(&key.PublicKey)
	set, err := Set(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want deduplicated 1 key, got %d", len(set.Keys))
	}
}

func TestSetMixedCertAndPKIX(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeCert(t, &key1.PublicKey, key1)
	pemData := encodePEM(cert) + encodePublicKeyPEM(&key2.PublicKey)
	set, err := Set(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(set.Keys))
	}
}

func TestSetInvalidPublicKeyPEM(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")})
	if _, err := Set(string(block)); err == nil {
		t.Fatal("want error for invalid PKIX public key")
	}
}

func TestRegistrySwapAndGet(t *testing.T) {
	reg := NewRegistry()
	if reg.Get("x") != nil {
		t.Fatal("empty registry must return nil")
	}
	if reg.Count() != 0 {
		t.Fatal("empty registry count must be 0")
	}
	set := &JWKSet{Keys: []JWK{{Kty: "RSA"}}}
	reg.Swap(map[string]*Service{"x": {Set: set}})
	if reg.Get("x") == nil || reg.Get("x").Set != set || reg.Count() != 1 {
		t.Fatal("swap/get mismatch")
	}
}
