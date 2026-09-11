// Package jwks converts X.509 certificates (PEM) into RFC 7517 JWK Sets
// and keeps an in-memory registry that is refreshed from the store.
package jwks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync/atomic"
)

// KidStyle selects how the kid of a JWK is computed.
type KidStyle string

const (
	// KidStyleRFC7638 is the RFC 7638 SHA-256 thumbprint over the
	// canonical required JWK members, base64url-encoded without padding.
	// The default.
	KidStyleRFC7638 KidStyle = "rfc7638"
	// KidStyleSPKIB64URL is the kid style used by kube-apiserver when
	// signing service account tokens (keyIDFromPublicKey in
	// pkg/serviceaccount/jwt.go): base64url-unpadded SHA-256 of the
	// DER-encoded SubjectPublicKeyInfo.
	KidStyleSPKIB64URL KidStyle = "spki-b64url"
	// KidStyleSPKIHex is the kid used by client-go keyutil.NewKeyID
	// (also kube-apiserver SA key listing): lowercase hex SHA-256 of
	// the DER-encoded SubjectPublicKeyInfo.
	KidStyleSPKIHex KidStyle = "spki-hex"
)

// JWK is a JSON Web Key. Unused fields are omitted per RFC 7517 §3.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	N   string `json:"n,omitempty"` // RSA modulus
	E   string `json:"e,omitempty"` // RSA exponent
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKSet is a RFC 7517 key set document.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// ParseCertificates decodes every CERTIFICATE block in a PEM blob and
// returns them leaf-first, in the order they appear in the blob.
func ParseCertificates(pemData string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found in PEM")
	}
	return certs, nil
}

// parsePEMPublicKeys extracts the public keys of every CERTIFICATE and
// PUBLIC KEY (SubjectPublicKeyInfo) block in a PEM blob, in order.
func parsePEMPublicKeys(pemData string) ([]any, error) {
	var keys []any
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			keys = append(keys, cert.PublicKey)
		case "PUBLIC KEY":
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse public key: %w", err)
			}
			keys = append(keys, pub)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE or PUBLIC KEY blocks found in PEM")
	}
	return keys, nil
}

// KeyID returns the RFC 7638-style thumbprint of the certificate's public
// key, base64url-encoded without padding. This is stable across
// certificate renewals as long as the key pair is reused.
func KeyID(cert *x509.Certificate) (string, error) {
	jwk, err := publicKeyJWK(cert.PublicKey)
	if err != nil {
		return "", err
	}
	thumbprint, err := rfc7638Thumbprint(jwk)
	if err != nil {
		return "", err
	}
	return thumbprint, nil
}

// Set builds a JWK Set from one or more PEM certificates or PKIX
// "PUBLIC KEY" blocks. Each unique public key yields one JWK; the kid
// is computed with the given kid style.
func Set(pemData string, style KidStyle) (*JWKSet, error) {
	pubkeys, err := parsePEMPublicKeys(pemData)
	if err != nil {
		return nil, err
	}
	set := &JWKSet{Keys: []JWK{}}
	seen := map[string]bool{}
	for _, pub := range pubkeys {
		jwk, err := publicKeyJWK(pub)
		if err != nil {
			return nil, err
		}
		kid, err := kidFor(pub, style)
		if err != nil {
			return nil, err
		}
		if seen[kid] {
			continue
		}
		seen[kid] = true
		jwk.Kid = kid
		jwk.Use = "sig"
		jwk.Alg = defaultAlg(jwk.Kty, jwk.Crv)
		set.Keys = append(set.Keys, *jwk)
	}
	return set, nil
}

// kidFor computes the kid for a public key using the given style.
func kidFor(pub any, style KidStyle) (string, error) {
	switch style {
	case "", KidStyleRFC7638:
		jwk, err := publicKeyJWK(pub)
		if err != nil {
			return "", err
		}
		return rfc7638Thumbprint(jwk)
	case KidStyleSPKIB64URL, KidStyleSPKIHex:
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", fmt.Errorf("marshal SPKI: %w", err)
		}
		sum := sha256.Sum256(der)
		if style == KidStyleSPKIHex {
			return hex.EncodeToString(sum[:]), nil
		}
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unknown kid style %q", style)
	}
}

func publicKeyJWK(pub any) (*JWK, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return &JWK{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		crv, byteLen := curveParams(key.Curve)
		if crv == "" {
			return nil, fmt.Errorf("unsupported ECDSA curve: %T", key.Curve)
		}
		return &JWK{
			Kty: "EC",
			Crv: crv,
			X:   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, byteLen))),
			Y:   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, byteLen))),
		}, nil
	case ed25519.PublicKey:
		return &JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(key),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

func curveParams(c elliptic.Curve) (string, int) {
	switch c {
	case elliptic.P256():
		return "P-256", 32
	case elliptic.P384():
		return "P-384", 48
	case elliptic.P521():
		return "P-521", 66
	}
	return "", 0
}

func defaultAlg(kty, crv string) string {
	switch kty {
	case "RSA":
		return "RS256"
	case "EC":
		switch crv {
		case "P-256":
			return "ES256"
		case "P-384":
			return "ES384"
		case "P-521":
			return "ES512"
		}
	case "OKP":
		return "EdDSA"
	}
	return ""
}

// rfc7638Thumbprint computes the SHA-256 thumbprint over the required
// members of the JWK, per RFC 7638, base64url-encoded without padding.
func rfc7638Thumbprint(jwk *JWK) (string, error) {
	var required string
	switch jwk.Kty {
	case "RSA":
		required = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, jwk.E, jwk.N)
	case "EC":
		required = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, jwk.Crv, jwk.X, jwk.Y)
	case "OKP":
		required = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, jwk.Crv, jwk.X)
	default:
		return "", fmt.Errorf("cannot thumbprint kty %q", jwk.Kty)
	}
	sum := sha256.Sum256([]byte(required))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// Marshal renders the set as compact JSON, the wire format for JWKS.
func (s *JWKSet) Marshal() ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal jwks: %w", err)
	}
	return b, nil
}

// Service is a discovered service: its JWKS plus OIDC metadata.
type Service struct {
	Set    *JWKSet
	Issuer string
}

// Registry holds the currently loaded services, swapped atomically on
// each successful rescan.
type Registry struct {
	current atomic.Pointer[map[string]*Service]
}

func NewRegistry() *Registry {
	return &Registry{}
}

// Swap atomically replaces the registry contents.
func (r *Registry) Swap(sets map[string]*Service) {
	r.current.Store(&sets)
}

// Get returns the service for a name, or nil if unknown.
func (r *Registry) Get(name string) *Service {
	p := r.current.Load()
	if p == nil {
		return nil
	}
	return (*p)[name]
}

// Count returns the number of registered services.
func (r *Registry) Count() int {
	p := r.current.Load()
	if p == nil {
		return 0
	}
	return len(*p)
}

// SigningAlgs returns the distinct JWS "alg" values in the set.
func (s *JWKSet) SigningAlgs() []string {
	seen := map[string]bool{}
	algs := []string{}
	for _, k := range s.Keys {
		if k.Alg != "" && !seen[k.Alg] {
			seen[k.Alg] = true
			algs = append(algs, k.Alg)
		}
	}
	return algs
}
