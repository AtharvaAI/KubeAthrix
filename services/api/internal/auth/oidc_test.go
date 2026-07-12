package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOIDCVerifierValidatesSignatureClaimsRolesAndScopes(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 7, 11, 18, 0, 0, 0, time.UTC)
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": issuer + "/keys"})
		case "/keys":
			w.Header().Set("Cache-Control", "public, max-age=300")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK("test-key", &privateKey.PublicKey)}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL

	verifier, err := NewOIDCVerifier(context.Background(), OIDCConfig{
		IssuerURL: issuer,
		ClientID:  "kubeathrix",
		Clock:     func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatal(err)
	}
	token := signedToken(t, privateKey, "test-key", map[string]any{
		"iss":                   issuer,
		"sub":                   "user-123",
		"aud":                   []string{"another-client", "kubeathrix"},
		"exp":                   fixed.Add(10 * time.Minute).Unix(),
		"iat":                   fixed.Add(-time.Minute).Unix(),
		"preferred_username":    "platform-sre",
		"kubeathrix_roles":      []string{"operator"},
		"kubeathrix_namespaces": []string{"payments"},
		"scope":                 "openid kubeathrix:namespace:platform",
	})
	principal, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Subject != "user-123" || principal.Actor() != "platform-sre (user-123)" {
		t.Fatalf("unexpected principal: %#v", principal)
	}
	if !principal.HasRole(RoleOperator) || !principal.HasRole(RoleViewer) {
		t.Fatalf("operator role was not derived: %#v", principal.Roles)
	}
	if !principal.CanAccessNamespace("cluster-a", "payments") || !principal.CanAccessNamespace("cluster-a", "platform") {
		t.Fatalf("namespace scopes were not derived: %#v", principal.Namespaces)
	}
}

func TestOIDCVerifierRejectsInvalidAudienceExpiryAndSignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 7, 11, 18, 0, 0, 0, time.UTC)
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": issuer + "/keys"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK("test-key", &privateKey.PublicKey)}})
	}))
	defer server.Close()
	issuer = server.URL
	verifier, err := NewOIDCVerifier(context.Background(), OIDCConfig{IssuerURL: issuer, ClientID: "kubeathrix", Clock: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	baseClaims := map[string]any{
		"iss": issuer, "sub": "user-123", "aud": "kubeathrix",
		"exp": fixed.Add(10 * time.Minute).Unix(), "kubeathrix_roles": []string{"viewer"},
	}
	tests := []struct {
		name   string
		key    *rsa.PrivateKey
		claims map[string]any
	}{
		{name: "wrong signature", key: otherKey, claims: cloneClaims(baseClaims)},
		{name: "wrong audience", key: privateKey, claims: withClaim(baseClaims, "aud", "other-client")},
		{name: "expired", key: privateKey, claims: withClaim(baseClaims, "exp", fixed.Add(-time.Minute).Unix())},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verifier.Verify(context.Background(), signedToken(t, test.key, "test-key", test.claims)); err == nil {
				t.Fatal("expected token verification to fail")
			}
		})
	}
}

func rsaJWK(keyID string, publicKey *rsa.PublicKey) map[string]string {
	exponent := big.NewInt(int64(publicKey.E)).Bytes()
	return map[string]string{
		"kid": keyID,
		"use": "sig",
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(exponent),
	}
}

func signedToken(t *testing.T, privateKey *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	headerBytes, err := json.Marshal(map[string]string{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	claimBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimBytes)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func cloneClaims(source map[string]any) map[string]any {
	result := map[string]any{}
	for key, value := range source {
		result[key] = value
	}
	return result
}

func withClaim(source map[string]any, key string, value any) map[string]any {
	result := cloneClaims(source)
	result[key] = value
	return result
}
