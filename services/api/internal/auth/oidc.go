package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxOIDCResponseBytes = 1 << 20

type OIDCConfig struct {
	IssuerURL  string
	ClientID   string
	HTTPClient *http.Client
	Clock      func() time.Time
}

type OIDCVerifier struct {
	issuer     string
	clientID   string
	jwksURL    string
	httpClient *http.Client
	clock      func() time.Time

	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	keysUntil time.Time
}

type discoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_uri"`
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type tokenClaims struct {
	Issuer               string          `json:"iss"`
	Subject              string          `json:"sub"`
	Audience             json.RawMessage `json:"aud"`
	ExpiresAt            json.Number     `json:"exp"`
	NotBefore            json.Number     `json:"nbf"`
	IssuedAt             json.Number     `json:"iat"`
	Name                 string          `json:"name"`
	PreferredUsername    string          `json:"preferred_username"`
	Roles                any             `json:"roles"`
	Groups               any             `json:"groups"`
	KubeAthrixRoles      any             `json:"kubeathrix_roles"`
	KubeAthrixNamespaces any             `json:"kubeathrix_namespaces"`
	KubeAthrixClusters   any             `json:"kubeathrix_clusters"`
	Scope                string          `json:"scope"`
	RealmAccess          struct {
		Roles any `json:"roles"`
	} `json:"realm_access"`
}

type jwksDocument struct {
	Keys []jsonWebKey `json:"keys"`
}

type jsonWebKey struct {
	KeyID string `json:"kid"`
	Use   string `json:"use"`
	Type  string `json:"kty"`
	N     string `json:"n"`
	E     string `json:"e"`
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

func NewOIDCVerifier(ctx context.Context, config OIDCConfig) (*OIDCVerifier, error) {
	issuer := strings.TrimRight(strings.TrimSpace(config.IssuerURL), "/")
	if issuer == "" || strings.TrimSpace(config.ClientID) == "" {
		return nil, fmt.Errorf("OIDC issuer URL and client ID are required")
	}
	if err := validateEndpoint(issuer); err != nil {
		return nil, fmt.Errorf("invalid OIDC issuer: %w", err)
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	verifier := &OIDCVerifier{issuer: issuer, clientID: config.ClientID, httpClient: client, clock: clock}
	discoveryURL := issuer + "/.well-known/openid-configuration"
	var document discoveryDocument
	if _, err := verifier.getJSON(ctx, discoveryURL, &document); err != nil {
		return nil, fmt.Errorf("fetch OIDC discovery: %w", err)
	}
	if strings.TrimRight(document.Issuer, "/") != issuer {
		return nil, fmt.Errorf("OIDC discovery issuer mismatch")
	}
	if err := validateEndpoint(document.JWKSURL); err != nil {
		return nil, fmt.Errorf("invalid OIDC JWKS URI: %w", err)
	}
	verifier.jwksURL = document.JWKSURL
	if err := verifier.refreshKeys(ctx); err != nil {
		return nil, err
	}
	return verifier, nil
}

func (v *OIDCVerifier) Verify(ctx context.Context, rawToken string) (Principal, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 || len(rawToken) > 64*1024 {
		return Principal{}, ErrUnauthenticated
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.KeyID == "" {
		return Principal{}, ErrUnauthenticated
	}
	if header.Algorithm != "RS256" && header.Algorithm != "ES256" {
		return Principal{}, ErrUnauthenticated
	}
	key, err := v.key(ctx, header.KeyID)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !verifySignature(header.Algorithm, key, digest[:], signature) {
		return Principal{}, ErrUnauthenticated
	}
	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	decoder := json.NewDecoder(strings.NewReader(string(claimBytes)))
	decoder.UseNumber()
	var claims tokenClaims
	if err := decoder.Decode(&claims); err != nil {
		return Principal{}, ErrUnauthenticated
	}
	if err := v.validateClaims(claims); err != nil {
		return Principal{}, ErrUnauthenticated
	}
	principal := principalFromClaims(claims)
	if principal.Subject == "" || len(principal.Roles) == 0 {
		return Principal{}, ErrUnauthorized
	}
	return principal, nil
}

func (v *OIDCVerifier) validateClaims(claims tokenClaims) error {
	if strings.TrimRight(claims.Issuer, "/") != v.issuer || claims.Subject == "" {
		return ErrUnauthenticated
	}
	audiences, err := stringListFromRaw(claims.Audience)
	if err != nil || !contains(audiences, v.clientID) {
		return ErrUnauthenticated
	}
	now := v.clock().UTC()
	expiresAt, err := unixClaim(claims.ExpiresAt, true)
	if err != nil || !expiresAt.After(now.Add(-30*time.Second)) {
		return ErrUnauthenticated
	}
	if notBefore, err := unixClaim(claims.NotBefore, false); err != nil || (!notBefore.IsZero() && notBefore.After(now.Add(30*time.Second))) {
		return ErrUnauthenticated
	}
	if issuedAt, err := unixClaim(claims.IssuedAt, false); err != nil || (!issuedAt.IsZero() && issuedAt.After(now.Add(5*time.Minute))) {
		return ErrUnauthenticated
	}
	return nil
}

func principalFromClaims(claims tokenClaims) Principal {
	principal := Principal{
		Subject:    claims.Subject,
		Roles:      map[Role]struct{}{},
		Namespaces: toSet(stringList(claims.KubeAthrixNamespaces)),
		Clusters:   toSet(stringList(claims.KubeAthrixClusters)),
	}
	principal.DisplayName = strings.TrimSpace(claims.PreferredUsername)
	if principal.DisplayName == "" {
		principal.DisplayName = strings.TrimSpace(claims.Name)
	}
	roleValues := append(stringList(claims.Roles), stringList(claims.Groups)...)
	roleValues = append(roleValues, stringList(claims.KubeAthrixRoles)...)
	roleValues = append(roleValues, stringList(claims.RealmAccess.Roles)...)
	for _, value := range roleValues {
		normalized := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(value), "kubeathrix:"), "kubeathrix-")
		switch Role(normalized) {
		case RoleViewer, RoleOperator, RoleApprover, RoleAdministrator:
			principal.Roles[Role(normalized)] = struct{}{}
		}
	}
	for _, value := range strings.Fields(claims.Scope) {
		switch {
		case strings.HasPrefix(value, "kubeathrix:namespace:"):
			principal.Namespaces[strings.TrimPrefix(value, "kubeathrix:namespace:")] = struct{}{}
		case strings.HasPrefix(value, "kubeathrix:cluster:"):
			principal.Clusters[strings.TrimPrefix(value, "kubeathrix:cluster:")] = struct{}{}
		}
	}
	return principal
}

func (v *OIDCVerifier) key(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	v.mu.RLock()
	key := v.keys[keyID]
	expired := v.clock().After(v.keysUntil)
	v.mu.RUnlock()
	if key != nil && !expired {
		return key, nil
	}
	if err := v.refreshKeys(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	key = v.keys[keyID]
	if key == nil {
		return nil, fmt.Errorf("signing key not found")
	}
	return key, nil
}

func (v *OIDCVerifier) refreshKeys(ctx context.Context) error {
	var document jwksDocument
	maxAge, err := v.getJSON(ctx, v.jwksURL, &document)
	if err != nil {
		return fmt.Errorf("fetch OIDC signing keys: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, item := range document.Keys {
		if item.KeyID == "" || (item.Use != "" && item.Use != "sig") {
			continue
		}
		key, err := item.publicKey()
		if err == nil {
			keys[item.KeyID] = key
		}
	}
	if len(keys) == 0 {
		return fmt.Errorf("OIDC JWKS contains no supported signing keys")
	}
	if maxAge <= 0 || maxAge > time.Hour {
		maxAge = 15 * time.Minute
	}
	v.mu.Lock()
	v.keys = keys
	v.keysUntil = v.clock().Add(maxAge)
	v.mu.Unlock()
	return nil
}

func (v *OIDCVerifier) getJSON(ctx context.Context, endpoint string, target any) (time.Duration, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := v.httpClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxOIDCResponseBytes))
	if err := decoder.Decode(target); err != nil {
		return 0, err
	}
	return cacheMaxAge(response.Header.Get("Cache-Control")), nil
}

func (key jsonWebKey) publicKey() (crypto.PublicKey, error) {
	switch key.Type {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil || len(nBytes) < 256 {
			return nil, fmt.Errorf("invalid RSA modulus")
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		exponent := 0
		for _, value := range eBytes {
			exponent = exponent<<8 + int(value)
		}
		if exponent < 3 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: exponent}, nil
	case "EC":
		if key.Curve != "P-256" {
			return nil, fmt.Errorf("unsupported EC curve")
		}
		xBytes, errX := base64.RawURLEncoding.DecodeString(key.X)
		yBytes, errY := base64.RawURLEncoding.DecodeString(key.Y)
		if errX != nil || errY != nil {
			return nil, fmt.Errorf("invalid EC coordinate")
		}
		publicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
		if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
			return nil, fmt.Errorf("EC key is not on curve")
		}
		return publicKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

func verifySignature(algorithm string, key crypto.PublicKey, digest, signature []byte) bool {
	switch algorithm {
	case "RS256":
		publicKey, ok := key.(*rsa.PublicKey)
		return ok && rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest, signature) == nil
	case "ES256":
		publicKey, ok := key.(*ecdsa.PublicKey)
		if !ok || len(signature) != 64 {
			return false
		}
		return ecdsa.Verify(publicKey, digest, new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
	default:
		return false
	}
}

func validateEndpoint(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("absolute URL without credentials or fragment is required")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if parsed.Scheme == "http" && (strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return fmt.Errorf("HTTPS is required for non-loopback endpoints")
}

func unixClaim(number json.Number, required bool) (time.Time, error) {
	if number == "" {
		if required {
			return time.Time{}, fmt.Errorf("required numeric date is missing")
		}
		return time.Time{}, nil
	}
	value, err := strconv.ParseInt(string(number), 10, 64)
	if err != nil || value <= 0 {
		return time.Time{}, fmt.Errorf("invalid numeric date")
	}
	return time.Unix(value, 0).UTC(), nil
}

func stringListFromRaw(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("value is missing")
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return []string{single}, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func stringList(value any) []string {
	switch typed := value.(type) {
	case string:
		if strings.Contains(typed, " ") {
			return strings.Fields(typed)
		}
		if typed != "" {
			return []string{typed}
		}
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok && text != "" {
				result = append(result, text)
			}
		}
		return result
	case []string:
		return typed
	}
	return nil
}

func toSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result[value] = struct{}{}
		}
	}
	return result
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func cacheMaxAge(cacheControl string) time.Duration {
	for _, directive := range strings.Split(cacheControl, ",") {
		parts := strings.SplitN(strings.TrimSpace(directive), "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "max-age") {
			seconds, err := strconv.Atoi(strings.Trim(parts[1], `"`))
			if err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return 0
}
