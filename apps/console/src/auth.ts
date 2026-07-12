const TOKEN_KEY = "kubeathrix.oidc.access_token";
const TOKEN_EXPIRY_KEY = "kubeathrix.oidc.expires_at";
const STATE_KEY = "kubeathrix.oidc.state";
const VERIFIER_KEY = "kubeathrix.oidc.verifier";

export interface AuthConfig {
  mode: "oidc" | "development";
  issuerURL: string;
  clientID: string;
}

interface OIDCDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
}

export type AuthState =
  | { status: "authenticated"; config: AuthConfig }
  | { status: "login_required"; config: AuthConfig }
  | { status: "error"; message: string };

let initialization: Promise<AuthState> | undefined;

export function accessToken(): string | null {
  const token = sessionStorage.getItem(TOKEN_KEY);
  const expiresAt = Number(sessionStorage.getItem(TOKEN_EXPIRY_KEY) ?? "0");
  if (!token || !expiresAt || Date.now() >= expiresAt - 30_000) {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(TOKEN_EXPIRY_KEY);
    return null;
  }
  return token;
}

export function clearAuthentication(): void {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(TOKEN_EXPIRY_KEY);
  sessionStorage.removeItem(STATE_KEY);
  sessionStorage.removeItem(VERIFIER_KEY);
}

export function initializeAuth(): Promise<AuthState> {
  initialization ??= initializeAuthOnce();
  return initialization;
}

async function initializeAuthOnce(): Promise<AuthState> {
  try {
    const response = await fetch("/auth/config", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`Authentication configuration returned ${response.status}`);
    const config = (await response.json()) as AuthConfig;
    if (config.mode === "development") return { status: "authenticated", config };
    if (!config.issuerURL || !config.clientID) throw new Error("OIDC issuer and client ID are not configured");

    const parameters = new URLSearchParams(window.location.search);
    const code = parameters.get("code");
    if (code) {
      const expectedState = sessionStorage.getItem(STATE_KEY);
      const verifier = sessionStorage.getItem(VERIFIER_KEY);
      if (!expectedState || parameters.get("state") !== expectedState || !verifier) throw new Error("OIDC callback state validation failed");
      const discovery = await discover(config.issuerURL);
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        client_id: config.clientID,
        code,
        code_verifier: verifier,
        redirect_uri: redirectURI()
      });
      const tokenResponse = await fetch(discovery.token_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });
      if (!tokenResponse.ok) throw new Error(`OIDC token exchange returned ${tokenResponse.status}`);
      const token = (await tokenResponse.json()) as { access_token?: string; expires_in?: number };
      if (!token.access_token) throw new Error("OIDC token response did not include an access token");
      sessionStorage.setItem(TOKEN_KEY, token.access_token);
      sessionStorage.setItem(TOKEN_EXPIRY_KEY, String(Date.now() + Math.max(token.expires_in ?? 300, 60) * 1000));
      sessionStorage.removeItem(STATE_KEY);
      sessionStorage.removeItem(VERIFIER_KEY);
      window.history.replaceState({}, document.title, redirectURI());
    }
    return accessToken() ? { status: "authenticated", config } : { status: "login_required", config };
  } catch (error) {
    return { status: "error", message: error instanceof Error ? error.message : "Authentication initialization failed" };
  }
}

export async function beginLogin(config: AuthConfig): Promise<void> {
  const discovery = await discover(config.issuerURL);
  const verifier = randomURLSafe(64);
  const state = randomURLSafe(32);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const challenge = base64URL(new Uint8Array(digest));
  sessionStorage.setItem(STATE_KEY, state);
  sessionStorage.setItem(VERIFIER_KEY, verifier);
  const authorization = new URL(discovery.authorization_endpoint);
  authorization.search = new URLSearchParams({
    response_type: "code",
    client_id: config.clientID,
    redirect_uri: redirectURI(),
    scope: "openid profile email",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  }).toString();
  window.location.assign(authorization.toString());
}

function redirectURI(): string {
  return `${window.location.origin}${window.location.pathname}`;
}

async function discover(issuer: string): Promise<OIDCDiscovery> {
  const response = await fetch(`${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`OIDC discovery returned ${response.status}`);
  const discovery = (await response.json()) as OIDCDiscovery;
  if (!validBrowserEndpoint(discovery.authorization_endpoint) || !validBrowserEndpoint(discovery.token_endpoint)) {
    throw new Error("OIDC browser endpoints must use HTTPS except on the local loopback interface");
  }
  return discovery;
}

function validBrowserEndpoint(raw: string | undefined): boolean {
  if (!raw) return false;
  try {
    const endpoint = new URL(raw);
    if (endpoint.username || endpoint.password || endpoint.hash) return false;
    if (endpoint.protocol === "https:") return true;
    const host = endpoint.hostname.toLowerCase();
    return endpoint.protocol === "http:" && (host === "localhost" || host === "127.0.0.1" || host === "[::1]");
  } catch {
    return false;
  }
}

function randomURLSafe(length: number): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return base64URL(bytes);
}

function base64URL(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((value) => { binary += String.fromCharCode(value); });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
