import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { createServer } from "node:http";

const issuer = "http://127.0.0.1:41740";
const allowedOrigin = "http://127.0.0.1:41739";
const clientID = "kubeathrix";
const keyID = "kubeathrix-e2e";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicJWK = publicKey.export({ format: "jwk" });
const codes = new Map();

const server = createServer(async (request, response) => {
  response.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  response.setHeader("Cache-Control", "no-store");
  if (request.method === "OPTIONS") {
    response.writeHead(204).end();
    return;
  }
  const url = new URL(request.url ?? "/", issuer);
  if (url.pathname === "/health") {
    json(response, 200, { status: "ready" });
    return;
  }
  if (url.pathname === "/.well-known/openid-configuration") {
    json(response, 200, {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks`
    });
    return;
  }
  if (url.pathname === "/jwks") {
    json(response, 200, { keys: [{ ...publicJWK, kid: keyID, use: "sig", alg: "RS256" }] });
    return;
  }
  if (url.pathname === "/authorize" && request.method === "GET") {
    const redirectURI = url.searchParams.get("redirect_uri");
    const state = url.searchParams.get("state");
    const challenge = url.searchParams.get("code_challenge");
    if (url.searchParams.get("client_id") !== clientID || url.searchParams.get("response_type") !== "code" ||
        url.searchParams.get("code_challenge_method") !== "S256" || !redirectURI || !state || !challenge ||
        new URL(redirectURI).origin !== allowedOrigin) {
      json(response, 400, { error: "invalid_request" });
      return;
    }
    const code = randomBytes(24).toString("base64url");
    codes.set(code, { challenge, redirectURI, expiresAt: Date.now() + 60_000 });
    const callback = new URL(redirectURI);
    callback.searchParams.set("code", code);
    callback.searchParams.set("state", state);
    response.writeHead(302, { Location: callback.toString() }).end();
    return;
  }
  if (url.pathname === "/token" && request.method === "POST") {
    const body = await readBody(request);
    const parameters = new URLSearchParams(body);
    const code = parameters.get("code") ?? "";
    const record = codes.get(code);
    codes.delete(code);
    const verifier = parameters.get("code_verifier") ?? "";
    const actualChallenge = createHash("sha256").update(verifier).digest("base64url");
    if (!record || record.expiresAt < Date.now() || record.challenge !== actualChallenge ||
        parameters.get("client_id") !== clientID || parameters.get("grant_type") !== "authorization_code" ||
        parameters.get("redirect_uri") !== record.redirectURI) {
      json(response, 400, { error: "invalid_grant" });
      return;
    }
    json(response, 200, { access_token: accessToken(), token_type: "Bearer", expires_in: 300 });
    return;
  }
  json(response, 404, { error: "not_found" });
});

server.listen(41740, "127.0.0.1");

function accessToken() {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: keyID, typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    iss: issuer,
    sub: "oidc-e2e-operator",
    aud: clientID,
    iat: now,
    nbf: now - 1,
    exp: now + 300,
    name: "OIDC E2E Operator",
    kubeathrix_roles: ["administrator"],
    kubeathrix_namespaces: ["*"],
    kubeathrix_clusters: ["*"]
  })).toString("base64url");
  const signingInput = `${header}.${payload}`;
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

function json(response, status, value) {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(value));
}

async function readBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 64 * 1024) throw new Error("request body too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}
