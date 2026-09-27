import { generateRandomString, sha256Base64Url } from "../../shared/crypto.js";

export async function onRequestGet(context) {
  const provider = context.params.provider;

  if (provider !== "google" && provider !== "github") {
    return new Response("Not Found", { status: 404 });
  }

  const env = context.env;
  const baseUrl = env.PUBLIC_BASE_URL;

  const rawTxId = generateRandomString(32);
  const state = generateRandomString(32);
  const codeVerifier = generateRandomString(32);

  const txHash = await sha256Base64Url(rawTxId);
  const stateHash = await sha256Base64Url(state);
  const codeChallenge = await sha256Base64Url(codeVerifier);

  const expiresAt = Math.floor(Date.now() / 1000) + 600; // 10 minutos
  const redirectUri = `${baseUrl}/oauth/callback/${provider}`;

  let authUrl = "";

  if (provider === "google") {
    const nonce = generateRandomString(32);

    await env.DB.prepare(
      `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(txHash, provider, stateHash, nonce, codeVerifier, expiresAt).run();

    const params = new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "openid email profile",
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      nonce: nonce
    });

    authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  } else if (provider === "github") {
    await env.DB.prepare(
      `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
       VALUES (?, ?, ?, NULL, ?, ?)`
    ).bind(txHash, provider, stateHash, codeVerifier, expiresAt).run();

    const params = new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: "code",
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256"
    });

    authUrl = `https://github.com/login/oauth/authorize?${params.toString()}`;
  }

  const headers = new Headers({
    "Location": authUrl,
    "Cache-Control": "no-store",
    "Set-Cookie": `__Host-oauth-tx=${rawTxId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
  });

  return new Response(null, { status: 302, headers });
}
