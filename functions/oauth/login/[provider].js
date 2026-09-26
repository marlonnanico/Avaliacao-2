export async function onRequestGet(context) {
  const { request, env, params } = context;
  const providerName = params.provider;

  if (providerName !== "google" && providerName !== "github") {
    return new Response("Não encontrado", { status: 404 });
  }

  async function generateRandomBase64URL(byteLength = 32) {
    const array = new Uint8Array(byteLength);
    crypto.getRandomValues(array);
    let binary = "";
    for (let i = 0; i < array.byteLength; i++) binary += String.fromCharCode(array[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function sha256Hex(plain) {
    const data = new TextEncoder().encode(plain);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  async function sha256Base64URL(plain) {
    const data = new TextEncoder().encode(plain);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  const txId = await generateRandomBase64URL(32);
  const state = await generateRandomBase64URL(32);
  const codeVerifier = await generateRandomBase64URL(32);
  const codeChallenge = await sha256Base64URL(codeVerifier);
  const nonce = providerName === "google" ? await generateRandomBase64URL(32) : null;

  const txIdHash = await sha256Hex(txId);
  const stateHash = await sha256Hex(state);
  const expiresAt = Math.floor(Date.now() / 1000) + 600;

  // Lê a variável de ambiente configurada na Cloudflare
  const baseUrl = (env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  const redirectUri = `${baseUrl}/oauth/callback/${providerName}`;

  await env.DB.prepare(
    `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at) VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(txIdHash, providerName, stateHash, nonce || "", codeVerifier, expiresAt)
    .run();

  const authUrl = new URL(providerName === "google" 
    ? "https://accounts.google.com/o/oauth2/v2/auth" 
    : "https://github.com/login/oauth/authorize");

  authUrl.searchParams.set("client_id", providerName === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  if (providerName === "google") {
    authUrl.searchParams.set("scope", "openid email profile");
    authUrl.searchParams.set("nonce", nonce);
  } else if (providerName === "github") {
    authUrl.searchParams.set("scope", "read:user user:email");
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl.toString(),
      "Set-Cookie": `Host-oauth-tx=${txId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
      "Cache-Control": "no-store",
    },
  });
}
