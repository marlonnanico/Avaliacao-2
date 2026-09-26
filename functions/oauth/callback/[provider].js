export async function onRequestGet(context) {
  const { request, env, params } = context;
  const providerName = params.provider;

  if (providerName !== "google" && providerName !== "github") {
    return new Response("Não encontrado", { status: 404 });
  }

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error || !code || !state) {
    return new Response("Erro ou parâmetros em falta na resposta do provedor.", { status: 400 });
  }

  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/(?:^|;\s*)Host-oauth-tx=([^;]*)/);
  if (!match) {
    return new Response("Falha na validação do cookie temporário.", { status: 400 });
  }
  const txIdCookie = match[1];

  async function sha256Hex(plain) {
    const data = new TextEncoder().encode(plain);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  async function generateRandomBase64URL(byteLength = 32) {
    const array = new Uint8Array(byteLength);
    crypto.getRandomValues(array);
    let binary = "";
    for (let i = 0; i < array.byteLength; i++) binary += String.fromCharCode(array[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  const txIdHash = await sha256Hex(txIdCookie);
  const stateHash = await sha256Hex(state);
  const now = Math.floor(Date.now() / 1000);

  const tx = await env.DB.prepare(
    `SELECT * FROM oauth_transactions WHERE id_hash = ? AND provider = ? AND expires_at > ?`
  )
    .bind(txIdHash, providerName, now)
    .first();

  if (!tx || tx.state_hash !== stateHash) {
    return new Response("Transação inválida ou expirada.", { status: 400 });
  }

  await env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(txIdHash).run();

  const baseUrl = (env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  const redirectUri = `${baseUrl}/oauth/callback/${providerName}`;

  const clientId = providerName === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;
  const clientSecret = providerName === "google" ? env.GOOGLE_CLIENT_SECRET : env.GITHUB_CLIENT_SECRET;

  const tokenUrl = providerName === "google"
    ? "https://oauth2.googleapis.com/token"
    : "https://github.com/login/oauth/access_token";

  const bodyParams = new URLSearchParams();
  bodyParams.set("client_id", clientId);
  bodyParams.set("client_secret", clientSecret);
  bodyParams.set("code", code);
  bodyParams.set("redirect_uri", redirectUri);
  bodyParams.set("grant_type", "authorization_code");
  if (providerName === "google") {
    bodyParams.set("code_verifier", tx.code_verifier);
  }

  const tokenRes = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json"
    },
    body: bodyParams.toString()
  });

  if (!tokenRes.ok) {
    return new Response("Falha na troca de tokens", { status: 400 });
  }

  const tokenData = await tokenRes.json();
  let issuer = "";
  let subject = "";
  let email = null;
  let displayName = null;

  if (providerName === "google") {
    const idToken = tokenData.id_token;
    if (!idToken) return new Response("ID token ausente na resposta do Google.", { status: 400 });

    const parts = idToken.split(".");
    if (parts.length !== 3) return new Response("Formato de ID token inválido.", { status: 400 });

    const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
    if (header.alg !== "RS256") return new Response("Algoritmo JWT inválido.", { status: 400 });

    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    if (payload.iss !== "https://accounts.google.com" && payload.iss !== "accounts.google.com") {
      return new Response("Emissor inválido.", { status: 400 });
    }
    if (payload.aud !== clientId) return new Response("Audiência inválida.", { status: 400 });
    if (payload.exp < now) return new Response("Token expirado.", { status: 400 });
    if (tx.nonce && payload.nonce !== tx.nonce) return new Response("Nonce inválido.", { status: 400 });

    issuer = "https://accounts.google.com";
    subject = payload.sub;
    email = payload.email || null;
    displayName = payload.name || payload.email || "Utilizador Google";

  } else {
    const accessToken = tokenData.access_token;
    if (!accessToken) return new Response("Access token ausente na resposta do GitHub.", { status: 400 });

    const userRes = await fetch("https://api.github.com/user", {
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "Cloudflare-Pages-Auth"
      }
    });

    if (!userRes.ok) return new Response("Falha ao consultar perfil no GitHub.", { status: 400 });

    const userData = await userRes.json();
    issuer = "https://github.com";
    subject = String(userData.id);
    displayName = userData.name || userData.login || "Utilizador GitHub";
    email = userData.email || null;

    // Revogação imediata da aplicação OAuth conforme o roteiro
    await fetch(`https://api.github.com/applications/${clientId}/grant`, {
      method: "DELETE",
      headers: {
        "Authorization": "Basic " + btoa(`${clientId}:${clientSecret}`),
        "Content-Type": "application/json",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "Cloudflare-Pages-Auth"
      },
      body: JSON.stringify({ access_token: accessToken })
    }).catch(() => {});
  }

  const sessionId = await generateRandomBase64URL(32);
  const sessionIdHash = await sha256Hex(sessionId);
  const sessionExpiresAt = now + 28800; // 8 horas

  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(sessionIdHash, issuer, subject, email, displayName, sessionExpiresAt, now)
    .run();

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${baseUrl}/`,
      "Set-Cookie": [
        `Host-session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,
        `Host-oauth-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
      ].join(", "),
      "Cache-Control": "no-store",
    },
  });
}
