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
    return new Response("Parâmetros inválidos ou erro no provedor", { status: 400 });
  }

  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/Host-oauth-tx=([^;]+)/);
  const txCookie = match ? match[1] : null;

  if (!txCookie) return new Response("Cookie de transação ausente", { status: 400 });

  async function sha256Hex(plain) {
    const data = new TextEncoder().encode(plain);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  const txIdHash = await sha256Hex(txCookie);
  const now = Math.floor(Date.now() / 1000);

  const tx = await env.DB.prepare(
    "SELECT * FROM oauth_transactions WHERE id_hash = ? AND provider = ? AND expires_at > ?"
  )
    .bind(txIdHash, providerName, now)
    .first();

  if (!tx) return new Response("Transação expirada ou inválida", { status: 400 });

  const stateHash = await sha256Hex(state);
  if (stateHash !== tx.state_hash) {
    return new Response("State inválido", { status: 400 });
  }

  // Apaga a transação imediatamente para evitar reutilização
  await env.DB.prepare("DELETE FROM oauth_transactions WHERE id_hash = ?").bind(txIdHash).run();

  const clientId = providerName === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;
  const clientSecret = providerName === "google" ? env.GOOGLE_CLIENT_SECRET : env.GITHUB_CLIENT_SECRET;
  const tokenUrl = providerName === "google" 
    ? "https://oauth2.googleapis.com/token" 
    : "https://github.com/login/oauth/access_token";
  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${providerName}`;

  const bodyParams = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code: code,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
    code_verifier: tx.code_verifier,
  });

  const tokenRes = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: bodyParams,
  });

  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    return new Response("Falha na troca de tokens", { status: 400 });
  }

  let issuer = "";
  let subject = "";
  let email = null;
  let displayName = "";

  if (providerName === "google") {
    const parts = tokenData.id_token.split(".");
    if (parts.length !== 3) return new Response("JWT do Google inválido", { status: 400 });

    const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
    if (header.alg !== "RS256") return new Response("Algoritmo JWT não suportado", { status: 400 });

    const discoveryRes = await fetch("https://accounts.google.com/.well-known/openid-configuration");
    const discovery = await discoveryRes.json();
    const jwksRes = await fetch(discovery.jwks_uri);
    const jwks = await jwksRes.json();

    const keyData = jwks.keys.find((k) => k.kid === header.kid);
    if (!keyData) return new Response("Chave JWKS não encontrada", { status: 400 });

    const pubKey = await crypto.subtle.importKey(
      "jwk", keyData, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
    );

    const signatureBytes = Uint8Array.from(atob(parts[2].replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    const dataBytes = new TextEncoder().encode(parts[0] + "." + parts[1]);
    const isValid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", pubKey, signatureBytes, dataBytes);

    if (!isValid) return new Response("Assinatura do JWT inválida", { status: 400 });

    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    if (payload.exp < now) return new Response("Token expirado", { status: 400 });
    if (payload.aud !== clientId) return new Response("Audiência inválida", { status: 400 });
    if (payload.nonce !== tx.nonce) return new Response("Nonce inválido", { status: 400 });

    issuer = "https://accounts.google.com";
    subject = payload.sub;
    email = payload.email || null;
    displayName = payload.name || payload.email || "Usuário Google";

  } else if (providerName === "github") {
    const userRes = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "Cloudflare-Pages-Lab",
      },
    });

    if (!userRes.ok) return new Response("Falha ao consultar perfil do GitHub", { status: 400 });
    const userData = await userRes.json();

    issuer = "https://github.com";
    subject = String(userData.id);
    displayName = userData.name || userData.login;
    email = userData.email || null;

    // Revoga a autorização no GitHub conforme exigido no roteiro
    const basicAuth = btoa(`${clientId}:${clientSecret}`);
    await fetch(`https://api.github.com/applications/${clientId}/grant`, {
      method: "DELETE",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "Cloudflare-Pages-Lab",
      },
      body: JSON.stringify({ access_token: tokenData.access_token }),
    });
  }

  // Criação da sessão local no D1
  const sessionArray = new Uint8Array(32);
  crypto.getRandomValues(sessionArray);
  let sessionBin = "";
  for (let i = 0; i < sessionArray.byteLength; i++) sessionBin += String.fromCharCode(sessionArray[i]);
  const sessionRaw = btoa(sessionBin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const sessionHash = await sha256Hex(sessionRaw);
  const sessionExpiresAt = now + 28800; // 8 horas

  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(sessionHash, issuer, subject, email, displayName, sessionExpiresAt, now)
    .run();

  return new Response(null, {
    status: 302,
    headers: {
      Location: env.PUBLIC_BASE_URL,
      "Set-Cookie": [
        `Host-oauth-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
        `Host-session=${sessionRaw}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,
      ],
      "Cache-Control": "no-store",
    },
  });
}
