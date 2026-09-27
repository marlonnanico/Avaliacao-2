import { parseCookies } from "../../shared/cookies.js";
import { generateRandomString, sha256Base64Url } from "../../shared/crypto.js";
import { verifyGoogleIdToken } from "../../shared/oidc.js";

export async function onRequestGet(context) {
  const provider = context.params.provider;
  if (provider !== "google" && provider !== "github") {
    return new Response("Not Found", { status: 404 });
  }

  const url = new URL(context.request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error || !code || !state) {
    return new Response("Requisição de autenticação inválida", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  const cookies = parseCookies(context.request.headers.get("Cookie"));
  const rawTxId = cookies["__Host-oauth-tx"];
  if (!rawTxId) {
    return new Response("Cookie de transação não encontrado", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  const env = context.env;
  const baseUrl = env.PUBLIC_BASE_URL;
  const txHash = await sha256Base64Url(rawTxId);
  const stateHash = await sha256Base64Url(state);

  const now = Math.floor(Date.now() / 1000);

  // Consulta e consome a transação do banco
  const tx = await env.DB.prepare(
    `SELECT * FROM oauth_transactions WHERE id_hash = ? AND provider = ? AND expires_at > ?`
  ).bind(txHash, provider, now).first();

  if (!tx || tx.state_hash !== stateHash) {
    return new Response("Transação inválida, expirada ou estado alterado", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  // Apaga a transação imediatamente para evitar reutilização
  await env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(txHash).run();

  const redirectUri = `${baseUrl}/oauth/callback/${provider}`;
  let userProfile = { issuer: "", subject: "", email: null, displayName: null };

  if (provider === "google") {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        code: code,
        grant_type: "authorization_code",
        redirect_uri: redirectUri,
        code_verifier: tx.code_verifier
      })
    });

    if (!tokenRes.ok) {
      return new Response("Falha na troca de código com o Google", { status: 400, headers: { "Cache-Control": "no-store" } });
    }

    const tokenData = await tokenRes.json();
    const idTokenClaims = await verifyGoogleIdToken(tokenData.id_token, env.GOOGLE_CLIENT_ID, tx.nonce);

    userProfile.issuer = "https://accounts.google.com";
    userProfile.subject = idTokenClaims.sub;
    userProfile.email = idTokenClaims.email || null;
    userProfile.displayName = idTokenClaims.name || null;

  } else if (provider === "github") {
    const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
      },
      body: new URLSearchParams({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code: code,
        redirect_uri: redirectUri,
        code_verifier: tx.code_verifier
      })
    });

    if (!tokenRes.ok) {
      return new Response("Falha na troca de código com o GitHub", { status: 400, headers: { "Cache-Control": "no-store" } });
    }

    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;
    if (!accessToken) {
      return new Response("Access token não retornado pelo GitHub", { status: 400, headers: { "Cache-Control": "no-store" } });
    }

    // Consulta API do GitHub
    const userRes = await fetch("https://api.github.com/user", {
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Accept": "application/vnd.github+json",
        "User-Agent": "Cloudflare-Pages-OAuth-Lab",
        "X-GitHub-Api-Version": "2026-03-10"
      }
    });

    if (!userRes.ok) {
      return new Response("Falha ao obter perfil do GitHub", { status: 400, headers: { "Cache-Control": "no-store" } });
    }

    const githubUser = await userRes.json();

    // Revoga a autorização do GitHub imediatamente
    const basicAuth = btoa(`${env.GITHUB_CLIENT_ID}:${env.GITHUB_CLIENT_SECRET}`);
    const revokeRes = await fetch(`https://api.github.com/applications/${env.GITHUB_CLIENT_ID}/grant`, {
      method: "DELETE",
      headers: {
        "Authorization": `Basic ${basicAuth}`,
        "Content-Type": "application/json",
        "User-Agent": "Cloudflare-Pages-OAuth-Lab",
        "X-GitHub-Api-Version": "2026-03-10"
      },
      body: JSON.stringify({ access_token: accessToken })
    });

    if (revokeRes.status !== 204) {
      return new Response("Falha ao revogar token do GitHub", { status: 500, headers: { "Cache-Control": "no-store" } });
    }

    userProfile.issuer = "https://github.com";
    userProfile.subject = String(githubUser.id);
    userProfile.email = githubUser.email || null;
    userProfile.displayName = githubUser.name || githubUser.login || null;
  }

  // Criação da sessão local (8 horas de validade)
  const rawSessionId = generateRandomString(32);
  const sessionHash = await sha256Base64Url(rawSessionId);
  const sessionExpiresAt = now + 28800; // 8 horas em segundos

  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    sessionHash,
    userProfile.issuer,
    userProfile.subject,
    userProfile.email,
    userProfile.displayName,
    sessionExpiresAt,
    now
  ).run();

  const headers = new Headers({
    "Location": baseUrl,
    "Cache-Control": "no-store"
  });

  // Limpa o cookie temporário e insere o cookie de sessão opaco
  headers.append("Set-Cookie", `__Host-oauth-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
  headers.append("Set-Cookie", `__Host-session=${rawSessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`);

  return new Response(null, { status: 302, headers });
