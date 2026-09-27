import { parseCookies } from "../../shared/cookies.js";
import { generateRandomString, sha256Base64Url } from "../../shared/crypto.js";
import { verifyGoogleIdToken } from "../../shared/oidc.js";

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const provider = params.provider;
  const url = new URL(request.url);
  const baseUrl = env.PUBLIC_BASE_URL;

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  const cookies = parseCookies(request.headers.get("Cookie"));
  const storedState = cookies["__Host-oauth_state"];

  if (!code || !state || !storedState || state !== storedState) {
    return new Response("Estado OAuth inválido ou reutilizado", { status: 400 });
  }

  let userId = "";
  let email = "";

  if (provider === "google") {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${baseUrl}/oauth/callback/google`,
        grant_type: "authorization_code"
      })
    });

    if (!tokenRes.ok) {
      return new Response("Falha na troca de código com o Google", { status: 400 });
    }

    const tokenData = await tokenRes.json();
    const storedNonce = cookies["__Host-google_nonce"];
    const payload = await verifyGoogleIdToken(tokenData.id_token, env.GOOGLE_CLIENT_ID, storedNonce);

    // sub no Google é a identificação única do utilizador (ex: "10839281923812")
    userId = payload.sub;
    email = payload.email || "";
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
        code,
        redirect_uri: `${baseUrl}/oauth/callback/github`
      })
    });

    if (!tokenRes.ok) {
      return new Response("Falha na troca de código com o GitHub", { status: 400 });
    }

    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;

    const userRes = await fetch("https://api.github.com/user", {
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "User-Agent": "Cloudflare-Pages-App"
      }
    });

    if (!userRes.ok) {
      return new Response("Falha ao obter perfil do GitHub", { status: 400 });
    }

    const userData = await userRes.json();
    // Identificação única no GitHub (ex: "login" ou "id")
    userId = userData.login || String(userData.id);
    email = userData.email || "";

    if (!email) {
      const emailsRes = await fetch("https://api.github.com/user/emails", {
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "User-Agent": "Cloudflare-Pages-App"
        }
      });
      if (emailsRes.ok) {
        const emails = await emailsRes.json();
        const primary = emails.find(e => e.primary) || emails[0];
        if (primary) email = primary.email;
      }
    }
  } else {
    return new Response("Provedor não suportado", { status: 400 });
  }

  const rawSessionId = generateRandomString(32);
  const sessionHash = await sha256Base64Url(rawSessionId);

  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, provider, user_id, email, created_at) VALUES (?, ?, ?, ?, DATETIME('now'))`
  ).bind(sessionHash, provider, userId, email).run();

  const headers = new Headers({
    "Location": baseUrl,
    "Set-Cookie": `__Host-session=${rawSessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`
  });

  headers.append("Set-Cookie", `__Host-oauth_state=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
  headers.append("Set-Cookie", `__Host-google_nonce=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);

  return new Response(null, { status: 302, headers });
}
