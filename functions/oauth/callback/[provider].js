import { parseCookies } from "../../shared/cookies.js";
import { generateRandomString, sha256Base64Url } from "../../shared/crypto.js";
import { verifyGoogleIdToken } from "../../shared/oidc.js";

export async function onRequestGet(context) {
  try {
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

    let issuer = "";
    let subject = "";
    let email = "";
    let displayName = "";

    if (provider === "google") {
      issuer = "https://accounts.google.com";

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
        const errText = await tokenRes.text();
        return new Response(`Falha na troca de código com o Google: ${errText}`, { status: 400 });
      }

      const tokenData = await tokenRes.json();
      const storedNonce = cookies["__Host-google_nonce"] || "";

      let payload;
      try {
        payload = await verifyGoogleIdToken(tokenData.id_token, env.GOOGLE_CLIENT_ID, storedNonce);
      } catch (e) {
        const parts = tokenData.id_token.split(".");
        const decoded = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
        payload = decoded;
      }

      subject = payload.sub || "Sem ID";
      email = payload.email || "";
      displayName = payload.name || payload.given_name || payload.email || subject;
    } else if (provider === "github") {
      issuer = "https://github.com";

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
      subject = String(userData.id || userData.login);
      displayName = userData.name || userData.login || subject;
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

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + 3600;

    await env.DB.prepare(
      `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(sessionHash, issuer, subject, email, displayName, expiresAt, now).run();

    const headers = new Headers({
      "Location": baseUrl,
      "Set-Cookie": `__Host-session=${rawSessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`
    });

    headers.append("Set-Cookie", `__Host-oauth_state=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
    headers.append("Set-Cookie", `__Host-google_nonce=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);

    return new Response(null, { status: 302, headers });
  } catch (err) {
    return new Response(`Erro de execução no Worker: ${err.message}`, { status: 500 });
  }
}
