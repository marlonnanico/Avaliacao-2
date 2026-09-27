import { parseCookies } from "../shared/cookies.js";
import { sha256Base64Url } from "../shared/crypto.js";

export async function onRequestGet(context) {
  const env = context.env;
  const cookies = parseCookies(context.request.headers.get("Cookie"));
  const rawSessionId = cookies["__Host-session"];

  if (!rawSessionId) {
    return new Response(JSON.stringify({ error: "Não autenticado" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  const sessionHash = await sha256Base64Url(rawSessionId);
  const session = await env.DB.prepare(
    `SELECT user_id, provider, email, created_at FROM sessions WHERE id_hash = ?`
  ).bind(sessionHash).first();

  if (!session) {
    return new Response(JSON.stringify({ error: "Sessão inválida ou expirada" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  const iss = session.provider === "google" 
    ? "https://accounts.google.com" 
    : "https://github.com";

  return new Response(
    JSON.stringify({
      sub: session.user_id || "Não identificado",
      email: session.email || "Não informado",
      iss: iss,
      provider: session.provider
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    }
  );
}
