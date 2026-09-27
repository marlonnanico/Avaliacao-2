import { parseCookies } from "../shared/cookies.js";
import { sha256Base64Url } from "../shared/crypto.js";

export async function onRequestGet(context) {
  const cookies = parseCookies(context.request.headers.get("Cookie"));
  const rawSessionId = cookies["__Host-session"];

  if (!rawSessionId) {
    return new Response(JSON.stringify({ error: "Não autenticado" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  const env = context.env;
  const sessionHash = await sha256Base64Url(rawSessionId);
  const now = Math.floor(Date.now() / 1000);

  const session = await env.DB.prepare(
    `SELECT issuer, subject, email, display_name FROM sessions WHERE id_hash = ? AND expires_at > ?`
  ).bind(sessionHash, now).first();

  if (!session) {
    return new Response(JSON.stringify({ error: "Sessão inválida ou expirada" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  return new Response(
    JSON.stringify({
      issuer: session.issuer,
      subject: session.subject,
      email: session.email,
      displayName: session.display_name
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
      }
    }
  );
}
