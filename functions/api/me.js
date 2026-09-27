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
  const now = Math.floor(Date.now() / 1000);

  const session = await env.DB.prepare(
    `SELECT issuer, subject, email, display_name, expires_at FROM sessions WHERE id_hash = ?`
  ).bind(sessionHash).first();

  if (!session || (session.expires_at && session.expires_at < now)) {
    return new Response(JSON.stringify({ error: "Sessão inválida ou expirada" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  const provider = session.issuer.includes("google") ? "google" : "github";

  return new Response(
    JSON.stringify({
      sub: session.display_name || session.subject,
      email: session.email || "Não informado",
      iss: session.issuer,
      provider: provider
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    }
  );
}
