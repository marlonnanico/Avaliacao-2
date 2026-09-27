import { parseCookies } from "../shared/cookies.js";
import { sha256Base64Url } from "../shared/crypto.js";

export async function onRequestPost(context) {
  const env = context.env;
  const origin = context.request.headers.get("Origin");

  // Validação rígida de origem para CSRF
  if (origin !== env.PUBLIC_BASE_URL) {
    return new Response("Origem não permitida", { status: 403, headers: { "Cache-Control": "no-store" } });
  }

  const cookies = parseCookies(context.request.headers.get("Cookie"));
  const rawSessionId = cookies["__Host-session"];

  if (rawSessionId) {
    const sessionHash = await sha256Base64Url(rawSessionId);
    await env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`).bind(sessionHash).run();
  }

  const headers = new Headers({
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Set-Cookie": `__Host-session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
  });

  return new Response(JSON.stringify({ status: "logged_out" }), { status: 200, headers });
}
