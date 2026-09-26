export async function onRequestGet(context) {
  const { request, env } = context;
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/(?:^|;\s*)Host-session=([^;]*)/);

  if (!match) {
    return new Response(JSON.stringify(null), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  const sessionId = match[1];

  async function sha256Hex(plain) {
    const data = new TextEncoder().encode(plain);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  const sessionIdHash = await sha256Hex(sessionId);
  const now = Math.floor(Date.now() / 1000);

  const session = await env.DB.prepare(
    `SELECT * FROM sessions WHERE id_hash = ? AND expires_at > ?`
  )
    .bind(sessionIdHash, now)
    .first();

  if (!session) {
    return new Response(JSON.stringify(null), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  return new Response(JSON.stringify({
    email: session.email,
    displayName: session.display_name,
    issuer: session.issuer
  }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
  });
}
