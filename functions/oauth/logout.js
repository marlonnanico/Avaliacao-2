export async function onRequestPost(context) {
  const { request, env } = context;
  const baseUrl = (env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  const origin = request.headers.get("Origin");

  if (!origin || (baseUrl && origin !== baseUrl)) {
    return new Response("Origem inválida para logout.", { status: 403 });
  }

  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/(?:^|;\s*)Host-session=([^;]*)/);

  if (match) {
    const sessionId = match[1];
    async function sha256Hex(plain) {
      const data = new TextEncoder().encode(plain);
      const hashBuffer = await crypto.subtle.digest("SHA-256", data);
      return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
    }
    const sessionIdHash = await sha256Hex(sessionId);
    await env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`).bind(sessionIdHash).run().catch(() => {});
  }

  return new Response(null, {
    status: 200,
    headers: {
      "Set-Cookie": `Host-session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
      "Cache-Control": "no-store",
    },
  });
}
