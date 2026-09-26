export async function onRequestPost(context) {
  const { request, env } = context;
  const origin = request.headers.get("Origin");

  if (!origin || origin !== env.PUBLIC_BASE_URL) {
    return new Response("Origem inválida", { status: 403 });
  }

  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/Host-session=([^;]+)/);
  const sessionCookie = match ? match[1] : null;

  if (sessionCookie) {
    const data = new TextEncoder().encode(sessionCookie);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const sessionHash = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    await env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(sessionHash).run();
  }

  return new Response(null, {
    status: 200,
    headers: {
      "Set-Cookie": "Host-session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
      "Cache-Control": "no-store",
    },
  });
}
