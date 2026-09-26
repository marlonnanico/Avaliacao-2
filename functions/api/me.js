export async function onRequestGet(context) {
  const { request, env } = context;
  
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/Host-session=([^;]+)/);
  const sessionCookie = match ? match[1] : null;

  if (!sessionCookie) {
    return new Response(JSON.stringify({ error: "Não autorizado" }), {
      status: 401,
      headers: { 
        "Content-Type": "application/json", 
        "Cache-Control": "no-store" 
      },
    });
  }

  // Calcula o hash SHA-256 do cookie para comparar com o D1
  const encoder = new TextEncoder();
  const data = encoder.encode(sessionCookie);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const sessionHash = Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const now = Math.floor(Date.now() / 1000);

  const row = await env.DB.prepare(
    "SELECT subject, email, display_name, expires_at FROM sessions WHERE id_hash = ? AND expires_at > ?"
  )
    .bind(sessionHash, now)
    .first();

  if (!row) {
    return new Response(JSON.stringify({ error: "Sessão expirada ou inválida" }), {
      status: 401,
      headers: { 
        "Content-Type": "application/json", 
        "Cache-Control": "no-store" 
      },
    });
  }

  return new Response(
    JSON.stringify({
      subject: row.subject,
      email: row.email,
      displayName: row.display_name,
    }),
    {
      status: 200,
      headers: { 
        "Content-Type": "application/json", 
        "Cache-Control": "no-store" 
      },
    }
  );
}
