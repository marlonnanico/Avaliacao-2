export async function onRequestGet(context) {

  const cookie =
    context.request.headers
      .get("Cookie") || "";

  const sessionCookie =
    cookie
      .split(";")
      .find(c => c.trim().startsWith("__Host-session="));

  if (!sessionCookie) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "Cache-Control": "no-store"
      }
    });
  }

  const rawValue =
    sessionCookie.split("=")[1];

  const hashBuffer =
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(rawValue)
    );

  const hash =
    Array.from(
      new Uint8Array(hashBuffer)
    )
    .map(b =>
      b.toString(16).padStart(2, "0")
    )
    .join("");

  const session =
    await context.env.DB
      .prepare(
        `SELECT *
         FROM sessions
         WHERE id_hash = ?
         AND expires_at > ?`
      )
      .bind(
        hash,
        Math.floor(Date.now() / 1000)
      )
      .first();

  if (!session) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "Cache-Control": "no-store"
      }
    });
  }

  return Response.json(
    {
      issuer: session.issuer,
      email: session.email,
      displayName: session.display_name
    },
    {
      headers: {
        "Cache-Control": "no-store"
      }
    }
  );
}
