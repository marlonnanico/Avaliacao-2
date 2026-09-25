async function sha256(text) {
  const data = new TextEncoder().encode(text);

  const digest = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function getCookie(request, name) {
  const cookieHeader =
    request.headers.get("Cookie") || "";

  const cookies =
    cookieHeader.split(";");

  for (const cookie of cookies) {

    const [key, value] =
      cookie.trim().split("=");

    if (key === name) {
      return value;
    }
  }

  return null;
}

export async function onRequestGet(context) {

  const sessionValue =
    getCookie(
      context.request,
      "__Host-session"
    );

  if (!sessionValue) {

    return new Response(
      "Unauthorized",
      {
        status: 401,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }

  const hash =
    await sha256(sessionValue);

  const session =
    await context.env.DB.prepare(`
      SELECT *
      FROM sessions
      WHERE id_hash = ?
      AND expires_at > ?
    `)
    .bind(
      hash,
      Math.floor(Date.now() / 1000)
    )
    .first();

  if (!session) {

    return new Response(
      "Unauthorized",
      {
        status: 401,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }

  return Response.json(
    {
      issuer: session.issuer,
      subject: session.subject,
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
