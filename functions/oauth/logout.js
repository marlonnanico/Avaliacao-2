async function sha256(text) {

  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(text)
    );

  return Array.from(
    new Uint8Array(digest)
  )
    .map(b =>
      b.toString(16).padStart(2, "0")
    )
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

export async function onRequestPost(context) {

  const origin =
    context.request.headers.get(
      "Origin"
    );

  if (
    origin !==
    context.env.PUBLIC_BASE_URL
  ) {

    return new Response(
      "Forbidden",
      {
        status: 403
      }
    );
  }

  const sessionValue =
    getCookie(
      context.request,
      "__Host-session"
    );

  if (sessionValue) {

    const hash =
      await sha256(sessionValue);

    await context.env.DB.prepare(`
      DELETE FROM sessions
      WHERE id_hash = ?
    `)
    .bind(hash)
    .run();
  }

  return new Response(
    "Logout",
    {
      headers: {
        "Set-Cookie":
          "__Host-session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
        "Cache-Control":
          "no-store"
      }
    }
  );
}
