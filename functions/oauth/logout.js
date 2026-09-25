export async function onRequestPost(
  context
) {

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

  const cookie =
    context.request.headers
      .get("Cookie") || "";

  const sessionCookie =
    cookie
      .split(";")
      .find(c =>
        c.trim().startsWith(
          "__Host-session="
        )
      );

  if (sessionCookie) {

    const rawValue =
      sessionCookie.split("=")[1];

    const hashBuffer =
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(
          rawValue
        )
      );

    const hash =
      Array.from(
        new Uint8Array(hashBuffer)
      )
      .map(b =>
        b.toString(16)
         .padStart(2, "0")
      )
      .join("");

    await context.env.DB
      .prepare(
        "DELETE FROM sessions WHERE id_hash=?"
      )
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
