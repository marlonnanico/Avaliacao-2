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

function randomString() {

  const bytes =
    new Uint8Array(32);

  crypto.getRandomValues(bytes);

  return btoa(
    String.fromCharCode(...bytes)
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export async function onRequestGet(context) {

  const provider =
    context.params.provider;

  if (
    provider !== "google" &&
    provider !== "github"
  ) {
    return new Response(
      "Provider not found",
      {
        status: 404
      }
    );
  }

  const url =
    new URL(context.request.url);

  const code =
    url.searchParams.get("code");

  const state =
    url.searchParams.get("state");

  const error =
    url.searchParams.get("error");

  if (error) {

    return new Response(
      error,
      {
        status: 400
      }
    );
  }

  if (!code || !state) {

    return new Response(
      "Missing code/state",
      {
        status: 400
      }
    );
  }

  const txValue =
    getCookie(
      context.request,
      "__Host-oauth-tx"
    );

  if (!txValue) {

    return new Response(
      "Missing transaction cookie",
      {
        status: 400
      }
    );
  }

  const txHash =
    await sha256(txValue);

  const stateHash =
    await sha256(state);

  const transaction =
    await context.env.DB.prepare(`
      SELECT *
      FROM oauth_transactions
      WHERE id_hash = ?
      AND expires_at > ?
    `)
    .bind(
      txHash,
      Math.floor(Date.now() / 1000)
    )
    .first();

  if (!transaction) {

    return new Response(
      "Transaction not found",
      {
        status: 400
      }
    );
  }

  if (
    transaction.state_hash !==
    stateHash
  ) {

    return new Response(
      "Invalid state",
      {
        status: 400
      }
    );
  }

  await context.env.DB.prepare(`
    DELETE FROM oauth_transactions
    WHERE id_hash = ?
  `)
    .bind(txHash)
    .run();

  const sessionId =
    randomString();

  const sessionHash =
    await sha256(sessionId);

  const now =
    Math.floor(Date.now() / 1000);

  const expires =
    now + 28800;

  await context.env.DB.prepare(`
    INSERT INTO sessions
    (
      id_hash,
      issuer,
      subject,
      email,
      display_name,
      expires_at,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `)
    .bind(
      sessionHash,
      provider,
      code,
      null,
      provider,
      expires,
      now
    )
    .run();

  return new Response(
    null,
    {
      status: 302,
      headers: {
        Location:
          context.env.PUBLIC_BASE_URL,

        "Set-Cookie":
          `__Host-session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`
      }
    }
  );
}
