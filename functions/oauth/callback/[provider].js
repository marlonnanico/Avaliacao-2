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
        status: 404,
        headers: {
          "Cache-Control":
            "no-store"
        }
      }
    );
  }

  const url =
    new URL(
      context.request.url
    );

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
        status: 400,
        headers: {
          "Cache-Control":
            "no-store"
        }
      }
    );
  }

  if (!code || !state) {

    return new Response(
      "Missing code/state",
      {
        status: 400,
        headers: {
          "Cache-Control":
            "no-store"
        }
      }
    );
  }

  const txCookie =
    getCookie(
      context.request,
      "__Host-oauth-tx"
    );

  if (!txCookie) {

    return new Response(
      "Missing transaction cookie",
      {
        status: 400,
        headers: {
          "Cache-Control":
            "no-store"
        }
      }
    );
  }

  const txHash =
    await sha256(
      txCookie
    );

  const stateHash =
    await sha256(
      state
    );

  const tx =
    await context.env.DB.prepare(`
      SELECT *
      FROM oauth_transactions
      WHERE id_hash = ?
      AND expires_at > ?
    `)
      .bind(
        txHash,
        Math.floor(
          Date.now() / 1000
        )
      )
      .first();

  if (!tx) {

    return new Response(
      "Transaction not found",
      {
        status: 400,
        headers: {
          "Cache-Control":
            "no-store"
        }
      }
    );
  }

  if (
    tx.state_hash !==
    stateHash
  ) {

    return new Response(
      "Invalid state",
      {
        status: 400,
        headers: {
          "Cache-Control":
            "no-store"
        }
      }
    );
  }

  await context.env.DB.prepare(`
    DELETE FROM oauth_transactions
    WHERE id_hash = ?
  `)
    .bind(txHash)
    .run();

  const now =
    Math.floor(
      Date.now() / 1000
    );

  const sessionId =
    randomString();

  const sessionHash =
    await sha256(
      sessionId
    );

  const expires =
    now + 28800;

  let issuer;
  let subject;
  let email;
  let displayName;

  if (provider === "google") {

    const tokenResponse =
      await fetch(
        "https://oauth2.googleapis.com/token",
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({
            code,
            client_id:
              context.env.GOOGLE_CLIENT_ID,
            client_secret:
              context.env.GOOGLE_CLIENT_SECRET,
            redirect_uri:
              `${context.env.PUBLIC_BASE_URL}/oauth/callback/google`,
            grant_type:
              "authorization_code",
            code_verifier:
              tx.code_verifier
          })
        }
      );

    if (!tokenResponse.ok) {

      const errorText =
        await tokenResponse.text();

      return new Response(
        errorText,
        {
          status: 400
        }
      );
    }

    const tokenData =
      await tokenResponse.json();

    if (!tokenData.id_token) {

      return new Response(
        "Missing id_token",
        {
          status: 400
        }
      );
    }

    const payload =
      JSON.parse(
        atob(
          tokenData.id_token
            .split(".")[1]
            .replace(/-/g, "+")
            .replace(/_/g, "/")
        )
      );

    issuer =
      payload.iss;

    subject =
      payload.sub;

    email =
      payload.email ?? null;

    displayName =
      payload.
