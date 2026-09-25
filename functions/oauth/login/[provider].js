function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

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

function randomString() {
  const bytes = new Uint8Array(32);

  crypto.getRandomValues(bytes);

  return base64url(bytes);
}

async function createChallenge(verifier) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );

  return base64url(new Uint8Array(digest));
}

export async function onRequestGet(context) {

  const provider = context.params.provider;

  if (
    provider !== "google" &&
    provider !== "github"
  ) {
    return new Response("Not found", {
      status: 404
    });
  }

  const txId = randomString();
  const state = randomString();

  const nonce =
    provider === "google"
      ? randomString()
      : null;

  const verifier = randomString();

  const challenge =
    await createChallenge(verifier);

  const txHash =
    await sha256(txId);

  const stateHash =
    await sha256(state);

  const expires =
    Math.floor(Date.now() / 1000) + 600;

  await context.env.DB.prepare(`
      INSERT INTO oauth_transactions
      (
        id_hash,
        provider,
        state_hash,
        nonce,
        code_verifier,
        expires_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
  `)
    .bind(
      txHash,
      provider,
      stateHash,
      nonce,
      verifier,
      expires
    )
    .run();

  let authorizationUrl;

  if (provider === "google") {

    const redirect =
      `${context.env.PUBLIC_BASE_URL}/oauth/callback/google`;

    authorizationUrl =
      new URL(
        "https://accounts.google.com/o/oauth2/v2/auth"
      );

    authorizationUrl.searchParams.set(
      "client_id",
      context.env.GOOGLE_CLIENT_ID
    );

    authorizationUrl.searchParams.set(
      "redirect_uri",
      redirect
    );

    authorizationUrl.searchParams.set(
      "response_type",
      "code"
    );

    authorizationUrl.searchParams.set(
      "scope",
      "openid email profile"
    );

    authorizationUrl.searchParams.set(
      "state",
      state
    );

    authorizationUrl.searchParams.set(
      "nonce",
      nonce
    );

    authorizationUrl.searchParams.set(
      "code_challenge",
      challenge
    );

    authorizationUrl.searchParams.set(
      "code_challenge_method",
      "S256"
    );

  } else {

    const redirect =
      `${context.env.PUBLIC_BASE_URL}/oauth/callback/github`;

    authorizationUrl =
      new URL(
        "https://github.com/login/oauth/authorize"
      );

    authorizationUrl.searchParams.set(
      "client_id",
      context
