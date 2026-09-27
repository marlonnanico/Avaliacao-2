import { generateRandomString } from "../../shared/crypto.js";

export async function onRequestGet(context) {
  const { env, params } = context;
  const provider = params.provider;
  const baseUrl = env.PUBLIC_BASE_URL;

  const state = generateRandomString(32);
  const nonce = generateRandomString(32);

  let authUrl = "";
  const headers = new Headers();

  // Usa SameSite=Lax para garantir que o navegador envie o cookie de volta ao ser redirecionado pelo Google/GitHub
  headers.append(
    "Set-Cookie",
    `__Host-oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
  );

  if (provider === "google") {
    headers.append(
      "Set-Cookie",
      `__Host-google_nonce=${nonce}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
    );

    const googleParams = new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      redirect_uri: `${baseUrl}/oauth/callback/google`,
      response_type: "code",
      scope: "openid profile email",
      state: state,
      nonce: nonce,
      prompt: "select_account"
    });

    authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${googleParams.toString()}`;
  } else if (provider === "github") {
    const githubParams = new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      redirect_uri: `${baseUrl}/oauth/callback/github`,
      scope: "read:user user:email",
      state: state
    });

    authUrl = `https://github.com/login/oauth/authorize?${githubParams.toString()}`;
  } else {
    return new Response("Provedor não suportado", { status: 400 });
  }

  headers.set("Location", authUrl);
  return new Response(null, { status: 302, headers });
}
