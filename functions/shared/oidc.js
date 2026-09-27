export async function verifyGoogleIdToken(idToken, clientId, expectedNonce) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("JWT inválido");

  const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
  const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));

  if (header.alg !== "RS256") throw new Error("Algoritmo não suportado");

  const discoveryRes = await fetch("https://accounts.google.com/.well-known/openid-configuration");
  const discovery = await discoveryRes.json();

  const jwksRes = await fetch(discovery.jwks_uri);
  const jwks = await jwksRes.json();

  const keyData = jwks.keys.find((k) => k.kid === header.kid);
  if (!keyData) throw new Error("Chave pública não encontrada");

  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    keyData,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const encoder = new TextEncoder();
  const data = encoder.encode(`${parts[0]}.${parts[1]}`);
  
  const signatureStr = atob(parts[2].replace(/-/g, "+").replace(/_/g, "/"));
  const signature = Uint8Array.from(signatureStr, (c) => c.charCodeAt(0));

  const isValid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    signature,
    data
  );

  if (!isValid) throw new Error("Assinatura do token inválida");

  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== "https://accounts.google.com" && payload.iss !== "accounts.google.com") {
    throw new Error("Emissor inválido");
  }
  if (payload.aud !== clientId) throw new Error("Audiência inválida");
  if (payload.exp < now) throw new Error("Token expirado");
  if (expectedNonce && payload.nonce !== expectedNonce) throw new Error("Nonce inválido");

  return payload;
}
