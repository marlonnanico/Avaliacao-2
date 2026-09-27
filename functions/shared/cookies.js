export function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  const pairs = cookieHeader.split(";");
  for (const pair of pairs) {
    const [name, value] = pair.trim().split("=");
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  }
  return cookies;
}
