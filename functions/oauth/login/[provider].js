export async function onRequestGet(context) {
  return Response.json({
    PUBLIC_BASE_URL: context.env.PUBLIC_BASE_URL,
    GOOGLE_CLIENT_ID: context.env.GOOGLE_CLIENT_ID,
    GITHUB_CLIENT_ID: context.env.GITHUB_CLIENT_ID
  });
}
