export async function onRequestGet(context) {
  return Response.json({
    callback: true,
    provider: context.params.provider,
    url: context.request.url
  });
}
