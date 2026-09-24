export function onRequestGet(context) {
  return Response.json({
    provider: context.params.provider
  });
}
