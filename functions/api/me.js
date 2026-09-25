export async function onRequestGet() {

  return new Response(
    "Unauthorized",
    {
      status: 401,
      headers: {
        "Cache-Control": "no-store"
      }
    }
  );
}
