export async function onRequestGet(context) {

  return new Response(
    "CALLBACK FUNCIONANDO",
    {
      headers: {
        "Content-Type": "text/plain"
      }
    }
  );
}
