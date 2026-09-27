document.addEventListener("DOMContentLoaded", () => {
  fetch("/api/me", { credentials: "same-origin" })
    .then((response) => (response.ok ? response.json() : null))
    .then((user) => {
      const status = document.getElementById("status");
      if (status) {
        status.textContent = user
          ? `Sessão de ${user.email ?? user.displayName}.`
          : "Nenhuma sessão neste navegador.";
      }
    })
    .catch(() => {
      const status = document.getElementById("status");
      if (status) {
        status.textContent = "Erro ao consultar status da sessão.";
      }
    });
