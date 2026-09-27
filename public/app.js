document.addEventListener("DOMContentLoaded", async () => {
  const statusEl = document.getElementById("status");
  const authActions = document.getElementById("auth-actions");
  const logoutForm = document.getElementById("logout-form");
  const profileCard = document.getElementById("profile-card");

  const userSub = document.getElementById("user-sub");
  const userEmail = document.getElementById("user-email");
  const userIss = document.getElementById("user-iss");

  try {
    const res = await fetch("/api/me");
    if (res.ok) {
      const data = await res.json();
      
      statusEl.textContent = "Bem-vindo(a) de volta!";
      
      // Suporta tanto o retorno formatado (/api/me) quanto os nomes diretos
      userSub.textContent = data.sub || data.user_id || data.id || "-";
      userEmail.textContent = data.email || "-";
      userIss.textContent = data.iss || data.provider || (data.provider === "google" ? "https://accounts.google.com" : "https://github.com") || "-";

      authActions.style.display = "none";
      profileCard.style.display = "block";
      logoutForm.style.display = "block";
    } else {
      statusEl.textContent = "Nenhuma sessão neste navegador.";
      authActions.style.display = "flex";
      profileCard.style.display = "none";
      logoutForm.style.display = "none";
    }
  } catch (e) {
    statusEl.textContent = "Erro ao verificar a sessão.";
    authActions.style.display = "flex";
    profileCard.style.display = "none";
    logoutForm.style.display = "none";
  }
});
