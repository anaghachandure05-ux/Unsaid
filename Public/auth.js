async function apiRequest(url, options = {}) {
  const opts = {
    headers: { "Content-Type": "application/json" },
    ...options
  };
  const res = await fetch(url, opts);
  let data = {};
  try {
    data = await res.json();
  } catch (_) {}
  return { ok: res.ok, status: res.status, data };
}

async function getCurrentUser() {
  const { ok, data } = await apiRequest("/api/me");
  if (!ok) return { loggedIn: false };
  return data;
}

async function logoutUser() {
  await apiRequest("/api/logout", { method: "POST" });
  window.location.href = "/";
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}
