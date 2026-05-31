const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

function getToken() {
  return localStorage.getItem("vault_token");
}

async function request(path: string, options: RequestInit = {}) {
  const token = getToken();
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(err.detail || "Request failed");
  }
  return res.json();
}

// Auth
export const api = {
  auth: {
    register: (username: string, master_password: string) =>
      request("/auth/register", { method: "POST", body: JSON.stringify({ username, master_password }) }),
    login: (username: string, master_password: string) =>
      request("/auth/login", { method: "POST", body: JSON.stringify({ username, master_password }) }),
    me: () => request("/auth/me"),
  },

  vault: {
    list: () => request("/vault/entries"),
    create: (entry: any) =>
      request("/vault/entries", { method: "POST", body: JSON.stringify(entry) }),
    update: (id: string, entry: any) =>
      request(`/vault/entries/${id}`, { method: "PUT", body: JSON.stringify(entry) }),
    delete: (id: string) =>
      request(`/vault/entries/${id}`, { method: "DELETE" }),
    search: (q: string) => request(`/vault/entries/search/${encodeURIComponent(q)}`),
  },

  webauthn: {
    registerBegin: () => request("/webauthn/register/begin", { method: "POST" }),
    registerFinish: (data: any) =>
      request("/webauthn/register/finish", { method: "POST", body: JSON.stringify(data) }),
    authBegin: (username: string) =>
      request("/webauthn/auth/begin", { method: "POST", body: JSON.stringify({ username }) }),
    authFinish: (data: any) =>
      request("/webauthn/auth/finish", { method: "POST", body: JSON.stringify(data) }),
    listDevices: () => request("/webauthn/devices"),
    removeDevice: (id: string) =>
      request(`/webauthn/devices/${id}`, { method: "DELETE" }),
  },
};
