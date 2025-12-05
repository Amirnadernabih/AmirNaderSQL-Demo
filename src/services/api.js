const base = process.env.REACT_APP_API_URL || "";

async function requestJson(url, options) {
  const res = await fetch(url, options);
  const ct = res.headers.get("content-type") || "";
  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  if (ct.includes("application/json")) {
    try { return JSON.parse(text); } catch {
      throw new Error(`Invalid JSON (${res.status}): ${text.slice(0, 200)}`);
    }
  }
  try { return JSON.parse(text); } catch {
    throw new Error(`Invalid JSON (${res.status}): ${text.slice(0, 200)}`);
  }
}

async function vulnerableLogin(username, password) {
  return requestJson(`${base}/api/vulnerable-login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
}

async function secureLogin(username, password) {
  return requestJson(`${base}/api/secure-login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
}

async function getUsers() {
  return requestJson(`${base}/api/get-users`, { method: "GET" });
}

export { vulnerableLogin, secureLogin, getUsers };
