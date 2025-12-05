const base = process.env.REACT_APP_API_URL || "";

async function vulnerableLogin(username, password) {
  const res = await fetch(`${base}/api/vulnerable-login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  return res.json();
}

async function secureLogin(username, password) {
  const res = await fetch(`${base}/api/secure-login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  return res.json();
}

async function getUsers() {
  const res = await fetch(`${base}/api/get-users`, {
    method: "GET"
  });
  return res.json();
}

export { vulnerableLogin, secureLogin, getUsers };

