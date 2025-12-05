const users = require("../data/mockUsers");

module.exports = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const { username, password } = req.body || {};
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  let injectionDetected = false;
  let authenticatedUser = null;

  if (
    /'\s*OR\s*'1'='1/i.test(query) ||
    /OR\s*1=1/i.test(query) ||
    /'--/i.test(query) ||
    /UNION\s+SELECT/i.test(query)
  ) {
    injectionDetected = true;
    authenticatedUser = users[0];
  } else {
    authenticatedUser = users.find((u) => u.username === username && u.password === password);
  }

  if (authenticatedUser) {
    return res.json({
      success: true,
      query,
      injectionDetected,
      user: { id: authenticatedUser.id, username: authenticatedUser.username, role: authenticatedUser.role },
      message: injectionDetected ? "⚠️ SQL Injection successful! Authentication bypassed!" : "Login successful"
    });
  } else {
    return res.json({
      success: false,
      query,
      injectionDetected: false,
      message: "Invalid credentials"
    });
  }
};
