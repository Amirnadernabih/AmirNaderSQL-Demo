const users = require("../data/mockUsers");

module.exports = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    return res.status(405).json({
      success: false,
      message: "Method Not Allowed"
    });
  }

  const { username, password } = req.body || {};

  const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
  const parameters = [username, password];

  const authenticatedUser = users.find((u) => u.username === username && u.password === password);

  if (authenticatedUser) {
    return res.json({
      success: true,
      query,
      parameters,
      user: { id: authenticatedUser.id, username: authenticatedUser.username, role: authenticatedUser.role },
      message: "✅ Login successful with prepared statement"
    });
  } else {
    return res.status(200).json({
      success: false,
      query,
      parameters,
      message: "❌ Invalid credentials - injection attempts treated as literal strings"
    });
  }
};
