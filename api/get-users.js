const users = require("../data/mockUsers");

module.exports = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const sanitized = users.map((u) => ({ id: u.id, username: u.username, role: u.role }));
  return res.json(sanitized);
};

