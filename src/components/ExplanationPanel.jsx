import React from "react";

export default function ExplanationPanel() {
  return (
    <div className="card">
      <h2>Explanation</h2>
      <div className="section-title">What is SQL Injection?</div>
      <div className="subtle">SQL injection is a technique that manipulates query strings to alter database operations.</div>

      <div className="section-title">Query Flow Diagram</div>
      <div className="code">
        User Input → String Concatenation → Malicious SQL → Database
        <br />
        User Input → Parameters (Escaped) → Safe SQL → Database
      </div>

      <div className="section-title">Code Comparison</div>
      <div className="code">
        ❌ Vulnerable
        <br />
        const query = `SELECT * FROM users WHERE username = '${"${username}"}' AND password = '${"${password}"}'`;
        <br />
        ✅ Secure
        <br />
        const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
        <br />
        execute(query, [username, password]);
      </div>

      <div className="section-title">Prevention Best Practices</div>
      <ul className="list">
        <li className="subtle">Use prepared statements</li>
        <li className="subtle">Validate and sanitize inputs</li>
        <li className="subtle">Limit database privileges</li>
        <li className="subtle">Avoid dynamic query building</li>
        <li className="subtle">Follow OWASP recommendations</li>
      </ul>

      <div className="section-title">Try It Yourself</div>
      <div className="subtle">Use the payload buttons and observe the difference between vulnerable and secure implementations.</div>
    </div>
  );
}

