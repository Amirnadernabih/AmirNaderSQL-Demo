import React from "react";

function Icon({ status }) {
  if (status === "loading") return <span className="spinner" />;
  if (status === "done") return <span className="badge" style={{ borderColor: "var(--green)", color: "var(--green)" }}>✓</span>;
  if (status === "error") return <span className="badge" style={{ borderColor: "var(--red)", color: "var(--red)" }}>✕</span>;
  return <span className="badge" style={{ color: "var(--gray)" }}>•</span>;
}

export default function ProcessPanel({ title, steps }) {
  const visible = (steps || []).filter((s) => s.status !== "pending");
  if (visible.length === 0) return null;
  return (
    <div className="card">
      <h2>{title || "Background Steps"}</h2>
      <div className="steps">
        {visible.map((s) => (
          <div key={s.key} className="step-row">
            <Icon status={s.status} />
            <div className="step-title">{s.title}</div>
            {s.note && <div className="subtle">{s.note}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}
