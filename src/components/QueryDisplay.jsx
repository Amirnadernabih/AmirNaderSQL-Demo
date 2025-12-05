import React from "react";

function tokenize(query) {
  const patterns = [
    /'\s*OR\s*'1'='1/gi,
    /OR\s*1=1/gi,
    /'--/gi,
    /UNION\s+SELECT/gi
  ];
  let parts = [{ text: query, injected: false }];
  patterns.forEach((re) => {
    const next = [];
    parts.forEach((p) => {
      if (!p.injected) {
        let lastIndex = 0;
        const s = p.text;
        s.replace(re, (match, offset) => {
          if (offset > lastIndex) {
            next.push({ text: s.slice(lastIndex, offset), injected: false });
          }
          next.push({ text: match, injected: true });
          lastIndex = offset + match.length;
          return match;
        });
        if (lastIndex < s.length) next.push({ text: s.slice(lastIndex), injected: false });
      } else {
        next.push(p);
      }
    });
    parts = next.length ? next : parts;
  });
  return parts;
}

export default function QueryDisplay({ query, parameters, isVulnerable, injectionDetected }) {
  const tokens = tokenize(query || "");
  return (
    <div className="card">
      <div className="code">
        {tokens.map((t, i) => (
          <span key={i} className={t.injected ? "injected" : undefined}>{t.text}</span>
        ))}
      </div>
      {Array.isArray(parameters) && parameters.length > 0 && (
        <div style={{ marginTop: 8 }}>
          {parameters.map((p, i) => (
            <span key={i} className="param">{String(p)}</span>
          ))}
        </div>
      )}
      <div className="list" style={{ marginTop: 8 }}>
        <span className="badge">Endpoint: {isVulnerable ? "Vulnerable" : "Secure"}</span>
        {isVulnerable && (
          <span className="badge">Injection detected: {injectionDetected ? "Yes" : "No"}</span>
        )}
      </div>
    </div>
  );
}
