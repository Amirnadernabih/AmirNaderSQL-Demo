import React, { useState } from "react";
import VulnerableLogin from "./VulnerableLogin";
import SecureLogin from "./SecureLogin";

export default function ComparisonView() {
  const [tab, setTab] = useState("vulnerable");
  return (
    <div>
      <div className="layout-toggle">
        <button
          className={`btn ${tab === "vulnerable" ? "btn-primary" : "btn-outline"}`}
          onClick={() => setTab("vulnerable")}
        >
          Vulnerable Demo
        </button>
        <button
          className={`btn ${tab === "secure" ? "btn-primary" : "btn-outline"}`}
          onClick={() => setTab("secure")}
        >
          Secure Demo
        </button>
      </div>

      {tab === "vulnerable" ? (
        <div className="grid-1">
          <VulnerableLogin />
        </div>
      ) : (
        <div className="grid-1">
          <SecureLogin />
        </div>
      )}
    </div>
  );
}
