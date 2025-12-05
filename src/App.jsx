import React from "react";
import ComparisonView from "./components/ComparisonView";
import ExplanationPanel from "./components/ExplanationPanel";

export default function App() {
  return (
    <div className="app-container">
      <header className="app-header">
        <h1>SQL Injection Demo</h1>
      </header>

      <main className="main-content">
        <ComparisonView />
        <ExplanationPanel />
      </main>
    </div>
  );
}

