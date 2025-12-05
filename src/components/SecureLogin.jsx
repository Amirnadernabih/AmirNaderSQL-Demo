import React, { useEffect, useState } from "react";
import { secureLogin, getUsers } from "../services/api";
import InjectionPayloads from "./InjectionPayloads";
import QueryDisplay from "./QueryDisplay";
import ProcessPanel from "./ProcessPanel";

export default function SecureLogin() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loginResult, setLoginResult] = useState(null);
  const [users, setUsers] = useState([]);
  const [steps, setSteps] = useState([
    { key: "dom", title: "DOM handles username and password", status: "pending" },
    { key: "clientQuery", title: "Client prepares parameterized query", status: "pending" },
    { key: "send", title: "Send request to server", status: "pending" },
    { key: "serverReceive", title: "Server receives credentials", status: "pending" },
    { key: "serverProcess", title: "Server binds parameters and matches exactly", status: "pending" },
    { key: "auth", title: "Server authenticates user", status: "pending" },
    { key: "clientRender", title: "Client updates UI", status: "pending" }
  ]);

  useEffect(() => {
    getUsers().then(setUsers).catch(() => setUsers([]));
  }, []);

  function setStep(idx, status, note) {
    setSteps((prev) => prev.map((s, i) => (i === idx ? { ...s, status, note } : s)));
  }

  function resetSteps() {
    setSteps([
      { key: "dom", title: "DOM handles username and password", status: "pending" },
      { key: "clientQuery", title: "Client prepares parameterized query", status: "pending" },
      { key: "send", title: "Send request to server", status: "pending" },
      { key: "serverReceive", title: "Server receives credentials", status: "pending" },
      { key: "serverProcess", title: "Server binds parameters and matches exactly", status: "pending" },
      { key: "auth", title: "Server authenticates user", status: "pending" },
      { key: "clientRender", title: "Client updates UI", status: "pending" }
    ]);
  }

  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

  async function handleLogin() {
    setLoading(true);
    resetSteps();
    try {
      setStep(0, "loading");
      await sleep(300);
      setStep(0, "done");
      setStep(1, "loading");
      await sleep(300);
      setStep(1, "done");
      setStep(2, "loading");
      setStep(3, "loading");
      const res = await secureLogin(username, password);
      setStep(2, "done");
      setStep(3, "done");
      setStep(4, "done", "Parameters bound; injection blocked");
      setStep(5, res.success ? "done" : "error", res.message);
      setLoginResult(res);
      setStep(6, "done");
    } catch (err) {
      setStep(2, "error", String(err.message || err));
      setStep(3, "error");
      setStep(5, "error");
      setLoginResult({ success: false, query: "", parameters: [], message: String(err.message || err) });
    } finally {
      setLoading(false);
    }
  }

  function fillPayload(payload) {
    setUsername(payload.username);
    setPassword(payload.password);
  }

  function resetForm() {
    setUsername("");
    setPassword("");
    setLoginResult(null);
  }

  return (
    <div className="grid-2">
      <div className="card">
        <h2>Secure Login</h2>
        <div className="banner banner-success">Protected with prepared statements</div>
        <div className="inputs">
          <div className="field">
            <label>Username</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Enter username" />
          </div>
          <div className="field">
            <label>Password</label>
            <div className="pw-row">
              <input type={showPassword ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Enter password" />
              <button type="button" className="btn btn-outline" onClick={() => setShowPassword(!showPassword)}>{showPassword ? "Hide" : "Show"}</button>
            </div>
          </div>
        </div>

        <div className="buttons">
          <button className="btn btn-success" onClick={handleLogin} disabled={loading}>{loading ? "Loading..." : "Login (Secure)"}</button>
          <button className="btn btn-outline" onClick={resetForm}>Reset</button>
        </div>

        <div className="section-title">Try Attack Payloads</div>
        <InjectionPayloads onFill={fillPayload} />

        <div className="section-title">Sample Users</div>
        <div className="users">
          {users.map((u) => (
            <span key={u.id} className="badge">{u.username} ({u.role})</span>
          ))}
        </div>

        {loginResult && (
          <div style={{ marginTop: 12 }}>
            <QueryDisplay
              query={loginResult.query}
              parameters={loginResult.parameters}
              isVulnerable={false}
              injectionDetected={false}
            />
            <div className={`banner ${loginResult.success ? "banner-success" : "banner-error"}`} style={{ marginTop: 8 }}>
              {loginResult.message}
            </div>
            {loginResult.user && (
              <div className="list" style={{ marginTop: 8 }}>
                <span className="badge">User: {loginResult.user.username}</span>
                <span className="badge">Role: {loginResult.user.role}</span>
              </div>
            )}
          </div>
        )}
      </div>

      <ProcessPanel title="Background Steps" steps={steps} />
    </div>
  );
}
