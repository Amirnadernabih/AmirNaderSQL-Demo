const vulnerable = require("../api/vulnerable-login");
const secure = require("../api/secure-login");

function simulate(handler, method, body) {
  return new Promise((resolve) => {
    const headers = {};
    const res = {
      setHeader: (k, v) => { headers[k] = v; },
      status: (code) => ({ end: () => resolve({ status: code, headers }) }),
      json: (obj) => resolve({ status: 200, headers, body: obj })
    };
    const req = { method, body };
    handler(req, res);
  });
}

async function run() {
  console.log("Testing vulnerable endpoint with injection...");
  const r1 = await simulate(vulnerable, "POST", { username: "admin' OR '1'='1' --", password: "x" });
  console.log(r1.body);

  console.log("Testing secure endpoint with injection...");
  const r2 = await simulate(secure, "POST", { username: "admin' OR '1'='1' --", password: "x" });
  console.log(r2.body);

  console.log("Testing secure endpoint with valid credentials...");
  const r3 = await simulate(secure, "POST", { username: "admin", password: "admin123" });
  console.log(r3.body);

  console.log("Testing vulnerable endpoint with wrong credentials...");
  const r4 = await simulate(vulnerable, "POST", { username: "wrong", password: "wrong" });
  console.log(r4.body);
}

run();

