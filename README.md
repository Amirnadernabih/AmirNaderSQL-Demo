# SQL Injection Demo - Educational Project

## 🎓 Purpose
This project demonstrates SQL injection vulnerabilities and how to prevent them using prepared statements. Created for university software security course.

## ⚠️ Disclaimer
**FOR EDUCATIONAL PURPOSES ONLY**
Do NOT use these techniques on unauthorized systems. Unauthorized access is illegal.

## 🚀 Tech Stack
- Frontend: React
- Backend: Serverless Node handlers (Vercel-compatible)
- Deployment: Vercel
- Data: Mock JSON (no database)

## 📦 Installation

```bash
# Install dependencies
npm install

# Run backend verification (optional)
npm run verify:backend

# Start React app (requires react-scripts)
npm start
```

## 🧪 Testing SQL Injection

### Vulnerable Form (Try these)
- Username: `admin' OR '1'='1' --`
- Username: `admin'--`
- Username: `' OR 1=1--`

### Secure Form (These will fail)
- Same injection attempts treated as literal strings
- Only valid credentials work

### Valid Credentials
- admin / admin123
- user1 / password1
- john / doe123

## 🌐 Vercel

`vercel.json` is included for serverless function routing under `/api/*`.

## 📖 What You'll Learn
- How SQL injection works
- Why string concatenation is dangerous
- How prepared statements prevent injection
- Secure coding practices

## 🔒 Security Measures
- Prepared statements
- Input validation
- Parameterized queries
- Principle of least privilege

## Structure

```
api/
  get-users.js
  secure-login.js
  vulnerable-login.js
data/
  mockUsers.js
public/
  index.html
src/
  App.jsx
  index.jsx
  components/
    ComparisonView.jsx
    ExplanationPanel.jsx
    InjectionPayloads.jsx
    QueryDisplay.jsx
    SecureLogin.jsx
    VulnerableLogin.jsx
  services/
    api.js
  styles/
    App.css
scripts/
  verifyEndpoints.js
```

## Notes

- When deploying, keep frontend and serverless functions in the same project for relative `/api/*` calls.
- Set `REACT_APP_API_URL` if hosting API separately; otherwise leave empty for same-domain.

## 📝 License
MIT - Educational Use Only

