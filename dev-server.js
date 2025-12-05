const express = require('express');
const app = express();

const vulnerableHandler = require('./api/vulnerable-login');
const secureHandler = require('./api/secure-login');
const usersHandler = require('./api/get-users');

app.use(express.json());

app.options('/api/*', (req, res) => res.status(200).end());
app.post('/api/vulnerable-login', (req, res) => vulnerableHandler(req, res));
app.post('/api/secure-login', (req, res) => secureHandler(req, res));
app.get('/api/get-users', (req, res) => usersHandler(req, res));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Dev API server running on http://localhost:${PORT}`);
});

