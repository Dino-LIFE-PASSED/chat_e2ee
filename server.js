const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (_req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Chat E2EE</title>
        <style>
          body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #0f172a; color: #f1f5f9; }
          .card { text-align: center; padding: 2rem; border: 1px solid #334155; border-radius: 12px; }
          h1 { color: #38bdf8; }
          .badge { display: inline-block; background: #22c55e; color: #fff; padding: 4px 12px; border-radius: 999px; font-size: 0.8rem; margin-top: 1rem; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>Chat E2EE</h1>
          <p>Deployment test successful</p>
          <span class="badge">Running on port ${PORT}</span>
        </div>
      </body>
    </html>
  `);
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
