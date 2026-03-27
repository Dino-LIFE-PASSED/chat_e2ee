const express    = require('express');
const http       = require('http');
const WebSocket  = require('ws');
const path       = require('path');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;

// Serve frontend files from /public
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// -------------------------------------------------------
// In-memory store
// For a real app you'd swap this with a database.
// -------------------------------------------------------

// Map of publicKey (base64 SPKI) → WebSocket connection
const online = new Map();

// Message history: array of { id, senderKey, recipientKey, encrypted, timestamp }
// Kept in memory so users can load history on reconnect (within the same server run).
const history = [];
let nextId = 1;

// -------------------------------------------------------
// WebSocket protocol
//
// Client → Server message types:
//   identify   { publicKey }             — register this connection
//   send       { recipientKey, encrypted } — relay an encrypted message
//
// Server → Client message types:
//   history    { messages: [...] }        — past messages for this user
//   message    { id, senderKey, recipientKey, encrypted, timestamp }
//   error      { message }
// -------------------------------------------------------

wss.on('connection', (ws) => {
  let myKey = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // ── identify ──────────────────────────────────────
    // Client sends its public key so the server can route
    // incoming messages to it. The server NEVER receives
    // a private key.
    if (msg.type === 'identify') {
      myKey = msg.publicKey;
      online.set(myKey, ws);

      // Replay all messages where this user is sender or recipient.
      // Messages are still encrypted — the server cannot read them.
      const past = history.filter(
        m => m.senderKey === myKey || m.recipientKey === myKey
      );
      ws.send(JSON.stringify({ type: 'history', messages: past }));
    }

    // ── send ──────────────────────────────────────────
    // The client has already encrypted the message in the browser.
    // The server stores and forwards the ciphertext as-is.
    if (msg.type === 'send' && myKey) {
      const record = {
        id:           nextId++,
        senderKey:    myKey,
        recipientKey: msg.recipientKey,
        encrypted:    msg.encrypted,   // opaque blob — server cannot read this
        timestamp:    new Date().toISOString(),
      };
      history.push(record);

      // Deliver live if the recipient is currently connected
      const recipientWs = online.get(msg.recipientKey);
      if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
        recipientWs.send(JSON.stringify({ type: 'message', ...record }));
      }
    }
  });

  ws.on('close', () => {
    if (myKey) online.delete(myKey);
  });
});

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
