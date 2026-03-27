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

// Pending friend requests for offline users: { id, from, to, timestamp }
const pendingRequests = [];

// Contacts per user — so they survive across devices/sessions.
// publicKey → { [contactKey]: { name } }
const userContacts = new Map();

let nextId = 1;

// -------------------------------------------------------
// WebSocket protocol
//
// Client → Server message types:
//   identify        { publicKey }               — register this connection
//   send            { recipientKey, encrypted } — relay an encrypted message
//   friend_request  { to }                      — notify another user they were added
//
// Server → Client message types:
//   history         { messages: [...] }          — past messages for this user
//   message         { id, senderKey, ... }       — incoming live message
//   friend_request  { request: { id, from, timestamp } } — live notification
//   friend_requests { requests: [...] }          — queued notifications on login
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

      // Send stored contacts so the user sees the same list on every device
      ws.send(JSON.stringify({ type: 'contacts', contacts: userContacts.get(myKey) || {} }));

      // Flush any queued friend requests for this user
      const queued = pendingRequests.filter(r => r.to === myKey);
      if (queued.length > 0) {
        ws.send(JSON.stringify({ type: 'friend_requests', requests: queued }));
        queued.forEach(r => pendingRequests.splice(pendingRequests.indexOf(r), 1));
      }
    }

    // ── update_contacts ────────────────────────────────
    // Client syncs their contact list to the server after any change.
    if (msg.type === 'update_contacts' && myKey) {
      userContacts.set(myKey, msg.contacts);
    }

    // ── friend_request ────────────────────────────────
    // User A just added User B to their contacts.
    // Notify B so they can add A back without manually exchanging keys.
    if (msg.type === 'friend_request' && myKey) {
      const req = { id: nextId++, from: myKey, to: msg.to, timestamp: new Date().toISOString() };
      const recipientWs = online.get(msg.to);
      if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
        // B is online — deliver immediately
        recipientWs.send(JSON.stringify({ type: 'friend_request', request: req }));
      } else {
        // B is offline — queue for next login
        pendingRequests.push(req);
      }
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
